"""샌드박스 제어. 호스트의 FastAPI는 의심 URL에 직접 접속하지 않는다(N1).

두 가지 구현이 같은 인터페이스를 따른다.
- OpenShellSandbox: NemoClaw 정책 적용 → openshell 샌드박스에서 OpenClaw 에이전트 실행 → 파일 회수 → 정책 제거(finally).
- LocalSandbox: 개발 전용. 같은 검사 스크립트를 로컬 픽스처로 실행하고 에이전트는 규칙으로 흉내 낸다. 실제 네트워크 접속 없음.
"""
from __future__ import annotations

import json
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import settings
from . import budget
from .urls import safe_host_for_policy
from checklib.navigation import navigation_hosts, public_destination, resolve_public_destination
from checklib.parse_url import normalize_url, parse_url

log = logging.getLogger("sandbox")
_JOB_ID_RE = re.compile(r"j_[0-9a-f]{32}")
FILE_NAMES = ["claim", "parse_url", "similarity", "fetch_chain", "page", "run_meta"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds")


@dataclass
class RunResult:
    files: dict[str, dict] = field(default_factory=dict)
    agent: dict = field(default_factory=dict)  # 도구 호출·소요 시간·모델·타임라인
    events: list[dict] = field(default_factory=list)  # {at, kind: open|blocked|close, host}
    incomplete: str | None = None
    timings_ms: dict[str, int] = field(default_factory=dict)
    policy_name: str | None = None
    residual_policy: bool = False  # 제거에 실패해 정책이 남았을 가능성


class SandboxError(Exception):
    pass


# ── 명령 실행 ────────────────────────────────────────────────────
@dataclass
class CmdResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[list[str], float | None], CmdResult]


def default_runner(args: list[str], timeout: float | None = None) -> CmdResult:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, encoding="utf-8",
                           errors="replace")
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(f"timeout: {args[0]}") from e
    except FileNotFoundError as e:
        raise SandboxError(f"command not found: {args[0]}") from e
    return CmdResult(p.returncode, p.stdout, p.stderr)


def first_json(text: str) -> dict | None:
    """표준 출력에서 첫 `{`부터 JSON으로 파싱한다(앞에 Node 경고 등이 붙는다)."""
    i = text.find("{")
    if i < 0:
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[i:])
        return obj if isinstance(obj, dict) else None
    except ValueError:
        return None


def extract_tools(meta: dict) -> list[str]:
    """openclaw agent --json 의 toolSummary/executionTrace에서 도구 이름을 최대한 관대하게 뽑는다."""
    names: list[str] = []

    def walk(x):
        if isinstance(x, str):
            return
        if isinstance(x, list):
            for i in x:
                if isinstance(i, str):
                    names.append(i)
                else:
                    walk(i)
        elif isinstance(x, dict):
            for key in ("tool", "name", "toolName"):
                if isinstance(x.get(key), str):
                    names.append(x[key])
                    break
            for key in ("tools", "calls", "steps", "events"):
                if key in x:
                    walk(x[key])

    for key in ("toolSummary", "executionTrace"):
        if key in meta:
            walk(meta[key])
            if names:
                break
    return names


def policy_name(job_id: str) -> str:
    """NemoClaw preset names must be RFC 1123 labels; application IDs contain `_`."""
    name = "job-" + job_id.replace("_", "-")
    if len(name) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", name):
        raise SandboxError("unsafe job ID for policy")
    return name


def investigation_policy_name(name: str) -> str | None:
    """Provider composition namespaces NemoClaw rules; still count them as live grants."""
    if re.fullmatch(r'(?:job|spike)-[A-Za-z0-9_-]+', name):
        return name
    match = re.fullmatch(r'nemoclaw_custom__((?:job|spike)-[A-Za-z0-9_-]+?)__((?:job|spike)-[A-Za-z0-9_-]+)', name)
    return match.group(1) if match else None


def render_preset(job_id: str, host: str, allowed_hosts: list[str] | None = None,
                  discovered: bool = False, address_pins: dict | None = None) -> str:
    if not safe_host_for_policy(host):
        raise SandboxError("unsafe host for policy")
    text = settings.preset_template.read_text(encoding="utf-8")
    import copy
    import yaml
    hosts = allowed_hosts if allowed_hosts is not None else [host]
    if len(hosts) > 6 or host not in hosts or any(not safe_host_for_policy(h) or
            (not discovered and h not in navigation_hosts(host)) for h in hosts):
        raise SandboxError("unsafe navigation hosts")
    data = yaml.safe_load(text.replace("job-<job_id>", policy_name(job_id)).replace("<target_host>", host))
    policy = data["network_policies"][policy_name(job_id)]
    endpoints = policy["endpoints"]
    policy["endpoints"] = [{**copy.deepcopy(e), "host": h} for h in dict.fromkeys(hosts) for e in endpoints]
    if address_pins is not None:
        for endpoint in policy['endpoints']:
            pins = address_pins.get(endpoint['host'], [])
            if not pins or any(not ipaddress.ip_address(ip).is_global or ipaddress.ip_address(ip).is_multicast for ip in pins):
                raise SandboxError('non-public or missing destination pins')
            endpoint['allowed_ips'] = pins
    return yaml.safe_dump(data, sort_keys=False)


# ══ 호스트 작업 폴더 ═══════════════════════════════════════════════════
class _LocalDirs:
    """호스트의 `<workdir>/<job_id>` 폴더(문자 원문·내려받은 페이지)를 남기지 않기 위한 공통 처리.

    지우지 못한 폴더는 그대로 남아 있으므로 폴더 목록을 훑어서 다시 지운다(비정상 종료로 남은 폴더도 같은 방법으로
    찾는다). 진행 중인 작업의 폴더는 건드리지 않도록 작업 ID를 `_active`에 둔다."""

    workdir: Path

    def _init_local(self) -> None:
        self._local_lock = threading.Lock()
        self._active: set[str] = set()

    def _begin_local(self, job_id: str) -> None:
        with self._local_lock:
            self._active.add(job_id)

    def _end_local(self, job_id: str) -> bool:
        """작업이 끝났다. 폴더를 지우고 정말 없어졌는지 돌려준다(못 지웠으면 다음 정리 때 다시 지운다)."""
        with self._local_lock:
            self._active.discard(job_id)
            return _rmtree_strict(self.workdir / job_id, job_id)

    def _leftover_dirs(self) -> list[Path]:
        try:
            return [c for c in self.workdir.iterdir() if c.is_dir() and _JOB_ID_RE.fullmatch(c.name)]
        except OSError:
            return []

    def reconcile_local(self) -> int:
        """진행 중이 아닌 작업 폴더를 모두 지운다. 지우지 못한 폴더 수를 돌려준다."""
        failed = 0
        for child in self._leftover_dirs():
            with self._local_lock:
                if child.name in self._active:
                    continue
                if not _rmtree_strict(child, child.name):
                    failed += 1
        return failed

    def _is_active(self, job_id: str) -> bool:
        with self._local_lock:
            return job_id in self._active

    def pending_local(self) -> int:
        with self._local_lock:
            return sum(1 for c in self._leftover_dirs() if c.name not in self._active)


def _rmtree_strict(path: Path, job_id: str) -> bool:
    """폴더를 지우고 정말 사라졌는지 확인한다. 실패하면 로그를 남기고 False."""
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return True
    except OSError as e:
        log.error("could not remove work dir of %s: %s", job_id, type(e).__name__)
    return not path.exists()


# ══ OpenShell ════════════════════════════════════════════════════════
class OpenShellSandbox(_LocalDirs):
    kind = "openshell"

    def __init__(self, runner: Runner = default_runner, name: str | None = None, workdir: Path | None = None):
        self._runner = runner
        self.name = name or settings.sandbox_name
        self.workdir = Path(workdir or settings.work_dir)
        # 정책이 남았는지 확인하지 못하면 True. 정리를 확인하기 전까지 새 조사를 받지 않는다(검토 2.5).
        self.quarantined = False
        # 샌드박스 안의 작업 폴더 삭제에 실패한 작업 ID. 파일에도 남겨 재시작 뒤에도 다시 지운다(검토 R1-11, R2-08).
        self._purge_lock = threading.Lock()
        self._pending_file = self.workdir / ".pending_purge.json"
        self._pending_purge: set[str] = self._load_pending()
        # 시작할 때 샌드박스 안의 작업 폴더 목록을 확인했는가. 확인하지 못하면 남은 자료가 있는지 모르므로 재사용하지 않는다(R3-14).
        self._remote_reconciled = False
        self._direct_policies: set[str] = set()
        self._init_local()

    def run(self, args, timeout=None):
        args, timeout = budget.command(args, timeout)
        return self._runner(args, timeout)

    def _list_policies(self) -> list[str] | None:
        """현재 적용된 조사용 정책 이름. 조회하지 못하면 None(상태를 모른다는 뜻)."""
        try:
            # `nemoclaw policy list` can exit 0 with an unavailable live state,
            # showing only its preset catalog. Query the enforced policy itself.
            r = self.run(["openshell", "policy", "get", self.name, "--full", "-o", "json"], 30)
        except Exception:  # noqa: BLE001
            return None
        if r.returncode != 0:
            return None
        data = first_json(r.stdout)
        if not data or data.get("status") != "effective" or data.get("sandbox") != self.name:
            return None
        policies = (data.get("policy") or {}).get("network_policies")
        if not isinstance(policies, dict):
            return None
        self._direct_policies.update(n for n, policy in policies.items() if n.startswith('job-') and
                                     any(e.get('allowed_ips') for e in policy.get('endpoints', [])))
        return sorted({logical for n in policies if (logical := investigation_policy_name(n))})

    def _add_policy(self, preset: Path, name: str, pinned: bool) -> CmdResult:
        if not pinned:
            return self.run(['nemoclaw', self.name, 'policy', 'add', '--from-file', str(preset), '--yes'], 60)
        # NemoClaw's user-preset format rejects allowed_ips. OpenShell's supported
        # policy API can preserve the current policy and narrow new grants to
        # validated public IPs. Never drop pins as a compatibility fallback.
        import yaml
        current = self.run(['openshell', 'policy', 'get', self.name, '--base', '-o', 'json'], 20)
        data = first_json(current.stdout)
        if current.returncode or not data or data.get('status') != 'effective' or data.get('sandbox') != self.name:
            raise SandboxError('cannot read effective policy')
        policy = data['policy']
        addition = yaml.safe_load(preset.read_text())['network_policies'][name]
        policy['network_policies'][name] = addition
        merged = preset.with_name('effective-policy.yaml')
        merged.write_text(yaml.safe_dump(policy, sort_keys=False), encoding='utf-8')
        self._direct_policies.add(name)  # even a timed-out apply can have taken effect
        r = self.run(['openshell', 'policy', 'set', self.name, '--policy', str(merged), '--wait', '--timeout', '30'], 35)
        if r.returncode:
            return r
        verified = self.run(['openshell', 'policy', 'get', self.name, '--full', '-o', 'json'], 20)
        effective = first_json(verified.stdout) or {}
        actual = (effective.get('policy') or {}).get('network_policies', {}).get(name)
        if verified.returncode or effective.get('status') != 'effective' or actual != addition:
            raise SandboxError('effective policy differs from exact pinned grant')
        return r

    def _close_policy(self, name: str) -> bool:
        """정책을 지우고 다시 조회해 정말 없어졌는지 확인한다. 확인되어야만 True."""
        for attempt in range(3):
            present = self._list_policies()
            if present is not None and name not in present:
                return True
            if attempt == 2:
                break
            try:
                if name in self._direct_policies:
                    self.run(['openshell', 'policy', 'update', self.name, '--remove-rule', name, '--wait', '--timeout', '30'], 35)
                else:
                    self.run(["nemoclaw", self.name, "policy", "remove", name, "--yes"], 60)
            except Exception:  # noqa: BLE001 - 시간 초과여도 서버에서는 지워졌을 수 있으니 재조회로 판단한다
                pass
        return False

    def _sweep(self) -> tuple[list[str], bool]:
        """남아 있는 조사용 정책을 모두 지운다. (지운 목록, 깨끗함이 확인됐는가)"""
        found = self._list_policies()
        if found is None:
            return [], False
        removed = [m for m in found if self._close_policy(m)]
        return removed, len(removed) == len(found)

    # 워커 시작 시: 이전 실행이 남긴 조사용 정책 정리
    def prepare(self) -> list[str]:
        removed, clean = self._sweep()
        self.quarantined = not clean
        self._remote_reconciled = False
        self.retry_pending()
        return removed

    def health(self) -> dict:
        out: dict = {"sandbox": {}, "inference": {}}
        for key, cmd in (("sandbox", ["openshell", "sandbox", "list"]), ("inference", ["openshell", "inference", "get"])):
            try:
                r = self.run(cmd, 15)
                out[key] = {"ok": r.returncode == 0, "text": (r.stdout or r.stderr)[:400]}
            except Exception as e:  # noqa: BLE001
                out[key] = {"ok": False, "text": str(e)[:200]}
        out["sandbox"]["quarantined"] = self.quarantined
        out["sandbox"]["pending_purge"] = len(self._pending_purge)
        out["sandbox"]["pending_local"] = self.pending_local()
        out["sandbox"]["remote_reconciled"] = self._remote_reconciled
        if self._pending_purge or not self._remote_reconciled or out["sandbox"]["pending_local"]:
            out["sandbox"]["ok"] = False
        if self.quarantined:
            out["sandbox"]["ok"] = False
        return out

    def _sandbox_cmd(self, *args: str) -> list[str]:
        return ["openshell", "sandbox", *args]

    def investigate(self, job_id: str, input_payload: dict, target_host: str, fetch_allowed: bool,
                    on_stage: Callable[[str], None] = lambda s: None) -> RunResult:
        touched: list[bool] = []  # 샌드박스로 업로드를 시도했는가(시도했다면 부분 업로드도 지운다)
        self._begin_local(job_id)
        try:
            return self._investigate(job_id, input_payload, target_host, fetch_allowed, on_stage, touched)
        finally:  # 어떤 경로로 끝나도 호스트와 샌드박스의 작업 폴더(문자 원문 포함)를 남기지 않는다
            self._end_local(job_id)  # 못 지운 폴더는 남아 있으므로 다음 정리(reconcile_local)가 다시 지운다
            if touched:
                with budget.cleanup():
                    self._purge_remote(job_id)

    def _investigate(self, job_id: str, input_payload: dict, target_host: str, fetch_allowed: bool,
                     on_stage: Callable[[str], None], touched: list[bool]) -> RunResult:
        res = RunResult(policy_name=policy_name(job_id))
        self.retry_pending()
        if self._pending_purge or not self._remote_reconciled:
            # 이전 조사 자료(문자 원문)가 샌드박스에 남아 있거나 남았는지 확인하지 못했다: 확인하기 전에는 재사용하지 않는다
            res.incomplete = "sandbox_unsafe"
            return res
        if self.quarantined:  # 이전 조사의 정책이 남았을 수 있다: 정리를 확인한 뒤에만 다시 연다
            _, clean = self._sweep()
            self.quarantined = not clean
            if self.quarantined:
                res.incomplete = "sandbox_unsafe"
                res.residual_policy = True
                return res
        job_local = self.workdir / job_id
        up_dir = job_local / "up" / job_id
        down_dir = job_local / "down"
        shutil.rmtree(job_local, ignore_errors=True)
        up_dir.mkdir(parents=True)
        down_dir.mkdir(parents=True)
        (up_dir / "input.json").write_text(json.dumps(input_payload, ensure_ascii=False), encoding="utf-8")
        address_only = input_payload.get('navigation_mode') == 'discover' and not input_payload.get('message_text')
        if address_only:
            (up_dir / 'claim.json').write_text(json.dumps({'ok': True, 'entity_id': None, 'purpose': 'other',
                                                          'reason': '주소만 입력되어 기관·목적을 추측하지 않음',
                                                          'at': _iso(_now())}), encoding='utf-8')

        opened = False
        add_attempted = False  # 추가 요청이 시간 초과·오류여도 서버에는 반영됐을 수 있다
        address_pins = {} if input_payload.get('navigation_mode') == 'discover' else None
        t_start = time.time()
        try:
            # 3. 입력 업로드 ("상위 폴더"를 대상으로 지정하면 <대상>/<원본폴더이름>이 만들어진다)
            touched.append(True)
            r = self.run(self._sandbox_cmd("upload", self.name, str(up_dir), "/sandbox/work"), 60)
            if r.returncode != 0:
                res.incomplete = "sandbox_error"
                return res

            # 4. 조사용 정책 열기 (IP·사설 호스트는 열지 않고 주소 분석만 한다)
            if fetch_allowed:
                if input_payload.get('navigation_mode') == 'discover':
                    try:
                        checked_host, addresses = budget.read_only(resolve_public_destination, input_payload['url'])
                        address_pins[checked_host] = addresses
                    except ValueError:
                        res.incomplete = 'destination_unavailable'
                        return res
                on_stage("policy_open")
                preset = job_local / f"{res.policy_name}.yaml"
                preset.write_text(render_preset(job_id, target_host, input_payload.get("allowed_hosts"), address_pins=address_pins), encoding="utf-8")
                add_attempted = True
                r = self._add_policy(preset, res.policy_name, address_pins is not None)
                if r.returncode != 0:
                    res.incomplete = "policy_error"
                    return res
                opened = True
                res.events.append({"at": _iso(_now()), "kind": "open", "host": target_host, "hosts": input_payload.get("allowed_hosts", [target_host])})
            res.timings_ms["policy_open"] = int((time.time() - t_start) * 1000)

            # 5. 에이전트 실행
            on_stage("agent_investigate")
            t_agent = time.time()
            agent_started = _now()
            msg = f"Use the phishing-investigator skill for job {job_id}."
            try:
                if address_only:
                    r = self.run(['openshell', 'sandbox', 'exec', '-n', self.name, '--timeout=35', '--',
                                  'python3', '/sandbox/.openclaw/workspace/skills/phishing-investigator/scripts/run_checks.py',
                                  '--job', job_id], 40)
                    agent_json = {'status': 'ok', 'result': {'meta': {'toolSummary': {'tools': ['exec']}}}} if r.returncode == 0 else None
                else:
                    r = self.run(["openshell", "sandbox", "exec", "-n", self.name,
                              f"--timeout={settings.agent_timeout_s + 5}", "--", "openclaw", "agent",
                              "--session-id", f"{job_id}-inv", "--message", msg, "--json",
                              "--timeout", str(settings.agent_timeout_s)], settings.agent_timeout_s + 10)
                    agent_json = first_json(r.stdout)
                blob = (r.stdout + r.stderr).lower()
                if r.returncode == 124:  # OpenShell's remote deadline, before the local process limit
                    res.incomplete = 'agent_timeout'
                elif r.returncode != 0 or agent_json is None:
                    res.incomplete = "overloaded" if ("429" in blob or "overload" in blob) else "agent_error"
                elif str(agent_json.get("status", "")).lower() not in ("ok", "done", "success", "completed", ""):
                    res.incomplete = "overloaded" if "overload" in blob or "429" in blob else "agent_error"
            except TimeoutError:
                agent_json, res.incomplete = None, "agent_timeout"
            res.timings_ms["agent_investigate"] = int((time.time() - t_agent) * 1000)
            res.agent = _agent_meta(agent_json, agent_started, kind="openshell")
            res.agent['execution_mode'] = 'address_checks' if address_only else 'message_agent'
            if not res.incomplete and opened and input_payload.get('navigation_mode') == 'discover':
                self._follow_navigation(job_id, input_payload, target_host, up_dir, down_dir, preset, res, on_stage, address_pins)
        except TimeoutError:
            res.incomplete = res.incomplete or ("policy_error" if add_attempted and not opened else "agent_timeout")
        except SandboxError:
            res.incomplete = res.incomplete or "sandbox_error"
        finally:
            # 6. 정책은 항상 제거하고, 실제로 없어졌는지 다시 조회해 확인한다.
            #    정리를 확인하기 전까지는 격리해 두고(정리 중 예외가 나도 격리가 남는다), 확인되면 푼다.
            if add_attempted:
                self.quarantined = True
                if opened:
                    try:
                        on_stage("policy_close")
                    except Exception:  # noqa: BLE001 - 진행 표시가 실패해도 정책 제거는 반드시 한다
                        log.exception("on_stage failed during policy_close")
                with budget.cleanup():
                    ok = self._close_policy(res.policy_name)
                res.residual_policy = not ok
                self.quarantined = not ok
                if not ok:
                    res.incomplete = res.incomplete or 'policy_error'
                if opened:
                    res.events.append({"at": _iso(_now()), "kind": "close", "host": target_host})

        # 7. 결과 파일 회수 (모델이 전달한 요약은 쓰지 않고 스크립트 원본 출력만 쓴다)
        try:
            self.run(self._sandbox_cmd("download", self.name, f"/sandbox/work/{job_id}", str(down_dir)), 60)
        except budget.BudgetExpired:
            res.incomplete = res.incomplete or 'agent_timeout'
        except Exception:  # noqa: BLE001
            pass
        res.files = _read_files(down_dir)
        _add_blocked_events(res)
        _finish_agent_marks(res)
        return res

    def _follow_navigation(self, job_id, payload, target_host, up_dir, down_dir, preset, res, on_stage, address_pins):
        """A host-controlled broker extends exact GET destinations, never wildcard trust.

        The model cannot change egress policy. Each observed redirect is checked
        on the host, then deterministic checks are rerun inside the sandbox.
        Previously visited hosts remain only until this job's finally cleanup.
        """
        deadline = time.monotonic() + 90
        decisions = res.agent.setdefault('navigation', [])
        refreshed = set()
        for _ in range(5):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            shutil.rmtree(down_dir, ignore_errors=True)
            down_dir.mkdir(parents=True)
            r = self.run(self._sandbox_cmd('download', self.name, f'/sandbox/work/{job_id}', str(down_dir)), min(30, remaining))
            if r.returncode:
                res.incomplete = 'sandbox_error'
                return
            files = _read_files(down_dir)
            chain = (files.get('fetch_chain') or {}).get('chain') or []
            if not chain or len(chain) > 6 or not chain[-1].get('blocked'):
                return
            last = chain[-1]
            refresh = last.get('host') in payload['allowed_hosts']
            if refresh:
                # CDNs can rotate public DNS answers between preflight and proxy resolution.
                # Refresh once per host, using independently resolved addresses, never the denial text.
                if last.get('host') in refreshed or last.get('block_reason') != '403 Forbidden':
                    return
                next_url = last.get('url', '')
            else:
                if len(chain) < 2 or last.get('block_reason') != 'navigation outside allowed site addresses':
                    return
                next_url = chain[-2].get('redirect_url', '')
            try:
                if not next_url or len(next_url) > 2000:
                    raise ValueError('invalid_redirect_edge')
                if not refresh and chain[-2].get('status') not in range(300, 400):
                    raise ValueError('invalid_redirect_edge')
                if normalize_url(next_url)[0][:500] != last.get('url'):
                    raise ValueError('invalid_redirect_edge')
                first_url = normalize_url(payload['url'])[0]
                if chain[0].get('url') != first_url[:500]:
                    raise ValueError('invalid_redirect_start')
                host, addresses = budget.read_only(resolve_public_destination, next_url)
                if refresh:
                    if host != last.get('host'):
                        raise ValueError('invalid_refresh_host')
                    addresses = sorted(set(addresses) | set(address_pins.get(host, [])))
                    if addresses == sorted(address_pins.get(host, [])):
                        decisions.append({'url': next_url[:500], 'allowed': False, 'reason': 'dns_answers_unchanged'})
                        return
                    if len(addresses) > 32:
                        raise ValueError('dns_address_limit')
                    refreshed.add(host)
                elif host in payload['allowed_hosts'] or len(payload['allowed_hosts']) >= 6:
                    raise ValueError('navigation_limit')
            except (ValueError, TypeError) as exc:
                decisions.append({'url': next_url[:500], 'allowed': False, 'reason': str(exc)})
                return
            if time.monotonic() >= deadline:
                return
            # remove is verified before replacement; finally removes any attempted replacement too.
            if not self._close_policy(res.policy_name):
                res.incomplete = 'policy_error'
                return
            if not refresh:
                payload['allowed_hosts'].append(host)
            address_pins[host] = addresses
            preset.write_text(render_preset(job_id, target_host, payload['allowed_hosts'], discovered=True,
                                            address_pins=address_pins), encoding='utf-8')
            r = self._add_policy(preset, res.policy_name, pinned=True)
            if r.returncode:
                res.incomplete = 'policy_error'
                return
            decisions.append({'url': next_url[:500], 'allowed': True,
                              'reason': 'public_dns_refresh' if refresh else 'public_redirect_destination'})
            res.events.append({'at': _iso(_now()), 'kind': 'open', 'host': host, 'hosts': list(payload['allowed_hosts'])})
            on_stage('agent_investigate')
            (up_dir / 'input.json').write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
            r = self.run(self._sandbox_cmd('upload', self.name, str(up_dir), '/sandbox/work'), 30)
            if r.returncode:
                res.incomplete = 'sandbox_error'
                return
            remaining = max(1, min(30, int(deadline - time.monotonic())))
            r = self.run(['openshell', 'sandbox', 'exec', '-n', self.name, f'--timeout={remaining}', '--',
                          'python3', '/sandbox/.openclaw/workspace/skills/phishing-investigator/scripts/run_checks.py',
                          '--job', job_id], remaining + 5)
            if r.returncode:
                res.incomplete = 'agent_timeout' if r.returncode == 124 else 'sandbox_error'
                return

    # ── 샌드박스 안 작업 폴더 삭제 ───────────────────────────────────────
    def _load_pending(self) -> set[str]:
        try:
            data = json.loads(self._pending_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return set()
        return {j for j in data if isinstance(j, str) and _JOB_ID_RE.fullmatch(j)} if isinstance(data, list) else set()

    def _save_pending(self) -> None:  # _purge_lock을 잡고 부른다
        try:
            self._pending_file.parent.mkdir(parents=True, exist_ok=True)
            self._pending_file.write_text(json.dumps(sorted(self._pending_purge)), encoding="utf-8")
        except OSError:
            log.error("could not persist pending purge list")

    def _purge_remote(self, job_id: str) -> bool:
        """샌드박스 안의 작업 폴더(입력 문자·페이지 원본)를 지운다. 실패하면 기록해 두고 다시 지운다."""
        if not _JOB_ID_RE.fullmatch(job_id):  # 경로에 넣기 전에 형식을 확인한다
            return False
        try:
            r = self.run(["openshell", "sandbox", "exec", "-n", self.name, "--", "rm", "-rf", f"/sandbox/work/{job_id}"], 30)
            ok = r.returncode == 0
        except Exception:  # noqa: BLE001
            ok = False
        with self._purge_lock:
            before = set(self._pending_purge)
            (self._pending_purge.discard if ok else self._pending_purge.add)(job_id)
            if self._pending_purge != before:
                self._save_pending()
        return ok

    def retry_pending(self) -> None:
        """정리하지 못한 것을 다시 정리한다. 조사 시작 전과 주기 작업(요청이 없을 때)에서 부른다.

        샌드박스 안의 작업 폴더 목록을 아직 확인하지 못했다면 그것부터 다시 시도한다."""
        if not self._remote_reconciled:
            self._remote_reconciled = self._reconcile_remote()
        with self._purge_lock:
            todo = list(self._pending_purge)
        for job_id in todo:
            if not self._is_active(job_id):
                self._purge_remote(job_id)
        self.reconcile_local()

    def _reconcile_remote(self) -> bool:
        """샌드박스에 남은 작업 폴더를 찾아 지운다(이전 실행이 비정상 종료한 경우). 목록을 확인했을 때만 True.

        폴더가 아예 없는 것은 정상(빈 목록)이고, 명령이 실패해 목록을 못 얻은 것은 확인하지 못한 것이다."""
        try:
            r = self.run(["openshell", "sandbox", "exec", "-n", self.name, "--", "sh", "-c",
                          "if [ -d /sandbox/work ]; then ls -1 /sandbox/work; fi"], 30)
        except Exception:  # noqa: BLE001
            return False
        if r.returncode != 0:
            return False
        for name in r.stdout.split():
            # 목록을 받은 뒤 시작한 작업의 폴더는 목록에 없고, 목록을 받을 때 이미 있던 폴더가 지금 진행 중이면 건드리지 않는다
            if _JOB_ID_RE.fullmatch(name) and not self._is_active(name):
                self._purge_remote(name)
        return True

    def explain(self, job_id: str, payload: dict) -> dict | None:
        if self.quarantined:  # 정책이 남았을 수 있는 샌드박스에서는 에이전트를 더 실행하지 않는다(템플릿 설명 사용)
            return None
        msg = "Use the verdict-explainer skill. INPUT: " + json.dumps(payload, ensure_ascii=False)
        try:
            r = self.run(["openshell", "sandbox", "exec", "-n", self.name,
                          f"--timeout={settings.explain_timeout_s + 5}", "--", "openclaw", "agent",
                          "--session-id", f"{job_id}-exp", "--message", msg, "--json",
                          "--timeout", str(settings.explain_timeout_s)], settings.explain_timeout_s + 10)
        except Exception:  # noqa: BLE001
            return None
        env = first_json(r.stdout)
        if not env:
            return None
        try:
            text = env["result"]["payloads"][0]["text"]
        except (KeyError, IndexError, TypeError):
            return None
        return first_json(text) if isinstance(text, str) else None


def _read_files(d: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for name in FILE_NAMES:
        for p in d.rglob(f"{name}.json"):
            try:
                out[name] = json.loads(p.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                out[name] = {"ok": False, "error": "unreadable"}
            break
    return out


def _agent_meta(agent_json: dict | None, started: datetime, kind: str) -> dict:
    meta: dict = {}
    duration = None
    model = None
    tools: list[str] = []
    session = None
    if agent_json:
        m = (agent_json.get("result") or {}).get("meta") or {}
        duration = m.get("durationMs")
        tools = extract_tools(m)
        am = m.get("agentMeta") or {}
        model = m.get("model") or am.get("model") or m.get("provider")
        session = m.get("sessionId") or agent_json.get("sessionId")
        meta["raw_meta"] = {k: m.get(k) for k in ("durationMs", "toolSummary", "executionTrace") if k in m}
    unexpected = [t for t in tools if t not in settings.allowed_tools]
    return {
        "kind": kind, "tool_calls": tools, "unexpected_tools": unexpected, "duration_ms": duration,
        "model_reported": model, "session": session, "started_at": _iso(started), **meta,
    }


def _add_blocked_events(res: RunResult) -> None:
    chain = (res.files.get("fetch_chain") or {}).get("chain", [])
    for hop in chain:
        if hop.get("blocked"):
            res.events.append({"at": hop.get("at") or _iso(_now()), "kind": "blocked", "host": hop.get("host")})
    res.events.sort(key=lambda e: e["at"])


def _finish_agent_marks(res: RunResult) -> None:
    claim = res.files.get("claim") or {}
    meta = res.files.get("run_meta") or {}
    res.agent.setdefault("marks", {})
    res.agent["marks"].update({"claim_at": claim.get("at"), "checks_started": meta.get("started_at"),
                               "checks_finished": meta.get("finished_at")})


# ══ 로컬(개발 전용) ═══════════════════════════════════════════════════
_PURPOSE_RULES = [
    ("payment", ("결제", "카드", "청구", "요금 납부", "착불")),
    ("government_notice", ("과태료", "세금", "경찰", "검찰", "법원", "민원", "국세", "건강보험")),
    ("prize_event", ("당첨", "이벤트", "경품", "쿠폰")),
    ("account_security", ("로그인", "계정", "본인 확인", "본인확인", "인증", "비밀번호", "해킹", "보안")),
    ("delivery", ("배송", "택배", "송장", "운송장", "주소", "반송")),
]


def sim_purpose(text: str) -> str:
    for purpose, words in _PURPOSE_RULES:
        if any(w in text for w in words):
            return purpose
    return "other"


def sim_entity_name(text: str) -> str | None:
    m = re.match(r"\s*[\[【(]([^\]】)]{1,20})[\]】)]", text)
    return m.group(1).strip() if m else None


def _forced_incomplete() -> dict[str, str]:
    out: dict[str, str] = {}
    for part in os.environ.get("SIM_FORCE_INCOMPLETE", "").split(","):
        if "=" in part:
            h, r = part.split("=", 1)
            out[h.strip().lower()] = r.strip()
    return out


class LocalSandbox(_LocalDirs):
    """개발용 흉내. 실제 격리는 없으므로 네트워크에 접속하지 않고 픽스처만 읽는다."""

    kind = "local-sim"

    def __init__(self, fixtures_dir: Path | None = None, workdir: Path | None = None,
                 force_incomplete: dict[str, str] | None = None):
        self.fixtures = Path(fixtures_dir or settings.fixtures_dir)
        self.workdir = Path(workdir or settings.work_dir)
        self.force = {**_forced_incomplete(), **(force_incomplete or {})}
        self._init_local()

    def prepare(self) -> list[str]:
        self.reconcile_local()  # 이전 실행이 비정상 종료해 남긴 작업 폴더
        return []

    def retry_pending(self) -> None:
        self.reconcile_local()

    def health(self) -> dict:
        return {"sandbox": {"ok": True, "text": "local-sim (개발용 흉내, 격리 없음)"},
                "inference": {"ok": True, "text": "규칙 기반 흉내(모델 미사용)"}}

    def _py(self, script: str, *args: str) -> CmdResult:
        p = subprocess.run([sys.executable, str(settings.scripts_dir / script), *args], capture_output=True,
                           text=True, timeout=60, encoding="utf-8", errors="replace")
        return CmdResult(p.returncode, p.stdout, p.stderr)

    def investigate(self, job_id: str, input_payload: dict, target_host: str, fetch_allowed: bool,
                    on_stage: Callable[[str], None] = lambda s: None) -> RunResult:
        self._begin_local(job_id)
        try:
            return self._investigate(job_id, input_payload, target_host, fetch_allowed, on_stage)
        finally:  # 예외로 끝나도 문자 원문이 든 폴더를 남기지 않는다
            self._end_local(job_id)

    def _investigate(self, job_id: str, input_payload: dict, target_host: str, fetch_allowed: bool,
                     on_stage: Callable[[str], None]) -> RunResult:
        res = RunResult(policy_name=policy_name(job_id))
        root = self.workdir
        jd = root / job_id
        shutil.rmtree(jd, ignore_errors=True)
        jd.mkdir(parents=True)
        (jd / "input.json").write_text(json.dumps(input_payload, ensure_ascii=False), encoding="utf-8")

        on_stage("policy_open")
        started = _now()
        if fetch_allowed:
            res.events.append({"at": _iso(started), "kind": "open", "host": target_host, "hosts": input_payload.get("allowed_hosts", [target_host])})
        forced = self.force.get(target_host.lower())

        on_stage("agent_investigate")
        t0 = time.time()
        text = input_payload.get("message_text") or input_payload.get("url", "")
        cands = input_payload.get("kb_candidates", [])
        entity = "none"
        norm = re.sub(r"\s+", "", text).lower()
        for c in cands:
            names = [c["name"], *c.get("aliases", [])]
            if any(re.sub(r"\s+", "", n).lower() in norm for n in names if len(n) >= 2):
                entity = c["id"]
                break
        purpose = sim_purpose(text)
        log: list[str] = []
        try:
            if forced:
                time.sleep(0.05)
                res.incomplete = forced
                res.timings_ms["agent_investigate"] = int((time.time() - t0) * 1000)
                res.agent = {"kind": "local-sim", "tool_calls": ["read"], "unexpected_tools": [],
                             "duration_ms": int((time.time() - t0) * 1000),
                             "model_reported": "local-rule-agent", "started_at": _iso(started), "marks": {}}
                return res
            claim_args = ["--job", job_id, "--entity", entity, "--purpose", purpose,
                          "--reason", "문자 맨 앞 이름과 내용으로 골랐어요", "--work-root", str(root)]
            name = sim_entity_name(text)
            if entity == "none" and name:
                claim_args += ["--name", name]
            log.append(self._py("record_claim.py", *claim_args).stdout.strip())
            check_args = ["--job", job_id, "--work-root", str(root), "--fixtures", str(self.fixtures)]
            log.append(self._py("run_checks.py", *check_args).stdout.strip())
        finally:
            if fetch_allowed:
                res.events.append({"at": _iso(_now()), "kind": "close", "host": target_host})
        dur = int((time.time() - t0) * 1000)
        res.timings_ms["agent_investigate"] = dur
        res.agent = {"kind": "local-sim", "tool_calls": ["read", "exec", "exec"], "unexpected_tools": [],
                     "duration_ms": dur, "model_reported": "local-rule-agent (모델 미사용)",
                     "session": f"{job_id}-inv", "started_at": _iso(started), "log": log}
        res.files = _read_files(jd)
        _add_blocked_events(res)
        _finish_agent_marks(res)
        return res

    def explain(self, job_id: str, payload: dict) -> dict | None:
        return None  # 템플릿 설명을 쓴다


def make_sandbox():
    if settings.sandbox_mode == "openshell":
        return OpenShellSandbox()
    return LocalSandbox()
