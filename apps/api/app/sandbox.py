"""샌드박스 제어. 호스트의 FastAPI는 의심 URL에 직접 접속하지 않는다(N1).

두 가지 구현이 같은 인터페이스를 따른다.
- OpenShellSandbox: NemoClaw 정책 적용 → openshell 샌드박스에서 OpenClaw 에이전트 실행 → 파일 회수 → 정책 제거(finally).
- LocalSandbox: 개발 전용. 같은 검사 스크립트를 로컬 픽스처로 실행하고 에이전트는 규칙으로 흉내 낸다. 실제 네트워크 접속 없음.
"""
from __future__ import annotations

import json
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
from .urls import safe_host_for_policy

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


def render_preset(job_id: str, host: str) -> str:
    if not safe_host_for_policy(host):
        raise SandboxError("unsafe host for policy")
    text = settings.preset_template.read_text(encoding="utf-8")
    return text.replace("<job_id>", job_id).replace("<target_host>", host)


# ══ OpenShell ════════════════════════════════════════════════════════
class OpenShellSandbox:
    kind = "openshell"

    def __init__(self, runner: Runner = default_runner, name: str | None = None, workdir: Path | None = None):
        self.run = runner
        self.name = name or settings.sandbox_name
        self.workdir = Path(workdir or settings.work_dir)
        # 정책이 남았는지 확인하지 못하면 True. 정리를 확인하기 전까지 새 조사를 받지 않는다(검토 2.5).
        self.quarantined = False
        # 샌드박스 안의 작업 폴더 삭제에 실패한 작업 ID. 파일에도 남겨 재시작 뒤에도 다시 지운다(검토 R1-11, R2-08).
        self._purge_lock = threading.Lock()
        self._pending_file = self.workdir / ".pending_purge.json"
        self._pending_purge: set[str] = self._load_pending()

    def _list_policies(self) -> list[str] | None:
        """현재 적용된 조사용 정책 이름. 조회하지 못하면 None(상태를 모른다는 뜻)."""
        try:
            r = self.run(["nemoclaw", self.name, "policy", "list"], 30)
        except Exception:  # noqa: BLE001
            return None
        if r.returncode != 0:
            return None
        return sorted(set(re.findall(r"\b((?:job|spike)-[A-Za-z0-9_-]+)\b", r.stdout)))

    def _close_policy(self, name: str) -> bool:
        """정책을 지우고 다시 조회해 정말 없어졌는지 확인한다. 확인되어야만 True."""
        for attempt in range(3):
            present = self._list_policies()
            if present is not None and name not in present:
                return True
            if attempt == 2:
                break
            try:
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
        self._reconcile_remote()
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
        if self._pending_purge:
            out["sandbox"]["ok"] = False
        if self.quarantined:
            out["sandbox"]["ok"] = False
        return out

    def _sandbox_cmd(self, *args: str) -> list[str]:
        return ["openshell", "sandbox", *args]

    def investigate(self, job_id: str, input_payload: dict, target_host: str, fetch_allowed: bool,
                    on_stage: Callable[[str], None] = lambda s: None) -> RunResult:
        touched: list[bool] = []  # 샌드박스로 업로드를 시도했는가(시도했다면 부분 업로드도 지운다)
        try:
            return self._investigate(job_id, input_payload, target_host, fetch_allowed, on_stage, touched)
        finally:  # 어떤 경로로 끝나도 호스트와 샌드박스의 작업 폴더(문자 원문 포함)를 남기지 않는다
            shutil.rmtree(self.workdir / job_id, ignore_errors=True)
            if touched:
                self._purge_remote(job_id)

    def _investigate(self, job_id: str, input_payload: dict, target_host: str, fetch_allowed: bool,
                     on_stage: Callable[[str], None], touched: list[bool]) -> RunResult:
        res = RunResult(policy_name=f"job-{job_id}")
        self.retry_pending()
        if self._pending_purge:  # 이전 조사 자료(문자 원문)가 샌드박스에 남아 있다: 지운 것을 확인하기 전에는 재사용하지 않는다
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

        opened = False
        add_attempted = False  # 추가 요청이 시간 초과·오류여도 서버에는 반영됐을 수 있다
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
                on_stage("policy_open")
                preset = job_local / f"job-{job_id}.yaml"
                preset.write_text(render_preset(job_id, target_host), encoding="utf-8")
                add_attempted = True
                r = self.run(["nemoclaw", self.name, "policy", "add", "--from-file", str(preset), "--yes"], 60)
                if r.returncode != 0:
                    res.incomplete = "policy_error"
                    return res
                opened = True
                res.events.append({"at": _iso(_now()), "kind": "open", "host": target_host})
            res.timings_ms["policy_open"] = int((time.time() - t_start) * 1000)

            # 5. 에이전트 실행
            on_stage("agent_investigate")
            t_agent = time.time()
            agent_started = _now()
            msg = f"Use the phishing-investigator skill for job {job_id}."
            try:
                r = self.run(["openshell", "sandbox", "exec", "-n", self.name, "--", "openclaw", "agent",
                              "--session-id", f"{job_id}-inv", "--message", msg, "--json",
                              "--timeout", str(settings.agent_timeout_s)], settings.agent_timeout_s + 10)
                agent_json = first_json(r.stdout)
                blob = (r.stdout + r.stderr).lower()
                if r.returncode != 0 or agent_json is None:
                    res.incomplete = "overloaded" if ("429" in blob or "overload" in blob) else "agent_error"
                elif str(agent_json.get("status", "")).lower() not in ("ok", "done", "success", "completed", ""):
                    res.incomplete = "overloaded" if "overload" in blob or "429" in blob else "agent_error"
            except TimeoutError:
                agent_json, res.incomplete = None, "agent_timeout"
            res.timings_ms["agent_investigate"] = int((time.time() - t_agent) * 1000)
            res.agent = _agent_meta(agent_json, agent_started, kind="openshell")
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
                ok = self._close_policy(f"job-{job_id}")
                res.residual_policy = not ok
                self.quarantined = not ok
                if opened:
                    res.events.append({"at": _iso(_now()), "kind": "close", "host": target_host})

        # 7. 결과 파일 회수 (모델이 전달한 요약은 쓰지 않고 스크립트 원본 출력만 쓴다)
        try:
            self.run(self._sandbox_cmd("download", self.name, f"/sandbox/work/{job_id}", str(down_dir)), 60)
        except Exception:  # noqa: BLE001
            pass
        res.files = _read_files(down_dir)
        _add_blocked_events(res)
        _finish_agent_marks(res)
        return res

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
        """지우지 못한 작업 폴더를 다시 지운다. 조사 시작 전과 주기 작업(요청이 없을 때)에서 부른다."""
        with self._purge_lock:
            todo = list(self._pending_purge)
        for job_id in todo:
            self._purge_remote(job_id)

    def _reconcile_remote(self) -> None:
        """시작할 때 샌드박스에 남은 작업 폴더를 찾아 지운다(이전 실행이 비정상 종료한 경우)."""
        try:
            r = self.run(["openshell", "sandbox", "exec", "-n", self.name, "--", "ls", "-1", "/sandbox/work"], 30)
        except Exception:  # noqa: BLE001
            return
        if r.returncode != 0:
            return
        for name in r.stdout.split():
            if _JOB_ID_RE.fullmatch(name):
                self._purge_remote(name)
        self.retry_pending()

    def explain(self, job_id: str, payload: dict) -> dict | None:
        if self.quarantined:  # 정책이 남았을 수 있는 샌드박스에서는 에이전트를 더 실행하지 않는다(템플릿 설명 사용)
            return None
        msg = "Use the verdict-explainer skill. INPUT: " + json.dumps(payload, ensure_ascii=False)
        try:
            r = self.run(["openshell", "sandbox", "exec", "-n", self.name, "--", "openclaw", "agent",
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


class LocalSandbox:
    """개발용 흉내. 실제 격리는 없으므로 네트워크에 접속하지 않고 픽스처만 읽는다."""

    kind = "local-sim"

    def __init__(self, fixtures_dir: Path | None = None, workdir: Path | None = None,
                 force_incomplete: dict[str, str] | None = None):
        self.fixtures = Path(fixtures_dir or settings.fixtures_dir)
        self.workdir = Path(workdir or settings.work_dir)
        self.force = {**_forced_incomplete(), **(force_incomplete or {})}

    def prepare(self) -> list[str]:
        return []

    def health(self) -> dict:
        return {"sandbox": {"ok": True, "text": "local-sim (개발용 흉내, 격리 없음)"},
                "inference": {"ok": True, "text": "규칙 기반 흉내(모델 미사용)"}}

    def _py(self, script: str, *args: str) -> CmdResult:
        p = subprocess.run([sys.executable, str(settings.scripts_dir / script), *args], capture_output=True,
                           text=True, timeout=60, encoding="utf-8", errors="replace")
        return CmdResult(p.returncode, p.stdout, p.stderr)

    def investigate(self, job_id: str, input_payload: dict, target_host: str, fetch_allowed: bool,
                    on_stage: Callable[[str], None] = lambda s: None) -> RunResult:
        res = RunResult(policy_name=f"job-{job_id}")
        root = self.workdir
        jd = root / job_id
        shutil.rmtree(jd, ignore_errors=True)
        jd.mkdir(parents=True)
        (jd / "input.json").write_text(json.dumps(input_payload, ensure_ascii=False), encoding="utf-8")

        on_stage("policy_open")
        started = _now()
        if fetch_allowed:
            res.events.append({"at": _iso(started), "kind": "open", "host": target_host})
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
        shutil.rmtree(jd, ignore_errors=True)
        return res

    def explain(self, job_id: str, payload: dict) -> dict | None:
        return None  # 템플릿 설명을 쓴다


def make_sandbox():
    if settings.sandbox_mode == "openshell":
        return OpenShellSandbox()
    return LocalSandbox()
