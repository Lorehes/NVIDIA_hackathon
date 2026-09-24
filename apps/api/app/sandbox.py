"""샌드박스 제어. 호스트의 FastAPI는 의심 URL에 직접 접속하지 않는다(N1).

두 가지 구현이 같은 인터페이스를 따른다.
- OpenShellSandbox: NemoClaw 정책 적용 → openshell 샌드박스에서 OpenClaw 에이전트 실행 → 파일 회수 → 정책 제거(finally).
- LocalSandbox: 개발 전용. 같은 검사 스크립트를 로컬 픽스처로 실행하고 에이전트는 규칙으로 흉내 낸다. 실제 네트워크 접속 없음.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import settings
from .urls import safe_host_for_policy

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

    # 워커 시작 시: 이전 실행이 남긴 조사용 정책 정리
    def prepare(self) -> list[str]:
        removed: list[str] = []
        try:
            r = self.run(["nemoclaw", self.name, "policy", "list"], 30)
        except Exception:  # noqa: BLE001
            return removed
        for m in set(re.findall(r"\b((?:job|spike)-[A-Za-z0-9_-]+)\b", r.stdout)):
            try:
                self.run(["nemoclaw", self.name, "policy", "remove", m, "--yes"], 30)
                removed.append(m)
            except Exception:  # noqa: BLE001
                pass
        return removed

    def health(self) -> dict:
        out: dict = {"sandbox": {}, "inference": {}}
        for key, cmd in (("sandbox", ["openshell", "sandbox", "list"]), ("inference", ["openshell", "inference", "get"])):
            try:
                r = self.run(cmd, 15)
                out[key] = {"ok": r.returncode == 0, "text": (r.stdout or r.stderr)[:400]}
            except Exception as e:  # noqa: BLE001
                out[key] = {"ok": False, "text": str(e)[:200]}
        return out

    def _sandbox_cmd(self, *args: str) -> list[str]:
        return ["openshell", "sandbox", *args]

    def investigate(self, job_id: str, input_payload: dict, target_host: str, fetch_allowed: bool,
                    on_stage: Callable[[str], None] = lambda s: None) -> RunResult:
        res = RunResult(policy_name=f"job-{job_id}")
        job_local = self.workdir / job_id
        up_dir = job_local / "up" / job_id
        down_dir = job_local / "down"
        shutil.rmtree(job_local, ignore_errors=True)
        up_dir.mkdir(parents=True)
        down_dir.mkdir(parents=True)
        (up_dir / "input.json").write_text(json.dumps(input_payload, ensure_ascii=False), encoding="utf-8")

        opened = False
        t_start = time.time()
        try:
            # 3. 입력 업로드 ("상위 폴더"를 대상으로 지정하면 <대상>/<원본폴더이름>이 만들어진다)
            r = self.run(self._sandbox_cmd("upload", self.name, str(up_dir), "/sandbox/work"), 60)
            if r.returncode != 0:
                res.incomplete = "sandbox_error"
                return res

            # 4. 조사용 정책 열기 (IP·사설 호스트는 열지 않고 주소 분석만 한다)
            if fetch_allowed:
                on_stage("policy_open")
                preset = job_local / f"job-{job_id}.yaml"
                preset.write_text(render_preset(job_id, target_host), encoding="utf-8")
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
            res.incomplete = res.incomplete or "agent_timeout"
        except SandboxError:
            res.incomplete = res.incomplete or "sandbox_error"
        finally:
            # 6. 정책은 항상 제거한다. 실패하면 한 번 더 시도하고 경보를 남긴다.
            if opened:
                on_stage("policy_close")
                ok = False
                for _ in range(2):
                    try:
                        rr = self.run(["nemoclaw", self.name, "policy", "remove", f"job-{job_id}", "--yes"], 60)
                        if rr.returncode == 0:
                            ok = True
                            break
                    except Exception:  # noqa: BLE001
                        continue
                res.residual_policy = not ok
                res.events.append({"at": _iso(_now()), "kind": "close", "host": target_host})

        # 7. 결과 파일 회수 (모델이 전달한 요약은 쓰지 않고 스크립트 원본 출력만 쓴다)
        try:
            self.run(self._sandbox_cmd("download", self.name, f"/sandbox/work/{job_id}", str(down_dir)), 60)
        except Exception:  # noqa: BLE001
            pass
        res.files = _read_files(down_dir)
        _add_blocked_events(res)
        _finish_agent_marks(res)
        shutil.rmtree(job_local, ignore_errors=True)
        return res

    def explain(self, job_id: str, payload: dict) -> dict | None:
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
