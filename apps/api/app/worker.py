"""조사 파이프라인(상세 명세 4절)과 순차 작업 큐(큐 워커 1개).

조사용 프리셋이 샌드박스 전체에 적용되므로 MVP에서는 작업을 1건씩 처리한다.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
import traceback
import uuid
from typing import Any

from . import explain as explain_mod
from . import presentation as pres
from . import trace as trace_mod
from .db import DB
from .kb import KB
from .models import InvestigationResult, Trace
from .sandbox import RunResult
from .urls import input_kind, is_private_or_ip_host, parse_url
from .verdict import Evidence, decide

from checklib import similarity as sim_lib  # noqa: E402  (urls.py가 sys.path를 등록한다)
from . import ko

log = logging.getLogger("worker")

STAGES = ["parse", "kb_lookup", "policy_open", "agent_investigate", "policy_close", "verdict", "explain", "done"]
STEP_TITLES = {
    "claim": "누가 보낸 척하는지",
    "address": "주소 살펴보기",
    "sandbox": "안전 공간에서 열어보기",
    "page": "페이지 속 내용",
    "summary": "결과 정리",
}
STEP_ORDER = ["claim", "address", "sandbox", "page", "summary"]


def new_job_id() -> str:
    return "j_" + uuid.uuid4().hex  # 128비트. 소유자 검사와 별개로 추측이 불가능해야 한다


def make_steps(**states: tuple[str, str | None]) -> list[dict]:
    """states: key=(status, detail). 지정하지 않은 단계는 waiting."""
    out = []
    for k in STEP_ORDER:
        status, detail = states.get(k, ("waiting", None))
        out.append({"key": k, "title": STEP_TITLES[k], "status": status, "detail": detail})
    return out


class Investigator:
    def __init__(self, db: DB, sandbox, kb: KB, resolver=None):
        """resolver: 호스트 이름이 내부망 주소로 해석되는지 알려 주는 함수. 실제로 접속하는 운영 모드에서만 넘긴다."""
        self.db, self.sandbox, self.kb, self.resolver = db, sandbox, kb, resolver

    # 진행 상태 갱신 도우미
    def _set(self, job_id: str, stage: str | None = None, steps: list[dict] | None = None, **kw: Any) -> None:
        fields = dict(kw)
        if stage:
            fields["stage"] = stage
        if steps is not None:
            fields["steps"] = steps
        self.db.update(job_id, **fields)

    def run(self, job_id: str) -> None:
        job = self.db.get(job_id)
        if not job:
            return
        t_all = time.time()
        timings: dict[str, int] = {}
        self._set(job_id, "parse", status="running", started_at=time.time(),
                  steps=make_steps(claim=("running", None)))
        try:
            self._run(job, timings)
        except Exception as e:  # noqa: BLE001 - 어떤 실패도 거짓 safe 없이 failed로 끝낸다
            log.error("job %s crashed: %s\n%s", job_id, e, traceback.format_exc())
            self._set(job_id, status="failed", stage="done", finished_at=time.time(),
                      error="조사 중에 문제가 생겼어요. 잠시 뒤에 다시 확인해 주세요.",
                      timings={**timings, "total": int((time.time() - t_all) * 1000)})

    # ── 본체 ─────────────────────────────────────────────────────
    def _run(self, job: dict, timings: dict[str, int]) -> None:
        job_id, url, text = job["job_id"], job["url"], job["input"]
        t0 = time.time()
        parse_host = parse_url(url)  # 호스트 측: 문자열 파싱만(네트워크 없음)
        message_given = input_kind(text, [url]) == "message"

        # 1~2. 파싱과 KB 후보
        cands = self.kb.candidates(text if message_given else url)
        timings["parse"] = int((time.time() - t0) * 1000)
        claim_detail = (f"{ko.subj(cands[0][0].name)} 보낸 척하는 문자예요" if cands and cands[0][1] != "embedding"
                        else "링크만 있어서 주소로 확인해요" if not message_given else "어느 회사인지 특정하지 못했어요")
        addr_detail = (f"진짜 사이트 이름은 {parse_host['registrable_domain']}예요" if parse_host.get("ok") else None)
        self._set(job_id, "kb_lookup", steps=make_steps(claim=("done", claim_detail), address=("done", addr_detail)))

        fetch_allowed = bool(parse_host.get("ok")) and not is_private_or_ip_host(parse_host["host_ascii"])
        internal = False
        if fetch_allowed and self.resolver:  # 정책을 열기 전에 DNS 결과가 내부망인지 확인
            internal = self.resolver(parse_host["host_ascii"])
            fetch_allowed = not internal
        payload = {
            "job_id": job_id, "url": url, "message_text": text if message_given else None,
            "kb_candidates": [e.as_candidate() for e, _ in cands],
            "kb_official_domains": self.kb.official_records(),
            "fetch_allowed": fetch_allowed,
        }

        # 3~7. 샌드박스 조사
        def on_stage(stage: str) -> None:
            steps = make_steps(claim=("done", claim_detail), address=("done", addr_detail),
                               sandbox=("running", "안전 공간의 문을 열고 있어요" if stage == "policy_open" else "링크 한 곳만 열어 보는 중"))
            hosts = [parse_host["host_ascii"]] if fetch_allowed and stage != "policy_close" and parse_host.get("ok") else []
            self._set(job_id, stage, steps=steps, open_hosts=hosts)

        t1 = time.time()
        run: RunResult = self.sandbox.investigate(job_id, payload, parse_host.get("host_ascii", ""), fetch_allowed,
                                                  on_stage)
        timings.update(run.timings_ms)
        timings["sandbox_total"] = int((time.time() - t1) * 1000)
        files = run.files
        blocked_count = (files.get("fetch_chain") or {}).get("blocked_count", 0)
        self._set(job_id, "verdict", open_hosts=[], blocked_count=blocked_count,
                  steps=make_steps(claim=("done", claim_detail), address=("done", addr_detail),
                                   sandbox=("stopped" if run.incomplete else "done",
                                            pres_incomplete(run.incomplete) if run.incomplete else
                                            ("다른 사이트로 넘어가려고 해서 막았어요" if blocked_count else "링크 한 곳을 열어봤어요")),
                                   page=("waiting", None)))

        # 8. 판정. 주소 분석은 호스트가 다시 계산하고, 샌드박스 파일은 요청과 맞는지 대조한 뒤에만 쓴다(검토 2.3).
        t2 = time.time()
        host_sim = None
        if parse_host.get("ok"):
            host_sim = {**sim_lib.compare(parse_host, self.kb.official_records())}
        if not run.incomplete:
            mismatch = files_mismatch(files, parse_host)
            if mismatch:
                log.error("job %s: sandbox result rejected (%s)", job_id, mismatch)
                run.incomplete = "result_mismatch"
        ev = Evidence(parse=parse_host if parse_host.get("ok") else files.get("parse_url"),
                      similarity=host_sim or files.get("similarity"),
                      fetch=files.get("fetch_chain"), page=files.get("page"), claim=files.get("claim"),
                      candidates=cands, incomplete=run.incomplete, internal_resolution=internal)
        if run.incomplete:  # 멈춘 경우에도 발견한 것을 보여 주려고 호스트 측 문자열 분석을 쓴다(판정은 unknown)
            ev.parse, ev.similarity = parse_host, host_sim
            if run.incomplete == "result_mismatch":  # 대조에 실패한 파일의 내용은 화면에도 쓰지 않는다
                ev.fetch = ev.page = None
        outcome = decide(ev, self.kb)
        timings["verdict"] = int((time.time() - t2) * 1000)

        # 9~10. 설명 (모델 → 검증 → 실패하면 템플릿)
        self._set(job_id, "explain", steps=make_steps(
            claim=("done", claim_detail), address=("done", addr_detail),
            sandbox=("stopped" if run.incomplete else "done", None),
            page=("stopped" if run.incomplete else "done", "못 함" if run.incomplete else _page_detail(files.get("page"))),
            summary=("running", "쉽게 설명을 써요")))
        t3 = time.time()
        result, trace, meta = build_outputs(job, outcome, ev, run, parse_host, host_sim, self.kb, self.sandbox,
                                            message_given, timings, run.incomplete)
        timings["explain"] = int((time.time() - t3) * 1000)
        timings["total"] = int((time.time() - t0) * 1000)

        # 유효성 검증(스키마) 후 저장
        result_m = InvestigationResult.model_validate(result)
        trace_m = Trace.model_validate(trace)
        final_steps = make_steps(
            claim=("done", claim_detail), address=("done", addr_detail),
            sandbox=("stopped" if run.incomplete else "done",
                     pres_incomplete(run.incomplete) if run.incomplete else
                     ("다른 사이트로 넘어가려고 해서 막았어요" if blocked_count else "링크 한 곳을 열어봤어요")),
            page=("stopped" if run.incomplete else "done", "못 함" if run.incomplete else _page_detail(files.get("page"))),
            summary=("stopped" if run.incomplete else "done", None))
        self._set(job_id, "done", status="done", finished_at=time.time(), steps=final_steps,
                  result=result_m.model_dump(mode="json"), trace=trace_m.model_dump(mode="json"),
                  timings=timings, blocked_count=blocked_count)
        if run.residual_policy:
            log.error("ALERT: job %s policy %s may remain in the sandbox", job_id, run.policy_name)


def files_mismatch(files: dict, parse_host: dict) -> str | None:
    """샌드박스가 돌려준 결과가 이 작업의 대상 주소와 맞는지 확인한다. 어긋나면 이유(코드), 맞으면 None.

    에이전트가 결과 파일을 바꾸거나 다른 작업의 파일이 섞여도 호스트가 계산한 값과 다르면 판정에 쓰지 않는다.
    이동 경로는 단계마다 주소에서 호스트·등록 도메인을 다시 계산해 대조하고, 공식 여부 판정에 쓰이는
    `final_registrable_domain`도 경로에서 다시 계산한 값과 같아야 한다.
    """
    if not parse_host.get("ok"):
        return None
    parse = files.get("parse_url")
    if parse and parse.get("ok"):
        for key in ("host_ascii", "registrable_domain"):
            if parse.get(key) != parse_host.get(key):
                return f"parse_url.{key}"
    fetch = files.get("fetch_chain")
    if fetch and fetch.get("ok") and not fetch.get("skipped"):
        chain = fetch.get("chain")
        if not isinstance(chain, list) or not all(isinstance(h, dict) for h in chain):
            return "fetch_chain.shape"
        last_ok = None
        for i, hop in enumerate(chain):
            p = parse_url(str(hop.get("url", "")))
            if not p.get("ok"):
                return "fetch_chain.hop_url"
            if hop.get("host") != p["host_ascii"] or hop.get("registrable_domain") != p["registrable_domain"]:
                return "fetch_chain.hop_host"
            if i == 0 and p["host_ascii"] != parse_host.get("host_ascii"):
                return "fetch_chain.first_host"
            if not hop.get("blocked") and hop.get("error") is None:
                last_ok = (hop, p)
        if fetch.get("final_registrable_domain") != (last_ok[1]["registrable_domain"] if last_ok else None):
            return "fetch_chain.final_domain"
        if fetch.get("final_url") != (last_ok[0].get("url") if last_ok else None):
            return "fetch_chain.final_url"
    return None


def pres_incomplete(code: str | None) -> str:
    return ko.INCOMPLETE_REASONS.get(code or "", "조사가 중간에 멈췄어요")


def _page_detail(page: dict | None) -> str | None:
    if not page or not page.get("ok"):
        return "페이지를 보지 못했어요"
    n = sum(len(f.get("field_types", [])) for f in page.get("forms", []))
    return f"적는 칸 {n}개를 찾았어요" if n else "적는 칸이 없어요"


# ══ 결과 조립 ═════════════════════════════════════════════════════════
def build_outputs(job: dict, outcome, ev: Evidence, run: RunResult, parse_host: dict, host_sim: dict | None,
                  kb: KB, sandbox, message_given: bool, timings: dict, incomplete: str | None):
    job_id, url = job["job_id"], job["url"]
    parse = ev.parse if ev.parse and ev.parse.get("ok") else (parse_host if parse_host.get("ok") else None)
    fetch = ev.fetch if ev.fetch and ev.fetch.get("ok") else None
    page = ev.page if ev.page and ev.page.get("ok") else None
    claim = ev.claim if ev.claim and ev.claim.get("ok") else None
    entity = outcome.entity
    actual = ((fetch or {}).get("final_registrable_domain") or (parse or {}).get("registrable_domain"))
    claim_name = (claim or {}).get("name")
    name = pres.sanitize_name(claim_name) if not entity else entity.name

    # 설명
    incomplete_text = pres_incomplete(incomplete) if incomplete else None
    template = pres.build_explanation(outcome, page, actual, claim_name, message_given, incomplete_text)
    explanation, explain_check = template, "skipped"
    if not incomplete and not run.residual_policy:  # 정책이 남았을 수 있으면 그 샌드박스에서 에이전트를 더 돌리지 않는다
        payload = explain_mod.build_payload(outcome, actual, name, entity.official_domains[0] if entity else None,
                                            template["unverified"])
        try:
            out = sandbox.explain(job_id, payload)
        except Exception:  # noqa: BLE001
            out = None
        if out is not None:
            checked = explain_mod.validate(out, payload, kb, template)
            if checked:
                explanation, explain_check = checked, "passed"
            else:
                explain_check = "template"

    for s_ in outcome.signals:  # 화면이 "별빛마켓의 진짜 주소는 목록에 없어요"를 쓸 수 있게 이름을 실어 준다
        if s_["type"] == "entity_not_in_kb" and name:
            s_["data"]["name"] = name
    risks, risks_note = pres.build_risks(outcome, page)
    comparison = pres.build_comparison(outcome, page, fetch, parse, claim_name, message_given) if parse else []
    parts = pres.url_parts(parse, url, entity, (fetch or {}).get("final_registrable_domain")) if parse else None
    partial = pres.partial_findings(outcome, name, actual, host_sim) if incomplete else []
    chain = (fetch or {}).get("chain", [])

    agent = run.agent or {}
    result = {
        "job_id": job_id,
        "mode": "live",
        "input_kind": "message" if message_given else "url",
        "verdict": outcome.verdict,
        "verdict_label": pres.verdict_label(outcome),
        "claimed_entity": ({"id": entity.id, "name": entity.name, "source": outcome.entity_source}
                           if entity else None),
        "stated_purpose": outcome.purpose,
        "stated_purpose_label": ko.PURPOSE_LABELS.get(outcome.purpose) if outcome.purpose else None,
        "url": url,
        "actual_registrable_domain": actual,
        "url_parts": parts,
        "signals": [{"type": s["type"], "strength": s["strength"], "data": s["data"]} for s in outcome.signals],
        "explanation": explanation,
        "comparison": comparison,
        "risks": risks,
        "risks_note": risks_note,
        "redirect_chain": [{k: h.get(k) for k in ("url", "host", "registrable_domain", "status", "blocked", "error", "at")}
                           for h in chain],
        "partial_findings": partial,
        "incomplete_reason": incomplete_text,
        "more_urls": job.get("more_urls", []),
        "agent": {
            "tool_calls": agent.get("tool_calls", []), "unexpected_tools": agent.get("unexpected_tools", []),
            "duration_ms": agent.get("duration_ms"), "model_reported": agent.get("model_reported"),
            "kind": agent.get("kind", "openshell"),
        },
    }

    trace = {
        "job_id": job_id, "verdict": outcome.verdict, "verdict_label": pres.verdict_label(outcome),
        "address": trace_mod.address_trace(parse, ev.similarity if ev.similarity and ev.similarity.get("ok") else host_sim,
                                           outcome, kb, url) if parse else None,
        "redirects": trace_mod.redirect_trace(fetch),
        "page": trace_mod.page_trace(ev.page, outcome, entity, actual) if not incomplete else
        {"available": False, "dev": {}},
        "agent": trace_mod.agent_trace({"agent": agent, "files": run.files}, claim, entity, explain_check,
                                       timings.get("sandbox_total") and (timings.get("sandbox_total", 0)
                                                                          + timings.get("explain", 0)),
                                       fetch_done=bool(fetch)),
        "sandbox": trace_mod.sandbox_trace({"events": run.events}, run.policy_name, run.residual_policy),
    }
    return result, trace, {"explain_check": explain_check}


# ══ 큐 ═══════════════════════════════════════════════════════════
class JobQueue:
    def __init__(self, investigator: Investigator):
        self.inv = investigator
        self.q: "queue.Queue[str]" = queue.Queue()
        self.running: str | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="investigator", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.q.put("")

    def submit(self, job_id: str) -> None:
        self.q.put(job_id)

    def _loop(self) -> None:
        while not self._stop.is_set():
            job_id = self.q.get()
            if not job_id:
                continue
            self.running = job_id
            try:
                self.inv.run(job_id)
            finally:
                self.running = None
