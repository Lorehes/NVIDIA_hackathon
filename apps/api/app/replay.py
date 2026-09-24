"""재생 모드(F12): 미리 저장한 결과를 단계별로 지연 표시한다. 모델이 과부하일 때 시연을 이어 가기 위한 장치.

화면에는 항상 "시연 모드" 표시가 붙는다(결과의 mode == "replay").
"""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path

from .config import settings
from .db import DB
from .models import InvestigationResult, Trace
from .worker import make_steps


def replay_path(case_id: str) -> Path:
    return settings.replay_dir / f"{case_id}.json"


def has_replay(case_id: str) -> bool:
    return replay_path(case_id).exists()


def save_replay(case_id: str, result: dict, trace: dict, steps: list[dict]) -> None:
    settings.replay_dir.mkdir(parents=True, exist_ok=True)
    replay_path(case_id).write_text(
        json.dumps({"case_id": case_id, "result": result, "trace": trace, "steps": steps},
                   ensure_ascii=False, indent=2), encoding="utf-8")


def _sleep(sec: float) -> None:
    time.sleep(max(0.0, sec / max(settings.replay_speed, 0.01)))


def run_replay(db: DB, job_id: str, case_id: str) -> None:
    data = json.loads(replay_path(case_id).read_text(encoding="utf-8"))
    final = {s["key"]: s for s in data["steps"]}
    blocked = int(data["trace"].get("redirects", {}) and data["trace"]["redirects"].get("blocked_count", 0))
    host = data["result"].get("url_parts", {}) and data["result"]["url_parts"].get("registrable_domain")
    incomplete = data["result"].get("incomplete_reason")
    t0 = time.time()
    db.update(job_id, status="running", stage="parse", started_at=t0, steps=make_steps(claim=("running", None)))
    _sleep(1.2)
    d = lambda k: final[k].get("detail")  # noqa: E731
    db.update(job_id, stage="kb_lookup", steps=make_steps(claim=("done", d("claim")), address=("running", None)))
    _sleep(1.5)
    db.update(job_id, stage="policy_open", open_hosts=[host] if host else [],
              steps=make_steps(claim=("done", d("claim")), address=("done", d("address")),
                               sandbox=("running", "링크 한 곳만 열어 보는 중")))
    _sleep(3.0)
    if blocked:
        db.update(job_id, stage="agent_investigate", blocked_count=blocked)
        _sleep(1.5)
    db.update(job_id, stage="policy_close", open_hosts=[], blocked_count=blocked,
              steps=make_steps(claim=("done", d("claim")), address=("done", d("address")),
                               sandbox=("stopped" if incomplete else "done", d("sandbox")),
                               page=("stopped" if incomplete else "running", "못 함" if incomplete else None)))
    _sleep(1.5)
    db.update(job_id, stage="explain",
              steps=make_steps(claim=("done", d("claim")), address=("done", d("address")),
                               sandbox=("stopped" if incomplete else "done", d("sandbox")),
                               page=("stopped" if incomplete else "done", d("page")),
                               summary=("running", "쉽게 설명을 써요")))
    _sleep(1.5)
    result = copy.deepcopy(data["result"])
    trace = copy.deepcopy(data["trace"])
    result["job_id"] = trace["job_id"] = job_id
    result["mode"] = "replay"
    result.setdefault("agent", {})["kind"] = "replay"
    r = InvestigationResult.model_validate(result).model_dump(mode="json")
    tr = Trace.model_validate(trace).model_dump(mode="json")
    db.update(job_id, stage="done", status="done", finished_at=time.time(), result=r, trace=tr,
              steps=data["steps"], timings={"total": int((time.time() - t0) * 1000)})
