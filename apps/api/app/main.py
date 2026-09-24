"""FastAPI 앱. 루프백(127.0.0.1:8000)에서만 대기하고 Next.js 서버가 호출한다(브라우저는 직접 접근하지 않는다)."""
from __future__ import annotations

import logging
import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import replay as replay_mod
from .config import settings
from .db import DB
from .demo_cases import DEMO_CASES, find_case
from .kb import get_kb
from .models import (DemoCase, Health, InvestigationAccepted, InvestigationRequest, JobView, StepState)
from .sandbox import make_sandbox
from .urls import MAX_INPUT, extract_urls
from .worker import STAGES, Investigator, JobQueue, make_steps, new_job_id

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("api")

MESSAGES = {
    "no_url_found": "이 문자에는 링크가 없어요. 링크가 있는 문자를 넣어 주세요.",
    "input_too_long": "글이 너무 길어요. 문자 하나만 붙여 넣어 주세요. (2,000자까지)",
    "queue_full": "지금 확인하려는 사람이 많아요. 잠시 뒤에 다시 시도해 주세요.",
    "not_found": "찾을 수 없는 조사예요.",
    "replay_not_found": "이 문자는 저장된 시연 결과가 없어요. 시연 모드를 끄고 확인해 주세요.",
    "bad_request": "요청을 이해하지 못했어요.",
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str | None = None):
        self.status, self.code, self.message = status, code, message or MESSAGES.get(code, "문제가 생겼어요.")


class State:
    db: DB
    queue: JobQueue
    sandbox: object


state = State()


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.db = DB(settings.db_path)
    stale = state.db.fail_stale()
    if stale:
        log.warning("marked %d stale jobs as failed", stale)
    state.sandbox = make_sandbox()
    removed = state.sandbox.prepare()  # 이전 실행이 남긴 조사용 정책 정리
    if removed:
        log.warning("removed residual policies: %s", removed)
    state.queue = JobQueue(Investigator(state.db, state.sandbox, get_kb()))
    state.queue.start()
    log.info("started: sandbox_mode=%s", settings.sandbox_mode)
    yield
    state.queue.stop()


app = FastAPI(title="사칭 탐지 개인 보안 에이전트 API", lifespan=lifespan)
if settings.cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST"],
                       allow_headers=["*"])


@app.exception_handler(ApiError)
async def api_error_handler(_: Request, exc: ApiError):
    return JSONResponse(status_code=exc.status, content={"error": {"code": exc.code, "message": exc.message}})


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"error": {"code": "bad_request", "message": MESSAGES["bad_request"]}})


# ── 조사 요청 ────────────────────────────────────────────────────────
@app.post("/api/investigations", status_code=202, response_model=InvestigationAccepted)
def create_investigation(req: InvestigationRequest):
    text = req.input.strip()
    if not text:
        raise ApiError(400, "no_url_found")
    if len(text) > MAX_INPUT:
        raise ApiError(400, "input_too_long")
    urls = extract_urls(text)
    if not urls:
        raise ApiError(400, "no_url_found")
    url, more = urls[0], urls[1:]
    job_id = new_job_id()

    if req.mode == "replay":
        case = find_case(req.case_id, text)
        if not case or not replay_mod.has_replay(case["id"]):
            raise ApiError(400, "replay_not_found")
        state.db.create(dict(job_id=job_id, status="queued", stage="parse", mode="replay", case_id=case["id"],
                             input=text, url=url, more_urls=more, steps=make_steps()))
        threading.Thread(target=replay_mod.run_replay, args=(state.db, job_id, case["id"]), daemon=True).start()
        return InvestigationAccepted(job_id=job_id, status="queued", position=0, url=url, more_urls=more)

    waiting = state.db.queued_ids()
    if len(waiting) >= settings.queue_max:
        raise ApiError(429, "queue_full")
    state.db.create(dict(job_id=job_id, status="queued", stage="parse", mode="live", input=text, url=url,
                         more_urls=more, steps=make_steps()))
    state.queue.submit(job_id)
    position = len(waiting) + (1 if state.queue.running else 0)
    return InvestigationAccepted(job_id=job_id, status="queued", position=position, url=url, more_urls=more)


def _view(job: dict) -> JobView:
    if job["mode"] == "live" and job["status"] == "queued":
        ids = state.db.queued_ids()
        position = (ids.index(job["job_id"]) if job["job_id"] in ids else 0) + (1 if state.queue.running else 0)
    else:
        position = 0
    end = job.get("finished_at") or time.time()
    elapsed = int((end - job["started_at"]) * 1000) if job.get("started_at") else 0
    return JobView(
        job_id=job["job_id"], status=job["status"], stage=job["stage"], stages=STAGES,
        steps=[StepState(**s) for s in job["steps"]], position=position, mode=job["mode"], elapsed_ms=elapsed,
        open_hosts=job["open_hosts"], blocked_count=job["blocked_count"], url=job["url"],
        more_urls=job["more_urls"], result=job.get("result"), error=job.get("error"), timings_ms=job["timings"])


@app.get("/api/investigations/{job_id}", response_model=JobView)
def get_investigation(job_id: str):
    job = state.db.get(job_id)
    if not job:
        raise ApiError(404, "not_found")
    return _view(job)


@app.get("/api/investigations/{job_id}/trace")
def get_trace(job_id: str):
    job = state.db.get(job_id)
    if not job or not job.get("trace"):
        raise ApiError(404, "not_found")
    return job["trace"]


@app.get("/api/demo-cases", response_model=list[DemoCase])
def demo_cases():
    return [DemoCase(id=c["id"], label=c["label"], input=c["input"], expected_verdict=c["expected_verdict"],
                     available_replay=replay_mod.has_replay(c["id"])) for c in DEMO_CASES]


@app.get("/api/health", response_model=Health)
def health():
    h = state.sandbox.health()
    return Health(ok=True, sandbox_mode=settings.sandbox_mode, queue_length=len(state.db.queued_ids()),
                  running=bool(state.queue.running), sandbox=h.get("sandbox", {}), inference=h.get("inference", {}))
