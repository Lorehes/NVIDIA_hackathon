"""FastAPI 앱. 루프백(127.0.0.1:8000)에서만 대기하고 Next.js 서버가 호출한다(브라우저는 직접 접근하지 않는다)."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from . import replay as replay_mod
from .config import settings
from .db import DB
from .demo_cases import DEMO_CASES, find_case
from .kb import get_kb
from .limits import RateLimiter, Slots
from .models import (DemoCase, Health, InvestigationAccepted, InvestigationRequest, JobView, StepState)
from .sandbox import make_sandbox
from .urls import MAX_INPUT, extract_urls, resolves_to_internal
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
    "session_required": "브라우저를 새로 고친 뒤 다시 시도해 주세요.",
    "too_many_requests": "너무 자주 확인하고 있어요. 잠시 뒤에 다시 시도해 주세요.",
    "body_too_large": "글이 너무 길어요. 문자 하나만 붙여 넣어 주세요. (2,000자까지)",
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str | None = None):
        self.status, self.code, self.message = status, code, message or MESSAGES.get(code, "문제가 생겼어요.")


class State:
    db: DB
    queue: JobQueue
    sandbox: object
    limiter: RateLimiter
    replay_slots: Slots


state = State()
_submit_lock = threading.Lock()  # 대기열 여유 확인과 작업 등록을 한 덩어리로 처리한다
_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


def owner_of(request: Request) -> str:
    """익명 세션 ID(Next 서버가 httpOnly 쿠키로 발급해 헤더로 전달)를 소유자 키로 바꾼다. 원문은 저장하지 않는다."""
    sid = request.headers.get("x-session-id", "")
    if not _SESSION_RE.match(sid):
        raise ApiError(401, "session_required")
    return hashlib.sha256(sid.encode()).hexdigest()


def _client_ip(request: Request) -> str:
    """Next 서버가 신뢰할 수 있는 앞단에서 받아 넘긴 클라이언트 주소. 형식이 맞지 않으면 없는 것으로 본다."""
    raw = request.headers.get("x-client-ip", "").strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def _check_rate(owner: str, request: Request) -> None:
    """IP → 세션 → 전체 순서로 센다. IP 한도를 먼저 검사하므로 세션을 돌려 가며 상태를 늘릴 수 없다.

    클라이언트 IP를 모르면(신뢰할 앞단이 없을 때) 모두가 하나의 통에서 더 낮은 합계 한도를 나눠 쓴다.
    """
    ip = _client_ip(request)
    ip_ok = (state.limiter.allow(f"ip:{ip}") if ip
             else state.limiter.allow("ip:unknown", settings.rate_limit_untrusted_per_min))
    if not ip_ok:
        raise ApiError(429, "too_many_requests")
    if not state.limiter.allow(f"s:{owner}"):
        raise ApiError(429, "too_many_requests")
    if not state.limiter.allow("global", settings.rate_limit_global_per_min):
        raise ApiError(429, "too_many_requests")


async def _read_json_limited(request: Request) -> bytes:
    """본문을 읽는 도중에도 한도를 넘으면 멈춘다(전부 받은 뒤 검사하지 않는다)."""
    limit = settings.max_body_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise ApiError(413, "body_too_large")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > limit:
            raise ApiError(413, "body_too_large")
    return bytes(buf)


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.db = DB(settings.db_path, settings.retention_hours * 3600)
    state.limiter = RateLimiter(settings.rate_limit_per_min)
    state.replay_slots = Slots(settings.replay_max)
    state.db.purge_expired(settings.retention_hours * 3600)
    stale = state.db.fail_stale()
    if stale:
        log.warning("marked %d stale jobs as failed", stale)
    state.sandbox = make_sandbox()
    _health_cache.update(at=float("-inf"), value=None)
    removed = state.sandbox.prepare()  # 이전 실행이 남긴 조사용 정책 정리
    if removed:
        log.warning("removed residual policies: %s", removed)
    resolver = resolves_to_internal if settings.sandbox_mode == "openshell" else None  # local은 접속하지 않는다
    state.queue = JobQueue(Investigator(state.db, state.sandbox, get_kb(), resolver))
    state.queue.start()
    stop = threading.Event()
    threading.Thread(target=_purge_loop, args=(stop,), name="retention", daemon=True).start()
    log.info("started: sandbox_mode=%s", settings.sandbox_mode)
    yield
    stop.set()
    state.queue.stop()


def _purge_loop(stop: threading.Event) -> None:
    """요청이 없어도 보관 기간이 지난 기록(문자 원문·결과)을 주기적으로 지운다."""
    while not stop.wait(settings.purge_interval_s):
        try:
            n = state.db.purge_expired(settings.retention_hours * 3600)
            if n:
                log.info("purged %d expired jobs", n)
        except Exception:  # noqa: BLE001 - 한 번 실패해도 다음 주기에 다시 시도한다
            log.exception("retention purge failed")


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
async def create_investigation(request: Request):
    owner = owner_of(request)
    raw = await _read_json_limited(request)
    try:
        req = InvestigationRequest.model_validate_json(raw)
    except ValidationError:
        raise ApiError(400, "bad_request")
    return await run_in_threadpool(_create, req, owner, request)


def _create(req: InvestigationRequest, owner: str, request: Request) -> InvestigationAccepted:
    text = req.input.strip()
    if not text:
        raise ApiError(400, "no_url_found")
    if len(text) > MAX_INPUT:
        raise ApiError(400, "input_too_long")
    urls = extract_urls(text)
    if not urls:
        raise ApiError(400, "no_url_found")
    url, more = urls[0], urls[1:]
    _check_rate(owner, request)  # 형식이 올바른 요청만 횟수에 센다
    state.db.purge_expired(settings.retention_hours * 3600)  # 보관 기간이 지난 기록은 새 요청이 올 때마다 정리한다
    job_id = new_job_id()

    if req.mode == "replay":
        case = find_case(req.case_id, text)
        if not case or not replay_mod.has_replay(case["id"]):
            raise ApiError(400, "replay_not_found")
        if not state.replay_slots.acquire():  # 재생 모드도 스레드를 무제한으로 만들지 않는다
            raise ApiError(429, "queue_full")
        try:
            state.db.create(dict(job_id=job_id, owner=owner, status="queued", stage="parse", mode="replay",
                                 case_id=case["id"], input=text, url=url, more_urls=more, steps=make_steps()))
            threading.Thread(target=_run_replay, args=(job_id, case["id"]), daemon=True).start()
        except Exception:
            state.replay_slots.release()
            raise
        return InvestigationAccepted(job_id=job_id, status="queued", position=0, url=url, more_urls=more)

    with _submit_lock:
        waiting = state.db.queued_ids()
        if len(waiting) >= settings.queue_max:
            raise ApiError(429, "queue_full")
        state.db.create(dict(job_id=job_id, owner=owner, status="queued", stage="parse", mode="live", input=text,
                             url=url, more_urls=more, steps=make_steps()))
        state.queue.submit(job_id)
    position = len(waiting) + (1 if state.queue.running else 0)
    return InvestigationAccepted(job_id=job_id, status="queued", position=position, url=url, more_urls=more)


def _run_replay(job_id: str, case_id: str) -> None:
    try:
        replay_mod.run_replay(state.db, job_id, case_id)
    finally:
        state.replay_slots.release()


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
def get_investigation(job_id: str, request: Request):
    job = state.db.get(job_id, owner_of(request))  # 남의 작업은 존재 여부도 알려 주지 않는다(404)
    if not job:
        raise ApiError(404, "not_found")
    return _view(job)


@app.get("/api/investigations/{job_id}/trace")
def get_trace(job_id: str, request: Request):
    job = state.db.get(job_id, owner_of(request))
    if not job or not job.get("trace"):
        raise ApiError(404, "not_found")
    return job["trace"]


@app.get("/api/demo-cases", response_model=list[DemoCase])
def demo_cases():
    return [DemoCase(id=c["id"], label=c["label"], input=c["input"], expected_verdict=c["expected_verdict"],
                     available_replay=replay_mod.has_replay(c["id"])) for c in DEMO_CASES]


_health_lock = threading.Lock()
_health_cache: dict = {"at": float("-inf"), "value": None}


def _sandbox_health() -> dict:
    """외부 명령(openshell)을 도는 점검은 캐시하고, 한 번에 하나만 실행한다. 공개 경로라서 요청마다 돌리지 않는다."""
    now = time.monotonic()
    fresh = now - _health_cache["at"] < settings.health_cache_s
    if fresh and _health_cache["value"] is not None:
        return _health_cache["value"]
    if _health_lock.acquire(blocking=False):
        try:
            _health_cache["value"] = state.sandbox.health()
            _health_cache["at"] = time.monotonic()
        finally:
            _health_lock.release()
    return _health_cache["value"] or {"sandbox": {"ok": False, "text": "확인 중"}, "inference": {}}


@app.get("/api/health", response_model=Health)
def health():
    h = _sandbox_health()
    return Health(ok=True, sandbox_mode=settings.sandbox_mode, queue_length=len(state.db.queued_ids()),
                  running=bool(state.queue.running), sandbox=h.get("sandbox", {}), inference=h.get("inference", {}))
