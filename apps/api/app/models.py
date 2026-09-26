"""API 스키마. 프론트엔드(apps/web/lib/types.ts)는 이 파일을 그대로 옮긴 것이다.

구조는 상세 명세 1·4-4절을 따르고, 결과 화면(디자인 v2)이 필요로 하는 필드를 추가했다.
판정 배지 문구·비교표·위험 목록은 코드가 정하고, 모델이 쓴 설명은 `explanation`에만 들어간다.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Verdict = Literal["safe", "caution", "suspected_impersonation", "unknown"]
Strength = Literal["positive", "strong", "mid", "info"]
JobStatus = Literal["queued", "running", "done", "failed"]
Purpose = Literal["delivery", "payment", "account_security", "government_notice", "prize_event", "other"]
StepKey = Literal["claim", "address", "sandbox", "page", "summary"]
StepStatus = Literal["waiting", "running", "done", "stopped"]


# ── 요청 ──────────────────────────────────────────────────────────
class InvestigationRequest(BaseModel):
    input: str = Field(min_length=1)
    mode: Literal["live", "replay"] = "live"
    case_id: str | None = None  # replay 모드에서 특정 데모 사례를 지정


class InvestigationAccepted(BaseModel):
    job_id: str
    status: JobStatus
    position: int
    url: str  # 조사할 링크(입력에서 추출)
    more_urls: list[str] = []  # 함께 발견된 나머지 링크(조사하지 않음)


# ── 결과 ──────────────────────────────────────────────────────────
class ClaimedEntity(BaseModel):
    id: str
    name: str
    source: Literal["exact", "alias", "embedding", "agent", "address", "none"]


class Signal(BaseModel):
    type: str
    strength: Strength
    data: dict[str, Any] = {}


class Explanation(BaseModel):
    headline: str  # "한빛택배를 흉내 낸 가짜 사이트 같아요."
    warning: str | None = None  # "링크를 누르지 마세요."
    detail: str | None = None  # 이유 한두 문장
    confirmed_facts: list[str] = []  # 확실한 것
    suspicion_evidence: list[str] = []  # 가짜라고 보는 이유 / 조심해야 하는 이유
    unverified: list[str] = []  # 확인하지 못한 것 (문자 입력이면 항상 발신번호 포함)
    recommended_action: str  # 이렇게 하세요 (한 문장)
    action_bullets: list[str] = []
    source: Literal["agent", "template"] = "template"


class UrlParts(BaseModel):
    url: str
    scheme: str
    subdomain_part: str  # 앞에 붙인 글자. 끝의 점 포함 ("hanbit.example."), 없으면 ""
    registrable_domain: str  # 진짜 사이트 이름
    path: str
    official_domain: str | None = None  # 사칭 대상의 공식 도메인(KB), 없으면 null
    matches_official: bool | None = None  # 공식 도메인과 같은가 (KB에 없으면 null)
    matches_partner: bool = False
    partner_domain: str | None = None


class ComparisonRow(BaseModel):
    key: Literal["address", "fields", "promise", "destination", "redirect", "sender"]
    label: str  # 주소 / 적는 칸 / 회사 약속 / 적은 내용 / 넘어간 곳 / 보낸 번호
    said: str  # 문자가 한 말
    found: str  # 실제로 확인한 것
    status: Literal["ok", "bad", "warn", "unknown"]
    status_label: str  # 같아요 / 달라요 / 조심 / 모름 / 맞아요 / 괜찮아요 / 결제에 필요 / 약속과 달라요


class RiskItem(BaseModel):
    label: str  # "진짜 주소를 앞에 붙임"
    level: Literal["high", "mid", "info"]
    level_label: str  # 많이 위험 / 조금 위험 / 참고


class RedirectHop(BaseModel):
    url: str
    host: str
    registrable_domain: str
    status: int | None = None
    blocked: bool = False
    error: str | None = None
    at: str | None = None


class AgentSummary(BaseModel):
    tool_calls: list[str] = []
    unexpected_tools: list[str] = []
    duration_ms: int | None = None
    model_reported: str | None = None
    kind: Literal["openshell", "local-sim", "replay", "not_run"] = "openshell"


class InvestigationResult(BaseModel):
    job_id: str
    mode: Literal["live", "replay"] = "live"
    input_kind: Literal["message", "url"]
    verdict: Verdict
    verdict_label: str  # 안전해요 / 안전해요 · 협력 회사 / 조심하세요 / 가짜로 의심돼요 / 알 수 없어요
    claimed_entity: ClaimedEntity | None = None
    stated_purpose: Purpose | None = None
    stated_purpose_label: str | None = None
    url: str
    actual_registrable_domain: str | None = None
    url_parts: UrlParts | None = None
    signals: list[Signal] = []
    explanation: Explanation
    comparison: list[ComparisonRow] = []
    risks: list[RiskItem] = []
    risks_note: str | None = None  # "회사를 알 수 없어서 …" 같은 위험 목록 아래 한 줄
    redirect_chain: list[RedirectHop] = []
    partial_findings: list[str] = []  # verdict == unknown일 때 멈추기 전에 발견한 것
    incomplete_reason: str | None = None  # 조사가 멈춘 이유(쉬운 말)
    more_urls: list[str] = []
    agent: AgentSummary = AgentSummary()
    identity: dict[str, Any] = {}
    connection: dict[str, Any] = {}


# ── 진행 상태 ─────────────────────────────────────────────────────
class StepState(BaseModel):
    key: StepKey
    title: str  # 누가 보낸 척하는지 / 주소 살펴보기 / 안전 공간에서 열어보기 / 페이지 속 내용 / 결과 정리
    status: StepStatus
    detail: str | None = None  # 끝났을 때 한 줄 결과


class JobView(BaseModel):
    job_id: str
    status: JobStatus
    stage: str  # 상세 명세 1-2의 내부 단계 이름
    stages: list[str]
    steps: list[StepState]
    position: int = 0  # 대기열 앞 사람 수(queued일 때)
    mode: Literal["live", "replay"] = "live"
    elapsed_ms: int = 0
    open_hosts: list[str] = []  # 지금 문을 열어 둔 호스트(진행 화면의 "안전 공간에서 여는 중")
    blocked_count: int = 0
    url: str = ""
    more_urls: list[str] = []
    result: InvestigationResult | None = None
    error: str | None = None  # 쉬운 말 오류 문구
    timings_ms: dict[str, int] = {}


# ── 상세 기록(trace) ──────────────────────────────────────────────
class TrickCheck(BaseModel):
    key: Literal["subdomain_disguise", "lookalike", "confusable", "ip_host", "userinfo"]
    question: str  # 진짜 주소를 앞에 끼워 넣었나요?
    hint: str  # 예시·부연
    hit: bool
    answer: str  # 예 / 아니오
    detail: str | None = None  # "hanbit.example을 앞에 붙였어요"


class SimilarityRow(BaseModel):
    entity_id: str
    name: str
    domain: str
    similarity: float
    label: str  # 많이 닮음 / 조금 닮음 / 거의 안 닮음
    note: str | None = None  # "한 글자(i → l)만 달라요"


class AddressTrace(BaseModel):
    url: str
    scheme: str
    host_unicode: str
    host_ascii: str
    subdomain_part: str
    registrable_domain: str
    path: str
    tricks: list[TrickCheck]
    similarity: list[SimilarityRow]
    summary_sentence: str  # 쉽게 말해, "한빛택배 옆집"이라고 문패를 단 …
    kb_note: str
    dev: dict[str, Any] = {}


class RedirectTrace(BaseModel):
    chain: list[RedirectHop]
    redirect_count: int
    blocked_count: int
    last_seen_domain: str | None = None
    blocked_hosts: list[str] = []
    dev: dict[str, Any] = {}


class FieldRow(BaseModel):
    type: str  # card_number 등 (개발자용)
    label: str  # 카드 번호
    verdict: Literal["needed", "not_needed", "ok", "unknown"]  # 필요 없음 / 괜찮음 / 미검사 …
    verdict_label: str


class PageTrace(BaseModel):
    available: bool
    title: str | None = None
    brand_candidates: list[str] = []
    brand_sentence: str | None = None
    stated_purpose_label: str | None = None
    expected_fields_label: str | None = None  # "이름 · 전화번호 · 받을 주소"
    field_rows: list[FieldRow] = []
    sends_to: str | None = None  # 다른 사이트(collect-pay.test) 등
    sends_cross_domain: bool = False
    sends_sentence: str | None = None
    apk_links: list[str] = []
    js_redirect_hint: bool = False
    trust_claims: list[str] = []
    dev: dict[str, Any] = {}


class AgentStepTrace(BaseModel):
    t_sec: int
    title: str
    detail: str | None = None
    lines: list[str] = []  # ✓ 주소 조각내기 …


class AgentTrace(BaseModel):
    steps: list[AgentStepTrace]
    unexpected_count: int
    unexpected_tools: list[str]
    duration_ms: int | None = None
    duration_sec: int | None = None
    model_reported: str | None = None
    explain_check: Literal["passed", "template", "skipped"] = "skipped"
    dev_log: list[str] = []  # "00:01  read input.json"
    dev: dict[str, Any] = {}


class SandboxEvent(BaseModel):
    at: str  # 14:31:52
    kind: Literal["open", "blocked", "close"]
    title: str
    detail: str | None = None


class SandboxTrace(BaseModel):
    opened_host: str | None = None
    blocked_hosts: list[str] = []
    events: list[SandboxEvent] = []
    open_seconds: int | None = None
    remaining_open: int = 0
    allowed: list[str] = [
        "조사할 사이트의 허용된 주소 들어가기", "페이지를 보기만 하기", "정해진 확인 도구만 쓰기",
    ]
    denied: list[str] = [
        "다른 사이트 들어가기", "정보를 적어서 보내기", "프로그램·앱 설치하기", "페이지 속 프로그램 실행하기",
    ]
    dev: dict[str, Any] = {}


class Trace(BaseModel):
    job_id: str
    verdict: Verdict
    verdict_label: str
    address: AddressTrace | None = None
    redirects: RedirectTrace | None = None
    page: PageTrace | None = None
    agent: AgentTrace | None = None
    sandbox: SandboxTrace | None = None


# ── 기타 ──────────────────────────────────────────────────────────
class DemoCase(BaseModel):
    id: str
    label: str  # 진짜 택배 사이트 / 한 글자 바꾼 가짜 주소 / …
    input: str
    expected_verdict: Verdict
    available_replay: bool = False


class Health(BaseModel):
    ok: bool
    sandbox_mode: str
    queue_length: int
    running: bool
    sandbox: dict[str, Any] = {}
    inference: dict[str, Any] = {}
