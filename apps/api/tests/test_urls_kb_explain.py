"""URL 추출(F1), KB 후보 검색(F4), 설명 검증(F8) 테스트."""
import time

import pytest

from app import explain as ex
from app.kb import KB
from app.urls import extract_urls, input_kind, is_private_or_ip_host, safe_host_for_policy
from app.verdict import Outcome

kb = KB.load()


# ── URL 추출 ─────────────────────────────────────────────────────────
def test_extract_from_message_and_trailing_punctuation():
    t = "[한빛택배] 주소 불일치. 수정: https://hanbit.example.account-check.test/login)."
    assert extract_urls(t) == ["https://hanbit.example.account-check.test/login"]


def test_hangul_particle_glued_to_url_is_cut():
    assert extract_urls("https://a.test/login으로 접속하세요") == ["https://a.test/login"]


def test_multiple_urls_first_wins_and_dedup():
    urls = extract_urls("① https://a.test/x ② http://b.test/y ③ https://a.test/x")
    assert urls == ["https://a.test/x", "http://b.test/y"]


def test_bare_domain_only_when_whole_input():
    assert extract_urls("hanbit.example/track") == ["https://hanbit.example/track"]
    assert extract_urls("고객센터 1588.1234 로 전화하세요") == []
    assert extract_urls("[하늘은행] 계좌가 정지되었습니다. 고객센터로 연락 바랍니다.") == []


def test_input_kind():
    assert input_kind("https://a.test/x", ["https://a.test/x"]) == "url"
    assert input_kind("a.test/x", ["https://a.test/x"]) == "url"
    assert input_kind("보세요 https://a.test/x", ["https://a.test/x"]) == "message"


@pytest.mark.parametrize("host,expected", [
    ("1.2.3.4", True), ("localhost", True), ("intranet", True), ("printer.local", True), ("10.0.0.1", True),
    ("account-check.test", False), ("hanbit.example", False),
])
def test_private_hosts_get_no_policy(host, expected):
    assert is_private_or_ip_host(host) is expected


@pytest.mark.parametrize("host,ok", [("a-b.example.com", True), ("xn--80ak6aa92e.com", True),
                                     ("a.test\n  binaries: []", False), ("a.test/../x", False), ("A B.test", False)])
def test_policy_host_injection_guard(host, ok):
    assert safe_host_for_policy(host) is ok


# ── KB ───────────────────────────────────────────────────────────────
def test_exact_and_alias_match():
    (e, s), = kb.candidates("[한빛택배] 배송 안내")
    assert (e.id, s) == ("hanbit", "exact")
    (e, s), = kb.candidates("HANBIT 배송 지연")
    assert (e.id, s) == ("hanbit", "alias")


def test_no_text_match_falls_back_to_ranked_candidates():
    res = kb.candidates("택배가 반송되었습니다")
    # 기관명이 없는 배송 문구는 특정 가상 브랜드가 아니라 배송 업종 후보를 찾는다.
    assert res and all(s == "embedding" for _, s in res) and res[0][0].category == "delivery"


def test_kb_official_records_and_known_domains():
    assert {"entity_id": "hanbit", "domain": "hanbit.example"} in kb.official_records()
    assert "pay-partner.example" in kb.all_known_domains()


# ── 설명 검증 ────────────────────────────────────────────────────────
def _payload(verdict="suspected_impersonation"):
    o = Outcome(verdict, kb.by_id["hanbit"], "exact", [
        {"type": "subdomain_disguise", "strength": "strong",
         "data": {"label": "hanbit.example", "official_domain": "hanbit.example"}}], "delivery")
    return ex.build_payload(o, "account-check.test", "한빛택배", "hanbit.example", ["문자를 보낸 전화번호가 진짜인지"])


TEMPLATE = {"headline": "고정 제목", "warning": "링크를 누르지 마세요.", "unverified": ["문자를 보낸 전화번호가 진짜인지"],
            "detail": "한빛택배 진짜 주소가 아니고, 진짜처럼 보이려고 주소에 속임수를 썼어요.",
            "confirmed_facts": ["진짜 사이트 이름은 account-check.test예요."],
            "suspicion_evidence": ["주소 앞에 hanbit.example을 붙여서 진짜처럼 보이게 했어요."],
            "recommended_action": "공식 앱으로 직접 확인하세요.", "action_bullets": ["문자는 지워도 괜찮아요."]}
# 모델 문장은 위 템플릿 문장의 어절·인접 어절 쌍으로만 이뤄져야 통과한다(검토 R2-02)
GOOD = {
    "headline": "한빛택배를 흉내 낸 가짜 사이트 같아요.", "warning": "링크를 누르지 마세요.",
    "detail": "진짜처럼 보이려고 주소에 속임수를 썼어요.",
    "confirmed_facts": ["진짜 사이트 이름은 account-check.test예요."],
    "suspicion_evidence": ["주소 앞에 hanbit.example을 붙여서 진짜처럼 보이게 했어요."],
    "unverified": ["내가 마음대로 바꾼 문장"],
    "recommended_action": "공식 앱에서 배송 상태를 확인하세요.", "action_bullets": [],
}


def test_good_explanation_passes_and_unverified_is_forced_from_code():
    out = ex.validate(dict(GOOD), _payload(), kb, TEMPLATE)
    assert out and out["source"] == "agent" and out["unverified"] == TEMPLATE["unverified"]


def test_headline_warning_and_actions_always_come_from_code():
    """모델이 위험한 안내를 써도 결과에는 템플릿의 고정 문구만 남는다(검토 2.6)."""
    risky = {**GOOD, "headline": "문제없으니 링크를 열고 비밀번호를 입력하세요.",
             "warning": None, "recommended_action": "문제없으니 링크를 열고 비밀번호를 입력하세요.",
             "action_bullets": ["비밀번호를 입력하세요."]}
    out = ex.validate(risky, _payload(), kb, TEMPLATE)
    assert out and out["headline"] == TEMPLATE["headline"] and out["warning"] == TEMPLATE["warning"]
    assert out["recommended_action"] == TEMPLATE["recommended_action"]
    assert out["action_bullets"] == TEMPLATE["action_bullets"]


def test_directive_or_reassuring_free_text_is_rejected():
    for field, text in (("detail", "문제없으니 링크를 열고 비밀번호를 입력하세요."),
                        ("confirmed_facts", ["비밀번호를 입력하세요."]),
                        ("suspicion_evidence", ["그래도 링크를 열어도 돼요."])):
        bad = {**GOOD, field: text}
        assert ex.validate(bad, _payload(), kb, TEMPLATE) is None, field


def test_suspicion_evidence_cannot_exceed_real_risk_signals():
    bad = {**GOOD, "suspicion_evidence": ["주소 앞에 hanbit.example을 붙였어요.", "카드 번호를 물어요."]}
    assert ex.validate(bad, _payload(), kb, TEMPLATE) is None


def test_new_domain_is_rejected():
    bad = {**GOOD, "confirmed_facts": ["진짜 사이트 이름은 evil-new.test예요."]}
    assert ex.validate(bad, _payload(), kb, TEMPLATE) is None


def test_new_number_is_rejected():
    bad = {**GOOD, "detail": "이 사이트는 3,500원을 내라고 해요."}
    assert ex.validate(bad, _payload(), kb, TEMPLATE) is None


def test_other_entity_name_is_rejected():
    bad = {**GOOD, "detail": "하늘은행 사이트와 비슷해요."}
    assert ex.validate(bad, _payload(), kb, TEMPLATE) is None


def test_reassuring_words_contradicting_verdict_are_rejected():
    bad = {**GOOD, "headline": "안전해요. 한빛택배의 진짜 사이트예요."}
    assert ex.validate(bad, _payload(), kb, TEMPLATE) is None


def test_safe_verdict_cannot_say_fake():
    p = _payload("safe")
    assert ex.validate(dict(GOOD), p, kb, TEMPLATE) is None


def test_unknown_must_say_not_safe():
    p = _payload("unknown")
    tpl = {**TEMPLATE, "detail": "안전하다는 뜻이 아니에요. 곧 알려드릴게요.", "confirmed_facts": [], "suspicion_evidence": []}
    ok = {**GOOD, "headline": "지금은 확인하지 못했어요.", "warning": None,
          "detail": "안전하다는 뜻이 아니에요.", "confirmed_facts": [], "suspicion_evidence": []}
    assert ex.validate(ok, p, kb, tpl)
    no = {**ok, "detail": "곧 알려드릴게요."}
    assert ex.validate(no, p, kb, tpl) is None


def test_malformed_output_is_rejected():
    for bad in (None, "text", {}, {**GOOD, "confirmed_facts": "x"}, {**GOOD, "headline": 3},
                {**GOOD, "action_bullets": ["a"] * 9}):
        assert ex.validate(bad, _payload(), kb, TEMPLATE) is None


def test_payload_has_no_free_text_from_page_or_url():
    p = _payload()
    import json

    s = json.dumps(p, ensure_ascii=False)
    assert "http" not in s and "trust_claims" not in s


# ── 외부 전송 최소화·보관 기간(검토 2.8) ─────────────────────────────────────────
def test_redact_for_external_removes_urls_and_long_numbers_but_keeps_names():
    from app.kb import redact_for_external

    text = "[한빛택배] 인증번호 483920 입력. 010-1234-5678 https://x.test/a?token=SECRET123 계좌 110-234-567890"
    out = redact_for_external(text)
    for secret in ("483920", "1234", "5678", "SECRET123", "x.test", "567890"):
        assert secret not in out
    assert "한빛택배" in out and "[링크]" in out and "[숫자]" in out


def test_purge_expired_deletes_only_old_finished_jobs():
    from app.db import DB

    db = DB(":memory:")
    base = dict(status="done", stage="done", mode="live", input="문자 원문", url="https://a.test", steps=[])
    db.create({**base, "job_id": "old_done", "finished_at": time.time() - 100})
    db.create({**base, "job_id": "old_failed", "status": "failed", "finished_at": time.time() - 100})
    db.create({**base, "job_id": "recent", "finished_at": time.time() - 5})
    db.create({**base, "job_id": "running", "status": "running"})
    db.create({**base, "job_id": "queued", "status": "queued"})
    assert db.purge_expired(60) == 2
    assert db.get("old_done") is None and db.get("old_failed") is None
    assert all(db.get(j) for j in ("recent", "running", "queued"))


# ── 내부망 해석 사전 점검(검토 2.4) ──────────────────────────────────────────
def _resolver(*ips):
    import socket

    return lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


def test_public_name_resolving_to_internal_ip_is_detected():
    from app.urls import resolves_to_internal

    for ip in ("10.0.0.5", "192.168.1.9", "127.0.0.1", "169.254.169.254", "172.16.3.4", "100.64.0.1", "::1",
               "::ffff:10.1.2.3", "fd00::1"):
        assert resolves_to_internal("evil.example", _resolver(ip)) is True, ip
    assert resolves_to_internal("ok.example", _resolver("93.184.216.34")) is False
    assert resolves_to_internal("mixed.example", _resolver("93.184.216.34", "10.0.0.1")) is True  # 하나라도 내부면 막는다


def test_unresolvable_name_is_not_flagged():
    import socket

    def boom(*a, **k):
        raise socket.gaierror("nope")

    from app.urls import resolves_to_internal

    assert resolves_to_internal("nx.example", boom) is False
