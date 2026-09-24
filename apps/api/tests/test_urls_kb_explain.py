"""URL 추출(F1), KB 후보 검색(F4), 설명 검증(F8) 테스트."""
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
    assert res and all(s == "embedding" for _, s in res) and res[0][0].id == "hanbit"


def test_kb_official_records_and_known_domains():
    assert {"entity_id": "hanbit", "domain": "hanbit.example"} in kb.official_records()
    assert "pay-partner.example" in kb.all_known_domains()


# ── 설명 검증 ────────────────────────────────────────────────────────
def _payload(verdict="suspected_impersonation"):
    o = Outcome(verdict, kb.by_id["hanbit"], "exact", [
        {"type": "subdomain_disguise", "strength": "strong",
         "data": {"label": "hanbit.example", "official_domain": "hanbit.example"}}], "delivery")
    return ex.build_payload(o, "account-check.test", "한빛택배", "hanbit.example", ["문자를 보낸 전화번호가 진짜인지"])


TEMPLATE = {"unverified": ["문자를 보낸 전화번호가 진짜인지"]}
GOOD = {
    "headline": "한빛택배를 흉내 낸 가짜 사이트 같아요.", "warning": "링크를 누르지 마세요.", "detail": None,
    "confirmed_facts": ["진짜 사이트 이름은 account-check.test예요."],
    "suspicion_evidence": ["주소 앞에 hanbit.example을 붙여서 진짜처럼 보이게 했어요."],
    "unverified": ["내가 마음대로 바꾼 문장"],
    "recommended_action": "공식 앱에서 배송 상태를 확인하세요.", "action_bullets": [],
}


def test_good_explanation_passes_and_unverified_is_forced_from_code():
    out = ex.validate(dict(GOOD), _payload(), kb, TEMPLATE)
    assert out and out["source"] == "agent" and out["unverified"] == TEMPLATE["unverified"]


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
    ok = {**GOOD, "headline": "지금은 확인하지 못했어요.", "warning": None,
          "detail": "안전하다는 뜻이 아니에요.", "confirmed_facts": [], "suspicion_evidence": []}
    assert ex.validate(ok, p, kb, TEMPLATE)
    no = {**ok, "detail": "곧 알려드릴게요."}
    assert ex.validate(no, p, kb, TEMPLATE) is None


def test_malformed_output_is_rejected():
    for bad in (None, "text", {}, {**GOOD, "confirmed_facts": "x"}, {**GOOD, "headline": 3},
                {**GOOD, "action_bullets": ["a"] * 9}):
        assert ex.validate(bad, _payload(), kb, TEMPLATE) is None


def test_payload_has_no_free_text_from_page_or_url():
    p = _payload()
    import json

    s = json.dumps(p, ensure_ascii=False)
    assert "http" not in s and "trust_claims" not in s
