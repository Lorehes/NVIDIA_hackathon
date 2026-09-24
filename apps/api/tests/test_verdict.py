"""판정 엔진 단위 테스트: 규칙 4-3 각각 + 데모·보안 사례(상세 명세 9-1, 9-2)."""
import copy


from app import verdict as V
from app.kb import KB

kb = KB.load()
hanbit = kb.by_id["hanbit"]


def parse(reg, subs=(), ip=False, userinfo=False):
    return {"ok": True, "registrable_domain": reg, "domain_label": reg.split(".")[0], "suffix": reg.split(".")[-1],
            "subdomain_labels": list(subs), "is_ip_host": ip, "has_userinfo": userinfo, "host_ascii": reg,
            "host_unicode": reg, "scheme": "https", "path": "/"}


def similarity(best=None, contains=(), brand=(), confusable=(), mixed=False, pattern="none"):
    return {"ok": True, "closest_official": best or {"entity_id": "hanbit", "domain": "hanbit.example",
                                                       "similarity": 0.2, "edit_distance": 9, "pattern": "none"},
            "subdomain_contains_official": list(contains), "brand_in_domain": list(brand),
            "confusable_chars": list(confusable), "mixed_script": mixed, "typosquat_pattern": pattern}


def fetch(final, chain=None):
    chain = chain or [{"url": f"https://{final}/", "host": final, "registrable_domain": final, "status": 200,
                       "blocked": False, "error": None}]
    return {"ok": True, "chain": chain, "final_registrable_domain": final, "blocked_count":
            sum(1 for c in chain if c["blocked"])}


def page(fields=(), cross=None, apk=()):
    forms = [{"action_host": cross or "x", "action_registrable_domain": cross or "x",
              "cross_domain": bool(cross), "field_types": list(fields)}] if fields else []
    return {"ok": True, "forms": forms, "apk_links": list(apk), "trust_claims": [], "title": "", "brand_candidates": []}


def claim(entity="hanbit", purpose="delivery"):
    return {"ok": True, "entity_id": entity, "purpose": purpose}


CAND = [(hanbit, "exact")]


def decide(**kw):
    ev = V.Evidence(candidates=kw.pop("candidates", CAND), **kw)
    return V.decide(ev, kb)


def types(o):
    return {s["type"] for s in o.signals}


# ── 규칙 1: 데이터 없음 ─────────────────────────────────────────────────
def test_rule1_no_address_analysis_is_unknown():
    o = decide(parse=None)
    assert o.verdict == "unknown" and o.unknown_reason == "no_data"


def test_incomplete_agent_is_unknown_even_with_strong_signals():
    o = decide(parse=parse("account-check.test", ["hanbit", "example"]),
               similarity=similarity(contains=[{"entity_id": "hanbit", "domain": "hanbit.example",
                                                "match_kind": "domain", "label": "hanbit.example"}]),
               incomplete="agent_timeout")
    assert o.verdict == "unknown" and o.unknown_reason == "incomplete"
    assert "subdomain_disguise" in types(o)  # 발견한 것은 남긴다


# ── 규칙 2: 강 신호 + 기관 특정 ─────────────────────────────────────────
def test_rule2_lookalike_with_entity_is_suspected():
    best = {"entity_id": "hanbit", "domain": "hanbit.example", "similarity": 0.93, "edit_distance": 1,
            "pattern": "substitution"}
    o = decide(parse=parse("hanblt.example"), similarity=similarity(best), fetch=fetch("hanblt.example"),
               page=page(["password"]), claim=claim())
    assert o.verdict == "suspected_impersonation" and "lookalike_domain" in types(o)


def test_rule2_subdomain_disguise_without_claim_uses_address_entity():
    o = decide(parse=parse("account-check.test", ["hanbit", "example"]),
               similarity=similarity(contains=[{"entity_id": "hanbit", "domain": "hanbit.example",
                                                "match_kind": "domain", "label": "hanbit.example"}]),
               fetch=fetch("account-check.test"), page=page(), claim=claim(None, "other"), candidates=[])
    assert o.verdict == "suspected_impersonation"
    assert o.entity.id == "hanbit" and o.entity_source == "address"


def test_purpose_mismatch_card_in_delivery():
    o = decide(parse=parse("hanbit-parcel.test"), similarity=similarity(brand=[{"entity_id": "hanbit",
               "domain": "hanbit.example", "brand": "hanbit"}]), fetch=fetch("hanbit-parcel.test"),
               page=page(["card_number", "card_cvc"]), claim=claim())
    assert o.verdict == "suspected_impersonation"
    pm = next(s for s in o.signals if s["type"] == "purpose_mismatch")
    assert pm["data"]["fields"] == ["card_number", "card_cvc"] and pm["data"]["policy"]


def test_apk_is_strong():
    o = decide(parse=parse("evil.test"), similarity=similarity(), fetch=fetch("evil.test"),
               page=page(apk=["https://evil.test/a.apk"]), claim=claim())
    assert o.verdict == "suspected_impersonation" and "apk_download" in types(o)


# ── 규칙 3: 공식·파트너 = safe ───────────────────────────────────────────
def test_rule3_official_is_safe_without_warnings():
    o = decide(parse=parse("hanbit.example"), similarity=similarity({"entity_id": "hanbit", "domain": "hanbit.example",
               "similarity": 1.0, "edit_distance": 0, "pattern": "same"}), fetch=fetch("hanbit.example"),
               page=page(), claim=claim())
    assert o.verdict == "safe" and types(o) == {"official_match"}


def test_official_login_page_with_password_is_still_safe():
    o = decide(parse=parse("hanbit.example"), similarity=similarity(), fetch=fetch("hanbit.example"),
               page=page(["password"]), claim=claim(purpose="account_security"))
    assert o.verdict == "safe" and "credential_form" in types(o)


def test_partner_payment_with_card_is_safe_not_warned():
    o = decide(parse=parse("pay-partner.example"), similarity=similarity(), fetch=fetch("pay-partner.example"),
               page=page(["card_number", "card_expiry", "name"]), claim=claim(purpose="payment"))
    assert o.verdict == "safe" and "partner_match" in types(o)
    assert "purpose_mismatch" not in types(o) and "domain_not_official" not in types(o)


def test_partner_domain_is_not_flagged_as_lookalike_or_disguise():
    best = {"entity_id": "hanbit", "domain": "hanbit.example", "similarity": 0.85, "edit_distance": 2, "pattern": "none"}
    o = decide(parse=parse("pay-partner.example"), similarity=similarity(best), fetch=fetch("pay-partner.example"),
               page=page(), claim=claim(purpose="payment"))
    assert o.verdict == "safe"


def test_official_but_form_posts_to_other_domain_is_not_safe():
    o = decide(parse=parse("hanbit.example"), similarity=similarity(), fetch=fetch("hanbit.example"),
               page=page(["password"], cross="collect-pay.test"), claim=claim(purpose="account_security"))
    assert o.verdict == "caution" and "cross_domain_form" in types(o)


def test_official_but_redirects_to_unknown_domain_is_not_safe():
    chain = [{"url": "https://hanbit.example/", "host": "hanbit.example", "registrable_domain": "hanbit.example",
              "status": 302, "blocked": False, "error": None},
             {"url": "https://evil.test/", "host": "evil.test", "registrable_domain": "evil.test", "status": 403,
              "blocked": True, "error": None}]
    o = decide(parse=parse("hanbit.example"), similarity=similarity(), fetch=fetch("hanbit.example", chain),
               page=page(), claim=claim())
    assert o.verdict == "caution" and {"redirect_other_domain", "redirect_blocked"} <= types(o)


def test_official_but_unreachable_is_unknown_not_safe():
    chain = [{"url": "https://hanbit.example/", "host": "hanbit.example", "registrable_domain": "hanbit.example",
              "status": None, "blocked": False, "error": "ReadTimeout"}]
    o = decide(parse=parse("hanbit.example"), similarity=similarity(), fetch=fetch("hanbit.example", chain),
               page={"ok": False}, claim=claim())
    assert o.verdict == "unknown" and o.unknown_reason == "fetch_failed"


# ── 규칙 4·5·6 ───────────────────────────────────────────────────────
def test_rule4_unknown_entity_with_credentials_is_caution_not_suspected():
    o = decide(parse=parse("member-check.test"), similarity=similarity(), fetch=fetch("member-check.test"),
               page=page(["password", "otp"], cross="data-send.test"), claim=claim(None, "other"), candidates=[])
    assert o.verdict == "caution" and "entity_not_in_kb" in types(o) and o.entity is None


def test_rule4_known_entity_but_unrelated_domain_is_caution():
    o = decide(parse=parse("benign.test"), similarity=similarity(), fetch=fetch("benign.test"), page=page(),
               claim=claim())
    assert o.verdict == "caution" and "domain_not_official" in types(o)


def test_rule6_no_entity_no_signals_is_unknown_no_kb():
    o = decide(parse=parse("plain.test"), similarity=similarity(), fetch=fetch("plain.test"), page=page(),
               claim=claim(None, "other"), candidates=[])
    assert o.verdict == "unknown" and o.unknown_reason == "no_kb"


def test_rule5_fetch_failed_without_address_signals():
    chain = [{"url": "https://plain.test/", "host": "plain.test", "registrable_domain": "plain.test", "status": None,
              "blocked": False, "error": "ConnectError"}]
    o = decide(parse=parse("plain.test"), similarity=similarity(), fetch=fetch("plain.test", chain),
               page={"ok": False}, claim=claim(None, "other"), candidates=[])
    assert o.verdict == "unknown" and o.unknown_reason == "fetch_failed"


def test_ip_host_is_mid_signal():
    o = decide(parse=parse("1.2.3.4", ip=True), similarity=similarity(), fetch={"ok": True, "skipped": True,
               "chain": [], "final_registrable_domain": None}, page={"ok": False}, claim=claim(None, "other"),
               candidates=[])
    assert o.verdict == "caution" and "ip_or_userinfo_host" in types(o)


# ── 결정성·입력 불변 ─────────────────────────────────────────────────
def test_same_input_same_verdict_and_input_not_mutated():
    kwargs = dict(parse=parse("hanblt.example"), similarity=similarity({"entity_id": "hanbit",
                  "domain": "hanbit.example", "similarity": 0.93, "edit_distance": 1, "pattern": "substitution"}),
                  fetch=fetch("hanblt.example"), page=page(["password"]), claim=claim())
    snap = copy.deepcopy(kwargs)
    assert decide(**kwargs).verdict == decide(**kwargs).verdict
    assert kwargs == snap


def test_forged_claim_entity_outside_kb_is_ignored():
    o = decide(parse=parse("plain.test"), similarity=similarity(), fetch=fetch("plain.test"), page=page(),
               claim=claim("nonexistent", "other"), candidates=[])
    assert o.entity is None
