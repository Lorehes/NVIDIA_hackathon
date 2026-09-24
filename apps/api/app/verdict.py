"""판정 엔진(F7): 샌드박스가 남긴 파일만 입력으로 신호를 계산하고 규칙표(상세 명세 4절)대로 판정한다.

모델은 판정에 관여하지 않는다. 같은 입력이면 같은 판정(N5).

명세 대비 조정(사유는 docs/decisions.md):
- `brand_in_domain`(강): 등록 도메인 이름 안에 공식 브랜드 이름이 들어 있음(hanbit-parcel.test).
- `domain_not_official`(중): 사칭 대상이 KB에 있는데 주소가 공식·파트너 목록에 없음.
- 공식·파트너 도메인 위에서는 목적 불일치를 판정에 쓰지 않는다(목적 분류 오류로 정상 사이트를 흔들지 않기 위해).
- 조사가 중간에 멈추면(`incomplete`) 발견한 것과 관계없이 `unknown`(N6).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .kb import KB, Entity

SIM_THRESHOLD = 0.80

CREDENTIAL_TYPES = {"password", "card_number", "card_cvc", "card_expiry", "bank_account", "resident_id", "otp"}
CARD = {"card_number", "card_cvc", "card_expiry"}

# 목적별로 "요구하면 안 되는" 민감 입력란 (상세 명세 4-2)
PURPOSE_FORBIDDEN: dict[str, set[str]] = {
    "delivery": CARD | {"password", "bank_account", "resident_id", "otp"},
    "payment": {"password", "bank_account", "resident_id"},
    "account_security": CARD | {"bank_account", "resident_id"},
    "government_notice": CARD | {"password", "bank_account"},
    "prize_event": CARD | {"password", "bank_account", "resident_id", "otp"},
    "other": set(),
}

VERDICT_LABELS = {
    "safe": "안전해요",
    "caution": "조심하세요",
    "suspected_impersonation": "가짜로 의심돼요",
    "unknown": "알 수 없어요",
}


@dataclass
class Evidence:
    parse: dict | None = None
    similarity: dict | None = None
    fetch: dict | None = None
    page: dict | None = None
    claim: dict | None = None
    candidates: list[tuple[Entity, str]] = field(default_factory=list)  # (엔티티, 출처)
    incomplete: str | None = None  # 에이전트 실패·시간 초과 등 조사 중단 이유(코드)
    internal_resolution: bool = False  # 공용 이름인데 내부망 주소로 해석됨(호스트가 확인, 접속하지 않음)
    url_trimmed: bool = False  # 문자 속 주소를 한글 앞에서 잘라 조사했다(사용자가 뜻한 주소와 다를 수 있음)


@dataclass
class Outcome:
    verdict: str
    entity: Entity | None
    entity_source: str  # exact|alias|embedding|agent|address|none
    signals: list[dict]
    purpose: str | None
    unknown_reason: str | None = None  # incomplete | no_data | fetch_failed | unverified | no_kb
    verification_gaps: list[str] = field(default_factory=list)  # 안전 판정에 모자란 증거(코드)


_FIELD_ORDER = ["password", "card_number", "card_cvc", "card_expiry", "bank_account", "resident_id", "otp",
                "phone", "name", "address", "other"]


def order_fields(fields) -> list[str]:
    """입력란 종류를 화면에 보여 줄 일정한 순서로 정렬한다."""
    return sorted(fields, key=lambda t: _FIELD_ORDER.index(t) if t in _FIELD_ORDER else 99)


def sig(type_: str, strength: str, **data) -> dict:
    return {"type": type_, "strength": strength, "data": data}


def _ok(d: dict | None) -> bool:
    return bool(d) and d.get("ok") is True


def verification_gaps(ev: Evidence, entity: Entity | None = None) -> list[str]:
    """`safe`에 필요한 증거 중 빠진 것. 비어 있어야만 안전이라고 말할 수 있다.

    공식·협력 도메인이라는 사실은 "주소가 맞다"까지만 보증한다. 페이지를 실제로 열어 분석했고
    이동 경로를 끝까지 따라갔으며 암호화 접속이었어야 한다.
    """
    gaps: list[str] = []
    if not _ok(ev.parse):
        gaps.append("parse")
    elif ev.parse.get("ambiguous"):
        gaps.append("ambiguous_url")  # 백슬래시 등으로 브라우저와 해석이 갈릴 수 있었던 주소
    if ev.url_trimmed:
        gaps.append("url_trimmed")  # 한글 앞에서 잘라 조사한 주소: 사용자가 뜻한 주소를 조사했는지 알 수 없다
    if not _ok(ev.similarity):
        gaps.append("similarity")
    fetch = ev.fetch if _ok(ev.fetch) else None
    if not fetch or fetch.get("skipped"):
        gaps.append("fetch")
        return gaps + (["page"] if not _ok(ev.page) else [])
    chain = fetch.get("chain") or []
    if not chain:
        gaps.append("fetch")
    elif any(h.get("blocked") or h.get("error") for h in chain):
        gaps.append("redirect_incomplete")
    else:
        status = chain[-1].get("status")
        if not (isinstance(status, int) and 200 <= status < 300):
            gaps.append("http_status")  # 404·5xx뿐 아니라 이동 횟수 한도에서 끊긴 3xx도 여기에 든다
    if any(h.get("refresh") for h in chain):
        gaps.append("client_redirect")  # HTTP Refresh 헤더가 다른 주소로 보낼 수 있었다(도착지는 조사하지 않았다)
    if chain and not all(str(h.get("url", "")).lower().startswith("https://") for h in chain):
        gaps.append("not_https")
    elif (fetch.get("tls") or {}).get("verified") is not True:
        gaps.append("tls_unverified")
    if fetch.get("body_truncated"):
        gaps.append("page_truncated")  # 본문이 잘려 뒤쪽 입력란·이동 코드를 보지 못했다
    if not _ok(ev.page):
        gaps.append("page")
    else:
        if ev.page.get("js_redirect_hint") and "client_redirect" not in gaps:
            gaps.append("client_redirect")  # 메타 새로고침·스크립트 이동을 감지했지만 도착지는 조사하지 않았다
        trusted = {(fetch.get("final_registrable_domain") or "")}
        if entity:
            trusted |= set(entity.official_domains) | set(entity.partner_domains)
        if any(d not in trusted for d in ev.page.get("external_active_domains") or []):
            gaps.append("external_active_content")  # 실행하지 않은 다른 도메인의 코드·문서를 끌어온다
    return gaps


def resolve_entity(ev: Evidence, kb: KB) -> tuple[Entity | None, str]:
    """사칭 대상 결정. 문자에 이름·별칭이 있으면 코드가 결정하고, 그 밖에는 에이전트가 후보 중에서 고른 값을 쓴다."""
    text_hits = [(e, s) for e, s in ev.candidates if s in ("exact", "alias")]
    claim_id = ev.claim.get("entity_id") if _ok(ev.claim) else None
    if len(text_hits) == 1:
        return text_hits[0]
    if len(text_hits) > 1:  # 모호: 에이전트가 고른 것이 그중 하나면 그것
        for e, s in text_hits:
            if e.id == claim_id:
                return e, s
        return text_hits[0]
    if claim_id and claim_id in kb.by_id:
        src = next((s for e, s in ev.candidates if e.id == claim_id), "agent")
        return kb.by_id[claim_id], src
    # 문자에 기관이 없고 에이전트도 못 골랐지만, 주소 자체가 특정 기관을 가리킨다
    sim = ev.similarity if _ok(ev.similarity) else None
    if sim:
        for key in ("subdomain_contains_official", "brand_in_domain"):
            if sim.get(key):
                eid = sim[key][0]["entity_id"]
                if eid in kb.by_id:
                    return kb.by_id[eid], "address"
        best = sim.get("closest_official")
        if best and best["similarity"] >= SIM_THRESHOLD and best["entity_id"] in kb.by_id \
                and best.get("pattern") not in ("same",):
            return kb.by_id[best["entity_id"]], "address"
    return None, "none"


def compute_signals(ev: Evidence, kb: KB, entity: Entity | None) -> list[dict]:
    signals: list[dict] = []
    parse = ev.parse if _ok(ev.parse) else None
    if parse is None:
        return signals
    known = kb.all_known_domains()
    registrable = parse["registrable_domain"]
    fetch = ev.fetch if _ok(ev.fetch) else None
    final = (fetch or {}).get("final_registrable_domain") or registrable
    is_official = bool(entity and final in entity.official_domains)
    is_partner = bool(entity and final in entity.partner_domains)
    domain_is_known = final in known or registrable in known

    if is_official:
        signals.append(sig("official_match", "positive", domain=final, entity_id=entity.id))
    if is_partner:
        signals.append(sig("partner_match", "positive", domain=final, entity_id=entity.id))

    # ── 주소 신호 (KB에 있는 공식·파트너 도메인 자체는 위장·유사 대상에서 제외) ──
    sim = ev.similarity if _ok(ev.similarity) else None
    if sim and not domain_is_known:
        for c in sim.get("subdomain_contains_official", [])[:1]:
            signals.append(sig("subdomain_disguise", "strong", label=c["label"], official_domain=c["domain"],
                               entity_id=c["entity_id"], match_kind=c["match_kind"]))
        best = sim.get("closest_official")
        if best and best["similarity"] >= SIM_THRESHOLD and best.get("pattern") != "same":
            signals.append(sig("lookalike_domain", "strong", official_domain=best["domain"],
                               entity_id=best["entity_id"], similarity=best["similarity"],
                               edit_distance=best["edit_distance"], pattern=best["pattern"]))
        if sim.get("confusable_chars") or sim.get("mixed_script") or sim.get("typosquat_pattern") == "confusable":
            signals.append(sig("confusable_chars", "strong", chars=sim.get("confusable_chars", []),
                               mixed_script=bool(sim.get("mixed_script"))))
        for b in sim.get("brand_in_domain", [])[:1]:
            signals.append(sig("brand_in_domain", "strong", brand=b["brand"], official_domain=b["domain"],
                               entity_id=b["entity_id"]))
    if parse.get("is_ip_host") or parse.get("has_userinfo"):
        signals.append(sig("ip_or_userinfo_host", "mid", is_ip=bool(parse.get("is_ip_host")),
                           has_userinfo=bool(parse.get("has_userinfo"))))
    if ev.internal_resolution:
        signals.append(sig("internal_address", "mid"))
    if entity and not is_official and not is_partner:
        signals.append(sig("domain_not_official", "mid", official_domain=entity.official_domains[0],
                           entity_id=entity.id))

    # ── 이동 경로 ──
    if fetch:
        chain = fetch.get("chain", [])
        dests = []
        for hop in chain[1:]:
            d = hop.get("registrable_domain")
            ok_dest = entity and (d in entity.official_domains or d in entity.partner_domains)
            if d and d != registrable and not ok_dest and d not in dests:
                dests.append(d)
        if dests:
            signals.append(sig("redirect_other_domain", "mid", domains=dests))
        blocked = [h.get("host") for h in chain if h.get("blocked")]
        if blocked:
            signals.append(sig("redirect_blocked", "info", hosts=blocked))
        first = chain[0] if chain else None
        if first and first.get("error") and not first.get("blocked"):
            signals.append(sig("fetch_failed", "info", error=first["error"]))
    elif ev.fetch is not None and not _ok(ev.fetch):
        signals.append(sig("fetch_failed", "info", error=(ev.fetch or {}).get("error", "")))

    # ── 페이지 ──
    page = ev.page if _ok(ev.page) else None
    if page:
        forms = page.get("forms", [])
        field_types = {t for f in forms for t in f.get("field_types", [])}
        cred = order_fields(field_types & CREDENTIAL_TYPES)
        if cred:
            signals.append(sig("credential_form", "mid", fields=cred))
        for f in forms:
            if not f.get("cross_domain"):
                continue
            # 전송 대상이 여럿이면(form의 action과 버튼의 formaction) 하나하나 따져야 한다. 협력·공식 도메인 한 곳이
            # 있다고 나머지 대상까지 면제되면 안 된다. 대상 목록이 없는 옛 결과는 대표 도메인 하나로 판단한다.
            dests = f.get("destinations") or [{"host": f.get("action_host"), "cross_domain": True,
                                               "registrable_domain": f.get("action_registrable_domain") or ""}]
            bad = next((d for d in dests if d.get("cross_domain") and not (
                entity and (d.get("registrable_domain") in entity.partner_domains
                            or d.get("registrable_domain") in entity.official_domains))), None)
            if bad is None:
                continue
            signals.append(sig("cross_domain_form", "mid", action_host=bad.get("host"),
                               action_domain=bad.get("registrable_domain") or ""))
            break
        purpose = (ev.claim or {}).get("purpose") if _ok(ev.claim) else None
        if not (is_official or is_partner):
            bad = order_fields(field_types & PURPOSE_FORBIDDEN.get(purpose or "other", set()))
            policy_text = None
            if entity:
                for rule in entity.policy_rules:
                    hit = order_fields(field_types & set(rule.get("forbids", [])))
                    if hit:
                        policy_text = rule.get("text")
                        bad = order_fields(set(bad) | set(hit))
                        break
            if bad:
                signals.append(sig("purpose_mismatch", "strong", fields=bad, purpose=purpose,
                                   policy=policy_text))
        if page.get("apk_links"):
            signals.append(sig("apk_download", "strong", links=page["apk_links"][:3]))

    if entity is None:
        signals.append(sig("entity_not_in_kb", "info"))
    return signals


def decide(ev: Evidence, kb: KB) -> Outcome:
    entity, source = resolve_entity(ev, kb)
    purpose = ev.claim.get("purpose") if _ok(ev.claim) else None

    # N6: 조사가 중간에 멈추면 발견한 것과 관계없이 unknown (거짓 safe·성급한 단정 금지)
    if ev.incomplete:
        sigs = compute_signals(ev, kb, entity)
        return Outcome("unknown", entity, source, sigs, purpose, "incomplete")
    # 규칙 1: 주소 분석 신호조차 없음
    if not _ok(ev.parse):
        return Outcome("unknown", entity, source, [], purpose, "no_data")

    signals = compute_signals(ev, kb, entity)
    types = {s["type"] for s in signals}
    strong = [s for s in signals if s["strength"] == "strong"]
    mid = [s for s in signals if s["strength"] == "mid"]

    best = (ev.similarity or {}).get("closest_official") if _ok(ev.similarity) else None
    identified = entity is not None or bool(best and best["similarity"] >= SIM_THRESHOLD)

    if strong and identified:  # 규칙 2
        return Outcome("suspected_impersonation", entity, source, signals, purpose)
    # 규칙 3. 확인 못 한 부분이 하나라도 있으면 안전이라고 말하지 않는다(거짓 safe 금지).
    gaps = verification_gaps(ev, entity)
    matched = bool({"official_match", "partner_match"} & types)
    if (matched and not gaps and not strong
            and not {"cross_domain_form", "redirect_other_domain", "fetch_failed",
                     "ip_or_userinfo_host", "internal_address"} & types):
        return Outcome("safe", entity, source, signals, purpose)
    if mid or strong:  # 규칙 4
        return Outcome("caution", entity, source, signals, purpose, verification_gaps=gaps)
    if "fetch_failed" in types:  # 규칙 5
        return Outcome("unknown", entity, source, signals, purpose, "fetch_failed", gaps)
    if matched:  # 규칙 5-2: 주소는 맞지만 페이지·경로·암호화 접속을 확인하지 못함
        return Outcome("unknown", entity, source, signals, purpose, "unverified", gaps)
    return Outcome("unknown", entity, source, signals, purpose, "no_kb", gaps)  # 규칙 6
