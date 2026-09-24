"""판정 결과 → 화면용 필드. 배지 문구·비교표·위험 목록·템플릿 설명은 모두 코드가 정한다.

모델이 쓴 설명(explain.py)은 explanation 필드에만 들어가고, 검증에 실패하면 여기의 템플릿이 쓰인다.
"""
from __future__ import annotations

import re

from . import ko
from .kb import Entity
from .verdict import CARD, CREDENTIAL_TYPES, PURPOSE_FORBIDDEN, VERDICT_LABELS, Outcome, order_fields

_NAME_OK = re.compile(r"^[0-9A-Za-z가-힣 ·&.\-]{1,20}$")

LEVEL_LABEL = {"high": "많이 위험", "mid": "조금 위험", "info": "참고"}
STRENGTH_TO_LEVEL = {"strong": "high", "mid": "mid", "info": "info"}


def sanitize_name(name: str | None) -> str | None:
    """에이전트가 문자에서 뽑은 기관 이름(KB에 없을 때만 쓴다). 화면에 그대로 나가므로 엄격히 거른다."""
    if not name:
        return None
    name = " ".join(name.split())
    return name if _NAME_OK.match(name) else None


def verdict_label(outcome: Outcome) -> str:
    if outcome.verdict == "safe" and any(s["type"] == "partner_match" for s in outcome.signals):
        return "안전해요 · 협력 회사"
    return VERDICT_LABELS[outcome.verdict]


def _sig(outcome: Outcome, type_: str) -> dict | None:
    return next((s for s in outcome.signals if s["type"] == type_), None)


def _display_name(entity: Entity | None, claim_name: str | None) -> str | None:
    return entity.name if entity else sanitize_name(claim_name)


def _field_types(page: dict | None) -> list[str]:
    if not page or not page.get("ok"):
        return []
    seen = {t for f in page.get("forms", []) for t in f.get("field_types", [])}
    return order_fields(seen)


# ── 주소 조각 ─────────────────────────────────────────────────────
def url_parts(parse: dict, url: str, entity: Entity | None, final_domain: str | None) -> dict:
    subs = parse.get("subdomain_labels", [])
    actual = final_domain or parse["registrable_domain"]
    return {
        "url": url[:500],
        "scheme": parse.get("scheme", "https"),
        "subdomain_part": (".".join(subs) + ".") if subs else "",
        "registrable_domain": parse["registrable_domain"],
        "path": parse.get("path", "/"),
        "official_domain": entity.official_domains[0] if entity else None,
        "matches_official": (actual in entity.official_domains) if entity else None,
        "matches_partner": bool(entity and actual in entity.partner_domains),
        "partner_domain": entity.partner_domains[0] if entity and actual in entity.partner_domains else None,
    }


# ── 위험한 점 한눈에 ────────────────────────────────────────────────
def build_risks(outcome: Outcome, page: dict | None) -> tuple[list[dict], str | None]:
    types = {s["type"] for s in outcome.signals}
    items: list[dict] = []

    def add(label: str, strength: str, level: str | None = None) -> None:
        lv = level or STRENGTH_TO_LEVEL[strength]
        items.append({"label": label, "level": lv, "level_label": LEVEL_LABEL[lv]})

    strong_addr = types & {"subdomain_disguise", "lookalike_domain", "confusable_chars", "brand_in_domain"}
    for s in outcome.signals:
        t, d = s["type"], s["data"]
        if t == "subdomain_disguise":
            add("진짜 주소를 앞에 붙임", "strong")
        elif t == "lookalike_domain":
            add("진짜 주소와 비슷하게 만든 주소", "strong")
        elif t == "confusable_chars":
            add("헷갈리는 글자를 섞음", "strong")
        elif t == "brand_in_domain":
            add("주소에 회사 이름을 끼워 넣음", "strong")
        elif t == "purpose_mismatch":
            f = d.get("fields", [])
            if set(f) & CARD:
                add("필요 없는 카드 정보 요구", "strong")
            elif "password" in f:
                add("필요 없는 비밀번호 요구", "strong")
            elif "otp" in f:
                add("필요 없는 인증번호 요구", "strong")
            else:
                add("필요 없는 정보 요구", "strong")
        elif t == "apk_download":
            add("모르는 앱 설치를 시킴", "strong")
        elif t == "credential_form":
            f = d.get("fields", [])
            if "purpose_mismatch" in types:
                add("개인 정보 적는 칸", "mid")
            elif "password" in f:
                add("비밀번호 적는 칸", "mid")
            elif set(f) & CARD:
                add("카드 정보 적는 칸", "mid")
            elif "otp" in f:
                add("인증번호 적는 칸", "mid")
            else:
                add("개인 정보 적는 칸", "mid")
        elif t == "cross_domain_form":
            add("다른 사이트로 보냄", "mid")
        elif t == "ip_or_userinfo_host":
            add("숫자·@가 섞인 이상한 주소", "mid")
        elif t == "domain_not_official" and not strong_addr:
            add("진짜 주소가 아님", "mid")
        elif t == "redirect_other_domain":
            add("다른 곳으로 넘어가려 함", "mid", level="info")
        elif t == "redirect_blocked" and "redirect_other_domain" not in types:
            add("다른 곳으로 넘어가려 함", "info")
        elif t == "entity_not_in_kb":
            add("목록에 없는 회사", "info")
        elif t == "fetch_failed":
            add("사이트가 열리지 않음", "info")
    order = {"high": 0, "mid": 1, "info": 2}
    items.sort(key=lambda i: order[i["level"]])
    note = None
    if "entity_not_in_kb" in types and outcome.verdict == "caution":
        note = "회사를 알 수 없어서 \"가짜\"라고 단정하지 않았어요."
    return items, note


# ── 문자가 한 말 vs 실제 ───────────────────────────────────────────
def build_comparison(outcome: Outcome, page: dict | None, fetch: dict | None, parse: dict,
                     claim_name: str | None, message_given: bool) -> list[dict]:
    rows: list[dict] = []
    entity = outcome.entity
    name = _display_name(entity, claim_name)
    purpose = outcome.purpose
    types = {s["type"] for s in outcome.signals}
    fields = _field_types(page)
    page_ok = bool(page and page.get("ok"))

    # 주소
    if entity:
        said = f"{name} 결제 페이지예요" if purpose == "payment" else f"{name} 사이트예요"
        if "official_match" in types:
            rows.append(dict(key="address", label="주소", said=said, found=f"{name} 사이트가 맞아요",
                             status="ok", status_label="같아요"))
        elif "partner_match" in types:
            rows.append(dict(key="address", label="주소", said=said,
                             found=f"{ko.possessive(name)} 공식 결제 회사예요" if purpose == "payment"
                             else f"{ko.possessive(name)} 공식 협력 회사예요",
                             status="ok", status_label="맞아요"))
        else:
            rows.append(dict(key="address", label="주소", said=said, found="다른 사람의 사이트예요",
                             status="bad", status_label="달라요"))
    else:
        rows.append(dict(key="address", label="주소", said=f"{name or '문자에 나온 회사'} 사이트예요",
                         found="진짜 주소를 몰라 비교 못 함", status="unknown", status_label="모름"))

    # 적는 칸
    said_fields = ko.PURPOSE_LABELS.get(purpose or "other", "안내 문자")
    mism = _sig(outcome, "purpose_mismatch")
    if not page_ok:
        rows.append(dict(key="fields", label="적는 칸", said=said_fields, found="페이지를 보지 못했어요",
                         status="unknown", status_label="모름"))
    elif not fields:
        rows.append(dict(key="fields", label="적는 칸", said=said_fields, found="적는 칸 없음 (조회만)",
                         status="ok", status_label="맞아요"))
    elif mism:
        bad = mism["data"]["fields"]
        rows.append(dict(key="fields", label="적는 칸", said=said_fields,
                         found=f"{ko.obj(ko.field_list(bad, short=True))} 적으라고 해요",
                         status="bad", status_label="달라요"))
    else:
        cred = set(fields) & CREDENTIAL_TYPES
        allowed_only = not (set(fields) & PURPOSE_FORBIDDEN.get(purpose or "other", set()))
        if purpose == "payment" and (set(fields) & CARD):
            lab = "결제에 필요"
            st = "ok"
        elif cred and (purpose in (None, "other") or "domain_not_official" in types):
            lab, st = "조심", "warn"
        elif cred and allowed_only and ("official_match" in types or "partner_match" in types):
            lab, st = "괜찮아요", "ok"
        elif cred:
            lab, st = "조심", "warn"
        else:
            lab, st = "괜찮아요", "ok"
        rows.append(dict(key="fields", label="적는 칸", said=said_fields, found=ko.field_list(fields, short=True),
                         status=st, status_label=lab))

    # 회사 약속 / 적은 내용 / 넘어간 곳
    forms = page.get("forms", []) if page_ok else []
    if mism and mism["data"].get("policy"):
        rows.append(dict(key="promise", label="회사 약속", said=mism["data"]["policy"],
                         found=f"{_particle(mism['data']['fields'], '을', '를')} 물어요",
                         status="bad", status_label="약속과 달라요"))
    elif forms:
        xf = _sig(outcome, "cross_domain_form")
        if xf:
            rows.append(dict(key="destination", label="적은 내용", said="—",
                             found=f"다른 사이트({xf['data'].get('action_host')})로 보내져요",
                             status="warn", status_label="조심"))
        else:
            partner = "partner_match" in types
            rows.append(dict(key="destination", label="적은 내용", said="—",
                             found="같은 결제 회사로 보내져요" if partner and purpose == "payment"
                             else "이 페이지 안에서만 처리돼요" if not partner else "같은 협력 회사로 보내져요",
                             status="ok", status_label="괜찮아요"))
    else:
        red = _sig(outcome, "redirect_other_domain")
        blocked = _sig(outcome, "redirect_blocked")
        if red or blocked:
            dest = (red or {}).get("data", {}).get("domains", []) or (blocked or {}).get("data", {}).get("hosts", [])
            rows.append(dict(key="redirect", label="넘어간 곳", said="—",
                             found=f"다른 곳({dest[0] if dest else '?'})으로 넘어가려 했어요",
                             status="warn", status_label="조심"))
        else:
            rows.append(dict(key="redirect", label="넘어간 곳", said="—", found="다른 곳으로 넘어가지 않았어요",
                             status="ok", status_label="괜찮아요"))

    # 보낸 번호 (문자를 넣은 경우에만)
    if message_given:
        rows.append(dict(key="sender", label="보낸 번호", said=f"{ko.subj(name or '문자 속 회사')} 보냈어요",
                         found="확인할 방법이 없어요", status="unknown", status_label="모름"))
    return rows


def _particle(fields: list[str], with_batchim: str, without: str) -> str:
    """입력란 이름 나열 + 마지막 말에 맞는 조사. 예: '카드 번호, 카드 뒷면 숫자를'"""
    text = ko.field_list(fields, short=True)
    return text + (with_batchim if ko._has_batchim(text) else without)


# ── 템플릿 설명 ─────────────────────────────────────────────────────
def _evidence_sentences(outcome: Outcome, entity_name: str | None) -> list[str]:
    N = entity_name or "이 회사"
    out: list[str] = []
    addr_trick = any(x["type"] in ("subdomain_disguise", "lookalike_domain", "confusable_chars", "brand_in_domain")
                     for x in outcome.signals)
    for s in outcome.signals:
        t, d = s["type"], s["data"]
        if t == "subdomain_disguise":
            out.append(f"주소 앞에 {N} 주소를 붙여서 진짜처럼 보이게 했어요.")
        elif t == "lookalike_domain":
            out.append(f"진짜 주소({d['official_domain']})와 철자를 비슷하게 만들어서 진짜처럼 보이게 했어요.")
        elif t == "confusable_chars":
            out.append("헷갈리는 글자를 섞어서 진짜 주소처럼 보이게 했어요.")
        elif t == "brand_in_domain":
            out.append(f"주소 안에 {N} 이름을 끼워 넣어서 진짜처럼 보이게 했어요.")
        elif t == "purpose_mismatch":
            ctx = ko.PURPOSE_CONTEXT.get(d.get("purpose") or "other", "이 안내")
            out.append(f"{ctx}에 {_particle(d['fields'], '은', '는')} 필요 없어요.")
            if d.get("policy"):
                out.append(d["policy"] + ".")
        elif t == "apk_download":
            out.append("모르는 앱을 깔라고 해요.")
        elif t == "cross_domain_form":
            out.append(f"적은 내용이 이 페이지와 다른 사이트({d.get('action_host')})로 가요.")
        elif t == "redirect_other_domain" and not addr_trick and not any(
                x["type"] == "cross_domain_form" for x in outcome.signals):
            out.append("다른 사이트로 넘어가려 했어요.")
        elif t == "ip_or_userinfo_host":
            out.append("이름 없는 숫자 주소이거나 @ 표시가 섞인 주소예요.")
        elif t == "domain_not_official" and not addr_trick:
            out.append(f"이 주소는 {N} 진짜 주소 목록에 없어요.")
    return out


def _fact_sentences(actual: str | None, page: dict | None, outcome: Outcome) -> list[str]:
    facts: list[str] = []
    if actual:
        facts.append(f"진짜 사이트 이름은 {actual}이에요.")
    fields = _field_types(page)
    sens = [t for t in fields if t in CREDENTIAL_TYPES]
    if sens:
        facts.append(f"{_particle(sens, '을', '를')} 적는 칸이 있어요.")
    if _sig(outcome, "redirect_blocked"):
        facts.append("다른 사이트로 넘어가려 해서 막았어요.")
    return facts


def build_explanation(outcome: Outcome, page: dict | None, actual: str | None, claim_name: str | None,
                      message_given: bool, incomplete_reason: str | None = None) -> dict:
    entity = outcome.entity
    N = _display_name(entity, claim_name)
    types = {s["type"] for s in outcome.signals}
    fields = _field_types(page)
    app = (entity.official_app if entity and entity.official_app else (f"{N} 앱" if N else "공식 앱"))
    unverified = (["문자를 보낸 전화번호가 진짜인지"] if message_given else []) + ["페이지가 나중에 스스로 바뀌는 내용"]
    facts = _fact_sentences(actual, page, outcome)
    evidence = _evidence_sentences(outcome, N)

    v = outcome.verdict
    if v == "suspected_impersonation":
        who = N or "유명한 회사"
        mism = _sig(outcome, "purpose_mismatch")
        head = f"{ko.obj(who)} 흉내 낸 가짜 사이트 같아요."
        detail = f"{ko.possessive(N)} 진짜 주소가 아니고" if entity else "진짜 회사 주소가 아니고"
        look = _sig(outcome, "lookalike_domain")
        if look and not _sig(outcome, "subdomain_disguise"):
            detail = f"진짜 주소({look['data']['official_domain']})와 철자만 살짝 다른 주소이고"
        if mism:
            ctx = ko.PURPOSE_CONTEXT.get(mism["data"].get("purpose") or "other", "이 안내")
            detail += f", {ctx}에는 필요 없는 {_particle(mism['data']['fields'], '을', '를')} 적으라고 해요."
        else:
            detail += ", 진짜처럼 보이려고 주소에 속임수를 썼어요."
        cards = mism and set(mism["data"]["fields"]) & CARD
        bullets = ["문자 속 링크는 누르지 마세요."]
        if cards:
            bullets.append("이미 카드 번호를 적었다면 카드 회사에 바로 전화하세요.")
        elif fields and set(fields) & {"password", "otp", "bank_account"}:
            bullets.append("이미 비밀번호를 적었다면 바로 바꾸고, 은행이나 회사에 알리세요.")
        bullets.append("문자는 지워도 괜찮아요.")
        action = (f"{who} 공식 앱을 직접 열어서 배송 상태를 확인하세요."
                  if entity and entity.category == "delivery" else f"{who} 공식 앱이나 대표번호로 직접 확인하세요.")
        return dict(headline=head, warning="링크를 누르지 마세요.", detail=detail, confirmed_facts=facts,
                    suspicion_evidence=evidence, unverified=unverified, recommended_action=action,
                    action_bullets=bullets, source="template")

    if v == "safe":
        partner = "partner_match" in types
        if partner:
            head = f"{ko.subj(N)} 함께 쓰는 결제 사이트예요."
            detail = (f"주소는 {ko.with_(N)} 다르지만, {ko.subj(N)} 공식으로 쓰는 결제 회사예요. "
                      "주소가 다르다는 것만으로 가짜는 아니에요.")
            facts = [f"진짜 사이트 이름은 {actual}이에요.", f"{ko.subj(N)} 밝힌 협력 회사 목록에 있는 주소예요."]
            if outcome.purpose == "payment" and fields and not (set(fields) - CARD - {"name", "phone"}):
                facts.append("결제에 필요한 것만 적으라고 해요.")
            unverified = (["문자를 보낸 전화번호가 진짜인지"] if message_given else []) + ["결제 금액이 맞는지"]
            return dict(headline=head, warning=None, detail=detail, confirmed_facts=facts,
                        suspicion_evidence=[], unverified=unverified,
                        recommended_action="결제하기 전에 금액과 회사 이름을 한 번 더 보세요.",
                        action_bullets=["받을 택배가 없다면 결제하지 마세요.", f"{app}에서 결제해도 돼요."],
                        source="template")
        head = f"{ko.possessive(N)} 진짜 사이트예요."
        detail = (f"주소의 주인이 {N} 진짜 주소와 같고, 이상한 것을 적으라고 하지 않아요."
                  if not (set(fields) & CREDENTIAL_TYPES)
                  else f"주소의 주인이 {N} 진짜 주소와 같아요. 문자 내용과 맞지 않는 것을 적으라고 하지 않아요.")
        facts = [f"진짜 사이트 이름은 {actual}이에요.", f"{N} 진짜 주소 목록에 있는 주소예요."]
        facts.append("카드 번호나 비밀번호를 묻지 않아요." if not (set(fields) & CREDENTIAL_TYPES)
                     else "적으라고 하는 정보가 문자 내용과 맞아요.")
        return dict(headline=head, warning=None, detail=detail, confirmed_facts=facts, suspicion_evidence=[],
                    unverified=unverified, recommended_action="링크를 열어도 괜찮아요.",
                    action_bullets=["그래도 카드 번호나 비밀번호를 적으라고 하면 멈추고 다시 확인하세요.",
                                    f"불안하면 {app}에서 직접 확인해도 돼요."], source="template")

    if v == "caution":
        if entity:
            head = f"{ko.possessive(N)} 진짜 주소가 아니라서 조심해야 해요."
            detail = f"이 주소는 {N} 진짜 주소 목록에 없어요."
        else:
            head = "어느 회사인지 알 수 없지만, 위험한 점이 있어요."
            detail = f"\"{N}\"의 진짜 주소는 저희 목록에 없어요." if N else "문자가 말한 회사의 진짜 주소는 저희 목록에 없어요."
        sens = [t for t in fields if t in CREDENTIAL_TYPES]
        if sens and "cross_domain_form" in types:
            detail += f" 그런데 {_particle(sens[:1], '을', '를')} 적게 하고, 그 내용을 다른 사이트로 보내요."
        elif sens:
            detail += f" 그런데 {_particle(sens[:1], '을', '를')} 적는 칸이 있어요."
        unv = ([f"{N}의 진짜 주소"] if (not entity and N) else []) \
            + (["문자를 보낸 전화번호가 진짜인지"] if message_given else [])
        bullets = ["문자 속 전화번호로 전화하지 마세요."]
        if set(fields) & {"password", "otp"}:
            bullets.append("비밀번호, 인증번호는 적지 마세요.")
        return dict(headline=head, warning=None, detail=detail,
                    confirmed_facts=facts, suspicion_evidence=evidence, unverified=unv,
                    recommended_action=f"링크 대신, {app}이나 대표 전화번호로 직접 물어보세요.",
                    action_bullets=bullets, source="template")

    # unknown
    reason = outcome.unknown_reason
    if reason == "incomplete":
        head = "지금은 확인을 끝내지 못했어요."
        detail = ((incomplete_reason or "조사가 중간에 멈췄어요") + ". 안전하다는 뜻이 아니니 아직 링크를 누르지 마세요.")
    elif reason == "fetch_failed":
        head = "사이트가 열리지 않아서 확인하지 못했어요."
        detail = "페이지 안을 보지 못했어요. 안전하다는 뜻이 아니니 링크를 누르지 마세요."
    else:
        head = "공식 여부를 확인할 자료가 없어요."
        detail = "비교할 진짜 주소가 없고, 눈에 띄는 위험한 점도 찾지 못했어요. 안전하다는 뜻은 아니에요."
    return dict(headline=head, warning=None, detail=detail, confirmed_facts=facts, suspicion_evidence=[],
                unverified=unverified if reason != "incomplete" else (["페이지 속 내용"] + unverified[:1]),
                recommended_action=("1~2분 뒤에 다시 확인해 보세요." if reason in ("incomplete", "fetch_failed")
                                    else "회사 앱이나 대표 전화번호로 직접 확인해 보세요."),
                action_bullets=["그 전까지 링크를 누르지 마세요.",
                                f"급하다면 {app}에서 직접 확인하세요." if N else "급하다면 회사 대표번호로 직접 확인하세요."],
                source="template")


def partial_findings(outcome: Outcome, entity_name: str | None, actual: str | None,
                     similarity: dict | None) -> list[str]:
    """조사가 멈추기 전에 발견한 것(쉬운 말)."""
    out: list[str] = []
    N = entity_name or "이 회사"
    for s in outcome.signals:
        d = s["data"]
        if s["type"] == "lookalike_domain":
            diff = ""
            if d.get("pattern") == "substitution":
                diff = _diff_chars(actual or "", d["official_domain"])
            out.append(f"진짜 주소 {d['official_domain']}와 {'한 글자' + diff + '만 다른 ' if diff else '아주 비슷한 '}{actual}이에요.")
        elif s["type"] == "subdomain_disguise":
            out.append(f"주소 앞에 {N} 주소를 붙여 진짜처럼 보이게 했어요.")
        elif s["type"] == "confusable_chars":
            out.append("헷갈리는 글자가 섞인 주소예요.")
        elif s["type"] == "brand_in_domain":
            out.append(f"주소 안에 {N} 이름이 끼어 있어요.")
    return out


def _diff_chars(a: str, b: str) -> str:
    """길이가 같은 두 도메인에서 다른 한 글자를 '(i → l)' 형태로. 진짜 → 가짜 순서."""
    if len(a) != len(b):
        return ""
    diffs = [(y, x) for x, y in zip(a, b) if x != y]
    return f"({diffs[0][0]} → {diffs[0][1]})" if len(diffs) == 1 else ""
