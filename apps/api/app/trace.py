"""상세 보기(F11)용 기록. 결과와 샌드박스 실행 기록에서 5개 탭의 데이터를 만든다."""
from __future__ import annotations

from datetime import datetime

from . import ko
from .kb import KB, Entity
from .presentation import _diff_chars, _field_types, _sig
from .urls import parse_url  # noqa: F401  (검사 라이브러리 경로를 sys.path에 등록하는 부작용이 필요)
from .verdict import CARD, PURPOSE_FORBIDDEN, Outcome
from checklib.similarity import norm_similarity  # noqa: E402

KB_NOTE = ("각 회사 공식 홈페이지에서 직접 확인한 주소만 모아 두었어요. "
           "목록에 없는 회사는 \"알 수 없어요\"로 알려드려요.")


def sim_label(score: float) -> str:
    return "많이 닮음" if score >= 0.8 else "조금 닮음" if score >= 0.6 else "거의 안 닮음"


def _hhmmss(iso: str | None) -> str:
    if not iso:
        return "--:--:--"
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%H:%M:%S")
    except ValueError:
        return "--:--:--"


def _sec_between(a: str | None, b: str | None) -> int | None:
    try:
        return int((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds())
    except (TypeError, ValueError):
        return None


# ── 1. 주소 ──────────────────────────────────────────────────────
def address_trace(parse: dict, similarity: dict | None, outcome: Outcome, kb: KB, url: str) -> dict:
    entity = outcome.entity
    N = entity.name if entity else None
    sim = similarity if similarity and similarity.get("ok") else {}
    types = {s["type"] for s in outcome.signals}
    subs = parse.get("subdomain_labels", [])
    sub_part = (".".join(subs) + ".") if subs else ""
    actual = parse["registrable_domain"]

    dis = _sig(outcome, "subdomain_disguise")
    look = _sig(outcome, "lookalike_domain")
    conf = _sig(outcome, "confusable_chars")
    tricks = [
        dict(key="subdomain_disguise", question="진짜 주소를 앞에 끼워 넣었나요?",
             hint=(f"{dis['data']['official_domain']}을 앞에 붙였어요" if dis else "예: 진짜 주소를 앞부분에 붙임"),
             hit=bool(dis), answer="예" if dis else "아니오",
             detail=f"{dis['data']['official_domain']}을 앞에 붙였어요" if dis else None),
        dict(key="lookalike", question="진짜 주소와 한두 글자만 다른가요?", hint="예: hanbit → hanblt",
             hit=bool(look), answer="예" if look else "아니오",
             detail=(f"{look['data']['official_domain']}와 {look['data']['pattern']} 차이" if look else None)),
        dict(key="confusable", question="헷갈리는 글자를 섞었나요?",
             hint="예: 영어 o 대신 숫자 0, 모양이 같은 외국 글자", hit=bool(conf), answer="예" if conf else "아니오",
             detail=(", ".join(c["char"] for c in conf["data"].get("chars", [])) or None) if conf else None),
        dict(key="ip_host", question="이름 없이 숫자로만 된 주소인가요?", hint="예: 123.45.67.89",
             hit=bool(parse.get("is_ip_host")), answer="예" if parse.get("is_ip_host") else "아니오", detail=None),
        dict(key="userinfo", question="주소 중간에 @ 표시가 있나요?", hint="@ 앞의 글자는 무시되고 뒤쪽으로 가요",
             hit=bool(parse.get("has_userinfo")), answer="예" if parse.get("has_userinfo") else "아니오", detail=None),
    ]

    rows = []
    for e in kb.entities:
        best = max(((norm_similarity(actual, d), norm_similarity(parse.get("domain_label", ""), d.split(".")[0]), d)
                    for d in e.official_domains), key=lambda x: max(x[0], x[1]))
        score = round(max(best[0], best[1]), 2)
        note = None
        if look and look["data"]["entity_id"] == e.id and look["data"].get("pattern") == "substitution":
            diff = _diff_chars(actual, best[2])
            note = f"한 글자{diff}만 달라요" if diff else "한 글자만 달라요"
        rows.append(dict(entity_id=e.id, name=e.name, domain=best[2], similarity=score, label=sim_label(score),
                         note=note))
    rows.sort(key=lambda r: -r["similarity"])

    if dis and N:
        sentence = (f"쉽게 말해, \"{N} 옆집\"이라고 문패를 단 다른 사람의 집과 같아요. "
                    f"문패에 {N}라고 써 있어도 집주인은 {actual}이에요.")
    elif look or conf:
        sentence = "철자를 살짝 바꿔서 진짜 주소처럼 보이게 만든 주소예요."
    elif "official_match" in types or "partner_match" in types:
        sentence = "주소의 주인이 진짜 주소 목록에 있는 곳과 같아요."
    else:
        sentence = "주소에서 눈에 띄는 속임수는 찾지 못했어요."
    return dict(
        url=url[:500], scheme=parse.get("scheme", "https"), host_unicode=parse.get("host_unicode", ""),
        host_ascii=parse.get("host_ascii", ""), subdomain_part=sub_part, registrable_domain=actual,
        path=parse.get("path", "/"), tricks=tricks, similarity=rows, summary_sentence=sentence, kb_note=KB_NOTE,
        dev={"parse_url.json": parse, "similarity.json": sim, "public_suffix": parse.get("suffix")},
    )


# ── 2. 넘어간 길 ────────────────────────────────────────────────────
def redirect_trace(fetch: dict | None) -> dict | None:
    if not fetch or not fetch.get("ok"):
        return None
    chain = fetch.get("chain", [])
    blocked = [h["host"] for h in chain if h.get("blocked")]
    return dict(
        chain=[{k: h.get(k) for k in ("url", "host", "registrable_domain", "status", "blocked", "error", "at")}
               for h in chain],
        redirect_count=fetch.get("redirect_count", max(0, len(chain) - 1)),
        blocked_count=len(blocked),
        last_seen_domain=fetch.get("final_registrable_domain"),
        blocked_hosts=blocked,
        dev={"fetch_chain.json": {k: v for k, v in fetch.items() if k != "chain"},
             "statuses": [h.get("status") for h in chain]},
    )


# ── 3. 페이지 ────────────────────────────────────────────────────
def page_trace(page: dict | None, outcome: Outcome, entity: Entity | None, actual: str | None) -> dict:
    if not page or not page.get("ok"):
        return dict(available=False, dev={"page.json": page or {}})
    purpose = outcome.purpose or "other"
    fields = _field_types(page)
    forbidden = PURPOSE_FORBIDDEN.get(purpose, set())
    rows = []
    for t in fields:
        if t in forbidden:
            rows.append(dict(type=t, label=ko.FIELD_LABELS.get(t, t), verdict="not_needed", verdict_label="필요 없음"))
        elif purpose == "payment" and t in CARD:
            rows.append(dict(type=t, label=ko.FIELD_LABELS.get(t, t), verdict="needed", verdict_label="필요함"))
        else:
            rows.append(dict(type=t, label=ko.FIELD_LABELS.get(t, t), verdict="ok", verdict_label="괜찮음"))

    brand_sentence = None
    if entity and any(entity.name.lower() in b.lower() or any(a.lower() in b.lower() for a in entity.aliases)
                      for b in page.get("brand_candidates", [])):
        if actual and actual in entity.official_domains:
            brand_sentence = "페이지가 밝힌 회사 이름과 주소의 주인이 같아요."
        else:
            brand_sentence = (f"페이지는 자기가 {entity.name}라고 말하지만, 앞에서 본 것처럼 "
                              f"주소의 주인은 {entity.name}가 아니에요.")

    cross = next((f for f in page.get("forms", []) if f.get("cross_domain")), None)
    xsig = _sig(outcome, "cross_domain_form")
    sends_to = cross["action_host"] if cross else None
    if xsig:
        sends_sentence = f"{sends_to} 이 페이지와 다른 사이트로 보내져요. 적는 순간 모르는 사람에게 가요."
    elif cross:
        sends_sentence = "다른 주소로 보내지지만 공식 협력 회사예요."
    elif page.get("forms"):
        sends_sentence = "적은 내용은 이 페이지 안에서만 처리돼요."
    else:
        sends_sentence = None

    return dict(
        available=True, title=page.get("title") or None, brand_candidates=page.get("brand_candidates", []),
        brand_sentence=brand_sentence, stated_purpose_label=ko.PURPOSE_LABELS.get(purpose),
        expected_fields_label=" · ".join(ko.FIELD_LABELS[t] for t in ko.PURPOSE_EXPECTED.get(purpose, [])) or None,
        field_rows=rows, sends_to=sends_to, sends_cross_domain=bool(xsig), sends_sentence=sends_sentence,
        apk_links=page.get("apk_links", []), js_redirect_hint=bool(page.get("js_redirect_hint")),
        trust_claims=page.get("trust_claims", []),
        dev={"page.json": page, "field_types": fields},
    )


# ── 4. AI 조사원 ───────────────────────────────────────────────────
def agent_trace(run: dict, claim: dict | None, entity: Entity | None, explain_check: str, total_ms: int | None,
                fetch_done: bool) -> dict:
    agent = run.get("agent", {})
    marks = agent.get("marks", {})
    started = agent.get("started_at")
    ok_claim = bool(claim and claim.get("ok"))

    def t(iso):
        s = _sec_between(started, iso)
        return max(0, s) if s is not None else 0

    steps = [dict(t_sec=0, title="문자를 읽었어요", detail="붙여 넣은 문자와, 비교할 회사 후보 목록을 받았어요.", lines=[])]
    if ok_claim:
        who = entity.name if entity else (claim.get("name") or "알 수 없음")
        steps.append(dict(t_sec=t(claim.get("at")), title="누가 보낸 척하는지 골랐어요",
                          detail=f"회사: {who} · 목적: {ko.PURPOSE_LABELS.get(claim.get('purpose'), '안내 문자')}"
                                 + (f"\n이유: {claim['reason']}" if claim.get("reason") else ""), lines=[]))
    if run.get("files", {}).get("parse_url") is not None or fetch_done:
        lines = ["✓ 주소 조각내기", "✓ 진짜 주소와 닮았는지 비교",
                 "✓ 안전 공간에서 열어보기" if fetch_done else "— 안전 공간에서 열어보기 (하지 못함)",
                 "✓ 페이지 속 적는 칸 살펴보기" if fetch_done else "— 페이지 속 적는 칸 살펴보기 (하지 못함)"]
        steps.append(dict(t_sec=t(marks.get("checks_started")), title="정해진 확인 도구를 차례로 돌렸어요",
                          detail=None, lines=lines))
    if explain_check != "skipped":
        steps.append(dict(t_sec=int((total_ms or 0) / 1000) - 1 if total_ms else 0,
                          title="결과를 쉬운 말로 설명했어요",
                          detail=("쓴 설명에 확인하지 않은 내용이 섞이지 않았는지 한 번 더 검사했어요. "
                                  + ("통과" if explain_check == "passed" else "통과하지 못해 정해 둔 문장으로 바꿨어요")),
                          lines=[]))
    unexpected = agent.get("unexpected_tools", [])
    dev_log = []
    for i, tool in enumerate(agent.get("tool_calls", [])):
        dev_log.append(f"00:{i + 1:02d}  {tool}")
    for line in agent.get("log", []):
        if line:
            dev_log.append(line)
    if agent.get("session") is not None:
        dev_log.append(f"session {agent.get('session')} · {agent.get('duration_ms')}ms")
    dur_ms = agent.get("duration_ms")
    return dict(
        steps=steps, unexpected_count=len(unexpected), unexpected_tools=unexpected, duration_ms=dur_ms,
        duration_sec=int(round(total_ms / 1000)) if total_ms else (int(round(dur_ms / 1000)) if dur_ms else None),
        model_reported=agent.get("model_reported"), explain_check=explain_check, dev_log=dev_log,
        dev={"tool_calls": agent.get("tool_calls", []), "raw_meta": agent.get("raw_meta"), "kind": agent.get("kind")},
    )


# ── 5. 안전 공간 ───────────────────────────────────────────────────
def sandbox_trace(run: dict, policy_name: str | None, residual: bool) -> dict:
    events_in = run.get("events", [])
    events = []
    opened_host, open_at, close_at = None, None, None
    blocked_hosts: list[str] = []
    for e in events_in:
        if e["kind"] == "open":
            opened_host, open_at = e.get("host"), e["at"]
            events.append(dict(at=_hhmmss(e["at"]), kind="open", title="문을 열었어요", detail="조사할 링크 한 곳만"))
        elif e["kind"] == "blocked":
            blocked_hosts.append(e.get("host") or "?")
            events.append(dict(at=_hhmmss(e["at"]), kind="blocked", title="다른 곳 들어가기를 막았어요",
                               detail=e.get("host")))
        elif e["kind"] == "close":
            close_at = e["at"]
            secs = _sec_between(open_at, close_at)
            events.append(dict(at=_hhmmss(e["at"]), kind="close", title="문을 다시 닫았어요",
                               detail=(f"열어 둔 시간 {secs}초 · " if secs is not None else "")
                               + ("닫는 데 실패했어요. 확인이 필요해요" if residual else "남은 열린 문 없음")))
    return dict(
        opened_host=opened_host, blocked_hosts=blocked_hosts, events=events,
        open_seconds=_sec_between(open_at, close_at), remaining_open=1 if residual else 0,
        dev={"policy": policy_name, "methods": ["GET"], "ports": [443, 80],
             "binaries": ["/usr/bin/python3", "/usr/bin/python3.13"]},
    )
