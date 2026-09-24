"""설명 생성 입력 만들기와 모델 출력 검증(F8, 상세 명세 5-2).

원칙: 모델이 쓴 설명은 신호 목록에 없는 사실을 새로 주장하면 버리고 템플릿 설명으로 바꾼다.
URL 원문과 페이지 문구는 모델에 보내지 않는다(프롬프트 주입 방어).
"""
from __future__ import annotations

import json
import re

from .kb import KB
from .verdict import Outcome

_DOMAIN_RE = re.compile(r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+", re.I)
_NUM_RE = re.compile(r"\d+")
_ALLOWED_NUMBERS = {"1", "2", "112", "118"}
_LIST_FIELDS = ["confirmed_facts", "suspicion_evidence", "unverified", "action_bullets"]
_STR_FIELDS = ["headline", "warning", "detail", "recommended_action"]
MAX_SENTENCE = 80


def build_payload(outcome: Outcome, actual: str | None, entity_name: str | None,
                  official_domain: str | None, unverified: list[str]) -> dict:
    """모델에 넘길 구조화 입력. 자유 문구는 없다."""
    signals = []
    for s in outcome.signals:
        data = {k: v for k, v in s["data"].items()
                if isinstance(v, (str, int, float, bool)) or (isinstance(v, list) and all(isinstance(x, str) for x in v))}
        signals.append({"type": s["type"], "strength": s["strength"], "data": data})
    return {
        "verdict": outcome.verdict,
        "actual_domain": actual,
        "entity": entity_name,
        "official_domain": official_domain,
        "purpose": outcome.purpose,
        "signals": signals,
        "unverified": unverified,
    }


def _flatten(exp: dict) -> list[str]:
    out: list[str] = []
    for k in _STR_FIELDS:
        v = exp.get(k)
        if isinstance(v, str):
            out.append(v)
    for k in _LIST_FIELDS:
        v = exp.get(k)
        if isinstance(v, list):
            out.extend(x for x in v if isinstance(x, str))
    return out


def validate(output: dict | None, payload: dict, kb: KB, template: dict) -> dict | None:
    """통과하면 정리된 explanation(dict, source='agent'), 실패하면 None."""
    if not isinstance(output, dict):
        return None
    if not isinstance(output.get("headline"), str) or not isinstance(output.get("recommended_action"), str):
        return None
    for k in _LIST_FIELDS:
        v = output.get(k, [])
        if not isinstance(v, list) or len(v) > 6 or any(not isinstance(x, str) for x in v):
            return None
    for k in ("warning", "detail"):
        if output.get(k) is not None and not isinstance(output.get(k), str):
            return None

    texts = _flatten(output)
    if not texts or any(len(t) > MAX_SENTENCE * 2 for t in texts):
        return None
    joined = "\n".join(texts)

    # 1) 도메인 형태 토큰은 모두 입력 안에 있어야 한다
    payload_text = json.dumps(payload, ensure_ascii=False).lower()
    allowed_domains = {d.lower() for d in _DOMAIN_RE.findall(payload_text)}
    for d in _DOMAIN_RE.findall(joined):
        if d.lower().rstrip(".") not in allowed_domains:
            return None

    # 2) 숫자는 입력에 있거나 안내 번호여야 한다
    allowed_nums = set(_NUM_RE.findall(payload_text)) | _ALLOWED_NUMBERS
    if any(n not in allowed_nums for n in _NUM_RE.findall(joined)):
        return None

    # 3) 입력에 없는 다른 기관 이름을 쓰면 안 된다
    entity = payload.get("entity") or ""
    for e in kb.entities:
        if e.name != entity and e.name in joined:
            return None

    # 4) 판정과 어긋나는 문구 금지
    v = payload["verdict"]
    reassure = re.search(r"안전해요|안전합니다|진짜 사이트예요|믿어도", joined)
    negated = "안전하다는 뜻이 아니" in joined or "안전하지 않" in joined
    if v == "safe" and re.search(r"가짜로 의심|사칭이 의심|흉내 낸 가짜|링크를 누르지 마세요", joined):
        return None
    if v in ("suspected_impersonation", "caution", "unknown") and reassure and not negated:
        return None
    if v == "unknown" and not negated:
        return None

    cleaned = {
        "headline": output["headline"].strip(),
        "warning": (output.get("warning") or None),
        "detail": (output.get("detail") or None),
        "confirmed_facts": list(output.get("confirmed_facts", [])),
        "suspicion_evidence": list(output.get("suspicion_evidence", [])),
        # 확인하지 못한 것은 코드가 정한다(빠뜨리거나 바꾸지 못하게)
        "unverified": template["unverified"],
        "recommended_action": output["recommended_action"].strip(),
        "action_bullets": list(output.get("action_bullets", [])),
        "source": "agent",
    }
    return cleaned
