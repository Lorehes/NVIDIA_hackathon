"""설명 생성 입력 만들기와 모델 출력 검증(F8, 상세 명세 5-2).

원칙: 모델이 쓴 설명은 신호 목록에 없는 사실을 새로 주장하면 버리고 템플릿 설명으로 바꾼다.
URL 원문과 페이지 문구는 모델에 보내지 않는다(프롬프트 주입 방어).

제목·경고·행동 권고·확인하지 못한 것은 코드의 고정 문구(템플릿)만 쓴다. 모델은 `detail`·`confirmed_facts`·
`suspicion_evidence`에만 관여하는데, 그 문장은 **코드가 만든 검증된 문장에 나온 어절과 그 어절의 인접한 쌍**으로만
이뤄져야 통과한다(금지어 목록으로는 한국어 표현의 변형을 다 막을 수 없기 때문이다). 새 단어나 새 어절 결합으로
행동 지시·안심 문구를 만들어 낼 수 없다. 금지 표현 검사는 이중 방어로 남긴다.
"""
from __future__ import annotations

import json
import re
import unicodedata

from .kb import KB
from .verdict import Outcome

_DOMAIN_RE = re.compile(r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+", re.I)
_NUM_RE = re.compile(r"\d+")
_ALLOWED_NUMBERS = {"1", "2", "112", "118"}
_LIST_FIELDS = ["confirmed_facts", "suspicion_evidence", "unverified", "action_bullets"]
_STR_FIELDS = ["headline", "warning", "detail", "recommended_action"]
MAX_SENTENCE = 80
# 행동 지시는 코드가 정한다. 모델 문장에 지시형·권유형 표현이 있거나 안심시키는 말이 있으면 통째로 버린다.
# 아래 정규식은 공백을 모두 지운 문장에 적용한다(띄어쓰기로 나눠 쓰는 우회를 막기 위해).
_DIRECTIVE_RE = re.compile(r"세요|십시오|주세요|시오|라고하|하자|면돼|면됩니다|바랍니다|해주|하시|드립니다")
_ACTION_RE = re.compile(r"링크를(?:열|누르|눌|클릭)|(?:사이트|페이지)(?:에|로)?(?:접속|들어가|방문)|앱을?(?:설치|다운)")
_FALSE_REASSURE_RE = re.compile(r"문제없|괜찮|걱정(?:안|하지|마)|열어도|눌러도|입력해도|접속해도")
# 판정이 안전이 아닐 때 모델 문장에 나오면 안 되는 안심 표현. 부정문("안전하지 않아요")은 먼저 걷어낸다.
_NEGATION_RE = re.compile(r"안전하지않|안전하다는뜻이아니|안전하다고(?:볼|말할|할)수없|믿을수없|정상이아니|문제가없다고(?:볼|말할)수없")
_STRICT_REASSURE_RE = re.compile(r"안전해요|안전합니다|안전한사이트|진짜사이트예요|진짜사이트입니다|믿어도")
_SAFE_WORDS_OK_RE =re.compile(r"안전(?:한)?(?:공간|곳|환경)")
_REASSURE_WORD_RE = re.compile(r"안전|정상|믿을|믿어|신뢰|오해|(?:진짜|공식)(?:사이트|페이지)(?:예요|에요|이에요|입니다|다)")


def build_payload(outcome: Outcome, actual: str | None, entity_name: str | None,
                  official_domain: str | None, unverified: list[str], vetted: list[str] | None = None) -> dict:
    """모델에 넘길 구조화 입력. 자유 문구는 없고, `vetted_sentences`는 코드가 만든 검증된 문장이다."""
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
        "vetted_sentences": vetted or [],
    }


def vetted_sentences(template: dict) -> list[str]:
    """코드가 만든 설명(템플릿)의 모든 문장. 모델은 이 문장의 표현만 재사용할 수 있다."""
    out: list[str] = []
    for k in _STR_FIELDS:
        v = template.get(k)
        if isinstance(v, str) and v:
            out.append(v)
    for k in _LIST_FIELDS:
        v = template.get(k)
        if isinstance(v, list):
            out.extend(x for x in v if isinstance(x, str) and x)
    return out


_EDGE_PUNCT = ".,!?…~\"'“”‘’()[]{}<>:;"


_MASK = "◇"  # 동적 값(회사 이름·도메인 등)을 대신하는 자리표시자
_DYNAMIC_KEYS = ("action_host", "action_domain", "official_domain", "domain", "label", "brand", "domains", "hosts")


def _dynamic_values(payload: dict) -> list[str]:
    """템플릿에 끼워 넣어지는 값 중 문자·페이지·에이전트에서 온 것. 이 값의 글자는 모델 문장의 근거 어휘가 될 수 없다."""
    vals = [payload.get("entity"), payload.get("actual_domain"), payload.get("official_domain")]
    for s in payload.get("signals", []):
        for k in _DYNAMIC_KEYS:
            v = (s.get("data") or {}).get(k)
            vals.extend(v if isinstance(v, list) else [v])
    out = {_clean(v).strip() for v in vals if isinstance(v, str)}
    return sorted((v for v in out if len(v) >= 2), key=len, reverse=True)


def _mask(text: str, values: list[str]) -> str:
    text = _clean(text)
    for v in values:
        text = re.sub(re.escape(v), _MASK, text, flags=re.I)
    return text


def _tokens(text: str) -> list[str]:
    return [t for t in (w.strip(_EDGE_PUNCT) for w in text.split()) if t]


def _closure(template: dict, values: list[str]) -> tuple[set[str], set[tuple[str, str]]]:
    """코드가 만든 문장에서 쓸 수 있는 어절과 인접 어절 쌍. 동적 값은 자리표시자로 바꾼 뒤에 센다.

    회사 이름이 `비밀번호 입력을 권장합니다`라도 그 글자가 허용 어휘가 되지 않는다."""
    vocab: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    for sentence in vetted_sentences(template):
        toks = _tokens(_mask(sentence, values))
        vocab.update(toks)
        pairs.update(zip(toks, toks[1:]))
    return vocab, pairs


def _within_closure(text: str, vocab: set[str], pairs: set[tuple[str, str]], values: list[str]) -> bool:
    toks = _tokens(_mask(text, values))
    if not toks:
        return True
    if all(set(t) <= {_MASK} for t in toks):  # 자리표시자뿐인 문장: 동적 값만 그대로 문장 노릇을 하게 둘 수 없다
        return False
    if len(toks) == 1:
        return toks[0] in vocab
    return all(p in pairs for p in zip(toks, toks[1:]))


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


def _clean(text: str) -> str:
    """NFKC로 전각·호환 문자를 정규화하고 보이지 않는 서식·제어 문자(제로폭 공백 등)를 지운다."""
    text = unicodedata.normalize("NFKC", text)
    # 서식·제어·사설·결합 문자(제로폭 공백, 결합 문자 U+034F 등)는 단어를 눈에 안 띄게 쪼개는 데 쓰이므로 지운다
    return "".join(ch for ch in text if unicodedata.category(ch) not in ("Cf", "Cc", "Co", "Cs", "Mn", "Me"))


def _clean_output(output: dict) -> dict:
    out = dict(output)
    for k in _STR_FIELDS:
        if isinstance(out.get(k), str):
            out[k] = _clean(out[k])
    for k in _LIST_FIELDS:
        if isinstance(out.get(k), list):
            out[k] = [_clean(x) if isinstance(x, str) else x for x in out[k]]
    return out


def validate(output: dict | None, payload: dict, kb: KB, template: dict) -> dict | None:
    """통과하면 정리된 explanation(dict, source='agent'), 실패하면 None."""
    if not isinstance(output, dict):
        return None
    output = _clean_output(output)
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

    # 결과에 실제로 쓰이는 모델 문장(설명·사실·의심 근거). 제목·경고·행동 권고는 코드가 정하므로 아래 검사에서 제외한다.
    free = ([output["detail"]] if isinstance(output.get("detail"), str) else []) \
        + list(output.get("confirmed_facts", [])) + list(output.get("suspicion_evidence", []))
    free_compact = re.sub(r"\s+", "", "|".join(free))  # 문장 경계를 넘어 붙어서 일치하는 것을 막으려고 | 로 잇는다
    compact = re.sub(r"\s+", "", joined)

    # 4) 판정과 어긋나는 문구 금지. 부정문("안전하지 않아요")을 걷어낸 뒤에도 안심 표현이 남으면 버린다.
    v = payload["verdict"]
    if v == "safe" and re.search(r"가짜로의심|사칭이의심|흉내낸가짜|링크를누르지마세요", compact):
        return None
    if v != "safe":
        if _STRICT_REASSURE_RE.search(_NEGATION_RE.sub("", compact)):  # 어느 필드에 쓰든 명시적 안심 문구는 거부한다
            return None
        rest = _SAFE_WORDS_OK_RE.sub("", _NEGATION_RE.sub("", free_compact))
        if _REASSURE_WORD_RE.search(rest) or _FALSE_REASSURE_RE.search(rest):
            return None
    if v == "unknown" and not _NEGATION_RE.search(compact):
        return None

    # 5) 모델이 채울 수 있는 자리에는 행동 지시·권유가 없어야 한다
    if _DIRECTIVE_RE.search(free_compact) or _ACTION_RE.search(free_compact):
        return None

    # 5-2) 모델 문장은 코드가 만든 검증된 문장의 어절과 인접 어절 쌍으로만 이뤄져야 한다(핵심 방어선)
    if any(_MASK in t for t in free):  # 자리표시자를 직접 써서 검사를 속이지 못하게 한다
        return None
    values = _dynamic_values(payload)
    vocab, pairs = _closure(template, values)
    if not all(_within_closure(t, vocab, pairs, values) for t in free):
        return None

    # 6) 의심 근거는 판정에 실제로 쓰인 위험 신호 수를 넘지 못한다(없는 위험을 지어내지 못하게)
    risky = sum(1 for s in payload.get("signals", []) if s.get("strength") in ("strong", "mid"))
    if len(output.get("suspicion_evidence", [])) > risky:
        return None

    # 제목·경고·행동 권고·확인하지 못한 것은 코드가 정한다(모델 출력은 쓰지 않는다)
    return {
        "headline": template["headline"],
        "warning": template.get("warning"),
        "detail": (output.get("detail") or None),
        "confirmed_facts": list(output.get("confirmed_facts", [])),
        "suspicion_evidence": list(output.get("suspicion_evidence", [])),
        "unverified": template["unverified"],
        "recommended_action": template["recommended_action"],
        "action_bullets": list(template.get("action_bullets", [])),
        "source": "agent",
    }
