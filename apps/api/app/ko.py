"""한국어 문장 조립 도우미: 조사, 입력란 이름 등 '쉬운 말' 사전(디자인 3a)."""
from __future__ import annotations


def _has_batchim(word: str) -> bool:
    for ch in reversed(word.strip()):
        code = ord(ch)
        if 0xAC00 <= code <= 0xD7A3:
            return (code - 0xAC00) % 28 != 0
        if ch.isdigit():
            return ch in "013678"  # 영, 일, 삼, 육, 칠, 팔 (공, 십은 무시)
        if ch.isalpha():
            return False
    return False


def subj(word: str) -> str:
    return word + ("이" if _has_batchim(word) else "가")


def obj(word: str) -> str:
    return word + ("을" if _has_batchim(word) else "를")


def topic(word: str) -> str:
    return word + ("은" if _has_batchim(word) else "는")


def with_(word: str) -> str:
    return word + ("과" if _has_batchim(word) else "와")


def possessive(word: str) -> str:
    return word + "의"


FIELD_LABELS = {
    "password": "비밀번호",
    "card_number": "카드 번호",
    "card_cvc": "카드 뒷면 숫자 3자리",
    "card_expiry": "카드 유효기간",
    "bank_account": "계좌번호",
    "resident_id": "주민등록번호",
    "otp": "인증번호",
    "phone": "전화번호",
    "name": "이름",
    "address": "받을 주소",
    "other": "기타 정보",
}

# 문자에서 붙일 때 짧게 쓰는 이름 (카드 뒷면 숫자 3자리 → 카드 뒷면 숫자)
FIELD_SHORT = {**FIELD_LABELS, "card_cvc": "카드 뒷면 숫자"}

PURPOSE_LABELS = {
    "delivery": "택배 안내",
    "payment": "결제 안내",
    "account_security": "계정·로그인 안내",
    "government_notice": "관공서 안내",
    "prize_event": "이벤트·당첨 안내",
    "other": "안내 문자",
}

PURPOSE_CONTEXT = {  # "택배 일에는 필요 없는 …"
    "delivery": "택배 일",
    "payment": "결제",
    "account_security": "계정 확인",
    "government_notice": "관공서 일",
    "prize_event": "이벤트",
    "other": "이 안내",
}

PURPOSE_EXPECTED = {
    "delivery": ["name", "phone", "address"],
    "payment": ["card_number", "card_expiry", "name"],
    "account_security": ["password", "otp"],
    "government_notice": ["name", "phone", "resident_id"],
    "prize_event": ["name", "phone", "address"],
    "other": [],
}

INCOMPLETE_REASONS = {
    "agent_timeout": "1분 안에 답이 오지 않아 멈췄어요",
    "overloaded": "AI가 너무 바빠서 조사가 멈췄어요",
    "agent_error": "AI 조사원이 답하지 못해 멈췄어요",
    "sandbox_error": "안전 공간을 준비하지 못해 멈췄어요",
    "policy_error": "안전 공간의 문을 열지 못해 멈췄어요",
}


def field_list(types: list[str], short: bool = False) -> str:
    table = FIELD_SHORT if short else FIELD_LABELS
    return ", ".join(table.get(t, t) for t in types)


def join_kr(items: list[str]) -> str:
    return ", ".join(items)
