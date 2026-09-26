"""데모 5개 사례(기획서 5절, 상세 명세 9-2). 가상 브랜드와 예약 도메인(.example/.test)만 쓴다."""
from __future__ import annotations

DEMO_CASES: list[dict] = [
    {
        "id": "official", "label": "진짜 택배 사이트", "expected_verdict": "safe",
        "input": "[한빛택배] 고객님의 택배가 배송 중입니다. 배송 조회: https://hanbit.example/track/12345",
    },
    {
        "id": "lookalike", "label": "한 글자 바꾼 가짜 주소", "expected_verdict": "suspected_impersonation",
        "input": "[한빛택배] 배송지 확인이 필요합니다. 로그인 후 확인: https://hanblt.example/login",
    },
    {
        "id": "disguise", "label": "진짜 주소를 앞에 붙인 가짜", "expected_verdict": "suspected_impersonation",
        "input": "[한빛택배] 주소 불일치로 배송 보류. 수정: https://hanbit.example.account-check.test/login",
    },
    {
        "id": "clone", "label": "화면을 베낀 가짜", "expected_verdict": "suspected_impersonation",
        "input": "[한빛택배] 배송지 오류로 반송 예정입니다. 주소 수정: https://hanbit-parcel.test/address",
    },
    {
        "id": "partner", "label": "택배사가 쓰는 결제 사이트", "expected_verdict": "safe",
        "input": "[한빛택배] 착불 요금 3,500원 결제 안내: https://pay-partner.example/checkout",
    },
]

# 화면 QA·재생 전용(예시 버튼에는 나오지 않는다)
EXTRA_CASES: list[dict] = [
    {
        "id": "vm-example", "label": "VM 실제 조사: 공개 예시 주소", "expected_verdict": "unknown",
        "input": "https://example.com", "live_capture_only": True,
    },
    {
        "id": "extra-caution", "label": "목록에 없는 회사", "expected_verdict": "caution",
        "input": "[별빛마켓] 회원 정보 확인이 필요합니다. https://member-check.test/login",
    },
    {
        "id": "extra-unknown", "label": "조사가 멈춤", "expected_verdict": "unknown",
        "input": "[한빛택배] 배송 안내입니다. 확인: https://hanblt.example/login",
        "force_incomplete": {"hanblt.example": "overloaded"},
    },
]

ALL_CASES = DEMO_CASES + EXTRA_CASES


def find_case(case_id: str | None = None, text: str | None = None) -> dict | None:
    for c in ALL_CASES:
        if case_id and c["id"] == case_id:
            return c
    if text:
        t = " ".join(text.split())
        for c in ALL_CASES:
            if " ".join(c["input"].split()) == t:
                return c
    return None
