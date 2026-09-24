# 공식 도메인 KB

`entities.json`이 사칭 대상 기관과 공식·파트너 도메인의 유일한 원본이다. 판정 엔진과 검사 스크립트(유사도)가 이 파일을 읽는다.

## 지금 들어 있는 것

가상 브랜드 2개(한빛택배, 하늘은행). 데모용이며 도메인은 예약 TLD(`.example`)다.

## 실제 기관을 추가하려면 (상세 명세 7절)

- **각 기관의 공식 사이트에서 직접 확인한 도메인만** 넣는다. 기억이나 검색 결과로 채우지 않는다.
- `sources`에 도메인을 확인한 공식 페이지 URL과 확인 날짜를 반드시 적는다.
- 확인하지 못한 기관은 넣지 않는다. (KB에 없는 기관은 "알 수 없어요/조심하세요"로 안내되고, 거짓 "가짜" 판정을 내지 않는다.)
- 도메인은 등록 도메인 단위로 적는다(`example.co.kr`처럼 다단계 접미사 포함).
- `fictional: false`로 표시한다.
- `policy_rules[].forbids`: 그 기관이 문자·링크로 요구하지 않겠다고 밝힌 입력란(`password`, `card_number`, `card_cvc`, `card_expiry`, `bank_account`, `resident_id`, `otp`).
  판정 엔진이 이 값으로 "회사 약속과 달라요"를 계산한다.

## 필드

| 필드 | 필수 | 설명 |
|---|---|---|
| `id` | 필수 | 영문 소문자 식별자 |
| `name` | 필수 | 표시 이름 |
| `aliases` | 필수 | 문자에 쓰일 수 있는 별칭 |
| `category` | 필수 | delivery, bank, card, government, telecom, fictional |
| `official_domains` | 필수 | 등록 도메인 단위 |
| `partner_domains` | 선택 | 공식적으로 쓰는 인증·결제 대행 도메인 |
| `policies` | 선택 | 표시용 문구 |
| `policy_rules` | 선택 | 엔진용 구조화 규칙(위 참고) |
| `official_app` | 선택 | 공식 앱 이름 |
| `sources` | 필수 | 확인한 공식 페이지 URL과 확인 날짜 |
| `fictional` | 필수 | 가상 브랜드 여부 |
