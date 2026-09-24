# 구현 중 내린 결정과 명세와의 차이

기준 문서: 2026-09-24 PRD · 기획서 · 아키텍처 설계서 · 상세 명세, 와이어프레임 v2(쉬운 말 버전).

## 미결 사항(D1~D4)에 대해 고른 것 — 모두 문서의 "추천"을 따랐다

| # | 선택 | 비고 |
|---|---|---|
| D1 | VM에 Next.js(:3100) 동일 배치, FastAPI는 루프백 | Next 서버가 API를 대신 호출(브라우저는 API 주소·비밀을 볼 수 없음) |
| D2 | 데모 도메인은 아직 미정. 코드는 예약 TLD(`.example`/`.test`) 픽스처로 동작 | 실제 도메인 확보 후 `infra/nginx/demo-sites.conf.example` 참고 |
| D3 | SQLite | `apps/api/data/jobs.sqlite`, 재시작해도 결과 유지 |
| D4 | 샌드박스 에이전트 2차 실행(A) | 90초를 넘기면 `Sandbox.explain`만 API 직접 호출로 바꾸면 된다 |

## 명세에 없던 것을 추가했거나 바꾼 것

| 항목 | 내용 | 이유 |
|---|---|---|
| 신호 `brand_in_domain`(강) | 등록 도메인 이름에 공식 브랜드 이름이 토큰으로 포함(`hanbit-parcel.test`) | 명세의 유사도(≥0.80)로는 "화면 복제" 사례(E4)의 주소를 잡지 못함 |
| 신호 `domain_not_official`(중) | 사칭 대상이 KB에 있는데 주소가 공식·파트너 목록에 없음 | 기관을 특정했는데도 공식 주소가 아닌 주소가 `unknown`이 되는 빈틈을 막음 |
| 규칙 3 보강 | `safe`는 페이지를 실제로 열어본 경우에만. `fetch_failed`·`redirect_other_domain`이 있으면 `safe`가 아님 | 열지 못한 사이트를 "안전"이라고 안내하지 않기 위해(N6) |
| 공식·파트너 도메인 | 목적 불일치(`purpose_mismatch`)와 위장·유사 신호를 판정에 쓰지 않음 | 모델의 목적 분류 오류가 정상 사이트(E1, E5)를 흔들지 못하게 |
| `incomplete`(조사 중단) | 에이전트 실패·시간 초과·정책 오류는 다른 신호와 무관하게 `unknown`. 단 멈추기 전 발견한 것(`partial_findings`)은 보여 줌 | 디자인 4e·PRD N6. 명세 규칙 1의 확장 |
| 3xx 응답 본문 저장 | 리다이렉트 응답이 본문(HTML)을 실어 보내면 저장·분석 | 디자인 3f·3g 사례(넘어가려던 곳은 막고 페이지는 분석)를 하나의 흐름으로 재현 |
| `record_claim.py --name` | KB에 없는 기관의 이름(20자)을 선택적으로 기록 | 결과 화면 "별빛마켓의 진짜 주소는 목록에 없어요"에 필요. 화면에 나가기 전 코드가 문자 종류를 제한 |
| KB `policy_rules` | `policies` 문구 옆에 구조화된 "요구하지 않는 입력란" 규칙 | "회사 약속과 달라요" 비교를 결정적으로 계산하려고 |
| 설명 필드 확장 | `warning`, `detail`, `action_bullets` 추가, `unverified`는 항상 코드가 채움 | 디자인의 결과 카드 구조. 모델이 "확인 못 한 것"을 빠뜨리거나 바꿀 수 없게 |
| `GET /investigations/{id}` | `steps[5]`(화면용 5단계), `open_hosts`, `blocked_count` 추가 | 진행 화면(3c)의 "안전 공간에서 여는 중" 박스와 5단계 표시 |
| 오류 형식 | `{"error":{"code","message"}}` + 쉬운 말 메시지 | 화면에 그대로 표시 |
| 시연 모드 | `mode=replay`는 `case_id` 또는 입력 문자가 데모 사례와 같을 때만. `data/replay/*.json` | 명세 9-3. 디자인에서 홈의 토글은 삭제되어 `?demo=1`로 켠다 |

## 로컬 개발용 흉내(LocalSandbox)

`SANDBOX_MODE=local`(기본)은 실제 격리가 없다. 같은 `record_claim.py`/`run_checks.py`를 실행하되 네트워크에는 접속하지 않고
`demo-sites/` 픽스처만 읽으며, 에이전트 역할(사칭 대상·목적 고르기)은 규칙으로 흉내 낸다. 결과의 `agent.kind`가 `local-sim`으로 표시된다.
운영·시연은 `SANDBOX_MODE=openshell`.

## 아직 사실이 아닌 것 (검증 필요)

- OpenShell/NemoClaw 실제 명령 형식은 스파이크 결과 보고서의 표기를 따랐고, 이 PC에는 없어 **실제 호출로는 검증하지 못했다**. 명령 순서·정책 수명주기는 가짜 실행기로 테스트했다(`tests/test_sandbox_openshell.py`).
  `openclaw agent --json`의 `toolSummary`/`executionTrace`/모델 이름 필드 위치는 [추정]이라 `sandbox.extract_tools`/`_agent_meta`가 관대하게 읽는다. 첫 실행 뒤 실제 형식에 맞춰 조정할 것.
- 임베딩 API(NeMo Retriever)는 키가 없어 검증하지 못했다(키가 없으면 문자 n-gram 검색으로 대체된다). 모델 ID는 [추정].
- 실제 기관 KB는 비어 있다(가상 브랜드 2개). `kb/README.md`의 절차로 공식 사이트에서 확인한 값만 추가할 것.
- V1(실제 모델), V2(`web_fetch` 차단), V3(동시 호출), V4(조사 1건 소요 시간)는 VM에서 확인해야 한다.
