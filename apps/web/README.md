# 문자 링크 확인 — 웹 (Next.js)

받은 문자·링크를 붙여 넣으면 결과와 이유를 쉬운 말로 보여 주는 화면입니다. 디자인 v2(쉬운 말 버전)를 구현했습니다.
브라우저는 FastAPI에 직접 접속하지 않고, Next 서버의 `/api/*` 라우트가 `API_BASE_URL`로 전달합니다. 키·토큰은 브라우저로 나가지 않습니다.

## 실행

```bash
cd apps/web
npm install
npm run dev            # http://localhost:3100  (개발)
npm run build && npm start   # 운영: next start -p 3100
npm run typecheck
```

백엔드 없이 화면만 볼 때:

```bash
API_MOCK=1 npm run dev
```

## 환경 변수

| 이름 | 기본값 | 설명 |
|---|---|---|
| `API_BASE_URL` | `http://127.0.0.1:8000` | FastAPI 주소(서버에서만 사용) |
| `API_MOCK` | `0` | `1`이면 `mocks/data.ts`의 예시 데이터로 응답 |

## 화면과 주소

| 주소 | 화면 |
|---|---|
| `/` | 홈: 문자 붙여넣기, 링크 미리 찾기, 예시 5개 |
| `/check/[jobId]` | 확인 중(2초마다 새로고침) → 결과(안전·조심·가짜 의심·알 수 없음) |
| `/check/[jobId]/trace?tab=address\|path\|page\|agent\|sandbox` | 조사 기록 5개 탭 |
| `/how` | 이용 방법 |

- 시연 모드: 주소에 `?demo=1`을 붙이면 켜지고(탭이 닫힐 때까지 기억), `?demo=0` 또는 배너의 "끄기"로 끕니다. 붙여 넣은 글이 데모 사례와 같으면 `mode: "replay"`와 `case_id`를 보냅니다.
- 링크 찾기 규칙은 서버와 같습니다(`lib/links.ts`): `https?://…`에서 끝 문장부호를 자르고, 경로 뒤에 처음 나오는 한글부터는 조사로 봅니다. 입력 전체가 공백 없는 도메인 한 덩어리면 링크로 받아들입니다.
- API_MOCK 모드에서 조사 id는 `mock_<시나리오>_<시작시각>` 입니다. `mock_queued_<ms>`는 대기 화면을 보여 줍니다. 입력에 `queue-demo`가 들어 있으면 대기 시나리오로 시작합니다.

## 구조

- `lib/types.ts` — `apps/api/app/models.py`를 1:1로 옮긴 타입
- `lib/api.ts`, `lib/submit.ts` — 브라우저 → Next 호출, 오류를 쉬운 말로 변환
- `app/api/**` — FastAPI 프록시(연결 실패는 502 `backend_unreachable`)
- `components/` — 화면(홈·진행·결과·조사 기록·이용 방법)
- `mocks/data.ts` — API_MOCK용 예시 결과·조사 기록·진행 순서
