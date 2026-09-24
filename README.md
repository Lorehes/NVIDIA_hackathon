# 사칭 탐지 개인 보안 에이전트 (가칭)

의심 문자·링크를 붙여 넣으면, 격리된 샌드박스에서 대신 열어보고 **누구를 사칭하는지 근거와 함께** 알려주는 웹 서비스.
판정은 코드(규칙)가, 설명은 모델(Nemotron)이 맡는다. 문서: `2026-09-24-*.md`, 결정 사항: `docs/decisions.md`.

```
apps/api        FastAPI: 작업 큐, KB 검색, 판정 엔진, 샌드박스 제어(nemoclaw/openshell), 설명 검증, SQLite
apps/web        Next.js: 홈 · 진행 · 결과 4종 · 상세 기록 5탭 · 이용 방법 (디자인 v2, 쉬운 말)
sandbox/skills  샌드박스 안에서 도는 검사 스크립트와 OpenClaw skill 2개
kb/             공식 도메인 KB (가상 브랜드 2개)
demo-sites/     데모 5개 + 보안 시나리오 테스트 페이지, 로컬 픽스처 라우팅(sites.json)
infra/          정책 프리셋 템플릿, 배포 스크립트, systemd, nginx 예시
design/         와이어프레임 압축 해제본(참고용)
```

## 로컬에서 실행 (Windows/macOS/Linux, 샌드박스는 흉내)

```bash
# 1) API (Python 3.12+)
cd apps/api
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements-dev.txt   # macOS/Linux: .venv/bin/python
.venv/Scripts/python -m pytest                      # 테스트 (106개)
.venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2) 웹 (Node 20+)
cd apps/web && npm install && npm run dev -- -p 3100     # http://localhost:3100
```

- 로컬 기본값(`SANDBOX_MODE=local`)은 실제 접속 없이 `demo-sites/` 픽스처만 읽는다. 홈의 예시 버튼 5개가 데모 사례다.
- 시연 모드(저장된 결과 재생): 주소 뒤에 `?demo=1`. 재생 데이터는 `apps/api/data/replay/`.
  다시 만들기: `python -m scripts.replay_tool build` (개발) / `python -m scripts.replay_tool save <job_id> <case_id>` (VM에서 실제 조사 결과를 저장).

## VM(Brev)에서 운영

1. `apps/api/.env`: `cp .env.example .env` 후 `SANDBOX_MODE=openshell`, `NVIDIA_API_KEY` 입력 (저장소에 커밋 금지)
2. 샌드박스 준비: `infra/scripts/prepare-sandbox.sh` (의존 패키지 1회), `infra/scripts/deploy-skills.sh` (skill 업로드)
3. 서비스: `infra/systemd/*.service` (API는 127.0.0.1:8000, 웹은 :3100 → Brev Secure Link)
4. 조사 전후 `infra/scripts/check-residual-policies.sh`로 조사용 프리셋이 남지 않았는지 확인

## 검증 상태

- 검사 스크립트·판정 엔진·설명 검증·API·데모 5개(E1~E5)와 보안 시나리오(S1, S2)는 자동 테스트로 확인했다.
- OpenShell/NemoClaw 실제 호출, 실제 모델(Nemotron) 응답 형식, NeMo Retriever 임베딩은 이 PC에서 검증하지 못했다. `docs/decisions.md`의 "아직 사실이 아닌 것" 참고.
