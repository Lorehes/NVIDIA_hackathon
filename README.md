# 사칭 탐지 개인 보안 에이전트 (가칭)

의심 문자·링크를 붙여 넣으면, 격리된 샌드박스에서 대신 열어보고 **누구를 사칭하는지 근거와 함께** 알려주는 웹 서비스.
판정은 코드(규칙)가, 설명은 모델(Nemotron)이 맡는다. 문서: `2026-09-24-*.md`, 결정 사항: `docs/decisions.md`.

```
apps/api        FastAPI: 작업 큐, KB 검색, 판정 엔진, 샌드박스 제어(nemoclaw/openshell), 설명 검증, SQLite
apps/web        Next.js: 홈 · 진행 · 결과 4종 · 상세 기록 5탭 · 이용 방법 (디자인 v2, 쉬운 말)
sandbox/skills  샌드박스 안에서 도는 검사 스크립트와 OpenClaw skill 2개
kb/             공식 도메인 KB (실제 기관·서비스 15개 + 가상 브랜드 2개)
demo-sites/     데모 5개 + 보안 시나리오 테스트 페이지, 로컬 픽스처 라우팅(sites.json)
infra/          정책 프리셋 템플릿, 배포 스크립트, systemd, nginx 예시
design/         와이어프레임 압축 해제본(참고용)
```

## 로컬에서 실행 (Windows/macOS/Linux, 샌드박스는 흉내)

```bash
# 1) API (Python 3.12+)
cd apps/api
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements-dev.txt   # macOS/Linux: .venv/bin/python
.venv/Scripts/python -m pytest                      # 테스트 (2026-09-25: 464개 통과)
.venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2) 웹 (Node 20+)
cd apps/web && npm install && npm run dev -- -p 3100     # http://localhost:3100
```

- 로컬 기본값(`SANDBOX_MODE=local`)은 실제 접속 없이 `demo-sites/` 픽스처만 읽는다. 홈의 예시 버튼 5개가 데모 사례다.
- 시연 모드(저장된 결과 재생): 주소 뒤에 `?demo=1`. 재생 데이터는 `apps/api/data/replay/`.
  다시 만들기: `python -m scripts.replay_tool build` (개발) / `python -m scripts.replay_tool save <job_id> <case_id>` (VM에서 실제 조사 결과를 저장).

## VM(Brev)에서 운영

1. `apps/api/.env`: `cp .env.example .env` 후 `SANDBOX_MODE=openshell`, `NVIDIA_API_KEY` 입력 (저장소에 커밋 금지)
2. 샌드박스 준비: `bash infra/scripts/prepare-sandbox.sh` (의존 패키지 1회), `bash infra/scripts/deploy-skills.sh` (skill 업로드)
3. Brev 연결에서 `bash infra/scripts/configure-runtime.sh` 실행 후 서비스: `infra/systemd/*.service` (API는 127.0.0.1:8000, 웹은 :3100 → Brev Secure Link)
4. 조사 전후 `bash infra/scripts/check-residual-policies.sh`로 조사용 프리셋이 남지 않았는지 확인

## 검증 상태

- VM에서 전체 자동 테스트 464개, 웹 타입 검사·프로덕션 빌드 통과.
- 실제 OpenShell/Nemotron 조사 1건 완료(75.929초), 결과 파일 회수·정책 정리 및 실제 결과 재생 데이터 저장.
- 실제 네트워크 GET 허용·POST 차단·다른 도메인 차단, 원격 명령 시간 초과 후 정리 확인.
- 실제 기관·서비스 15개를 공식 출처와 함께 추가. 통제된 오프라인 사례 60개 통과(실사용 정확도 통계 아님).
- 보유 도메인이 없어 E1–E5/S1·S2의 실제 HTTPS 데모 전체 검증과 발표 녹화는 남아 있다.
- 재현 절차·측정값·남은 제약: [VM 검증 기록](docs/2026-09-25-vm-validation.md).

- 대표·www·모바일 주소 이동 처리: [네이버 차단 수정 기록](docs/2026-09-25-navigation-fix.md).
