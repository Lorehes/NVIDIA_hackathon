"""환경 설정. 비밀(NVIDIA 키 등)은 .env에서만 읽고 브라우저로 내보내지 않는다."""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
API_ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv() -> None:
    env = API_ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()


class Settings:
    # 샌드박스 실행 방식
    #   openshell : NemoClaw/OpenShell 샌드박스에서 에이전트 실행(운영·시연)
    #   local     : 개발 전용. 검사 스크립트를 로컬 픽스처로 실행하고 에이전트는 규칙으로 흉내 낸다.
    #               실제 네트워크에는 절대 접속하지 않는다.
    sandbox_mode: str = os.environ.get("SANDBOX_MODE", "local")
    sandbox_name: str = os.environ.get("SANDBOX_NAME", "my-assistant")

    kb_path: Path = Path(os.environ.get("KB_PATH", REPO_ROOT / "kb" / "entities.json"))
    skills_dir: Path = REPO_ROOT / "sandbox" / "skills"
    scripts_dir: Path = skills_dir / "phishing-investigator" / "scripts"
    fixtures_dir: Path = Path(os.environ.get("FIXTURES_DIR", REPO_ROOT / "demo-sites"))
    preset_template: Path = REPO_ROOT / "infra" / "presets" / "job-template.yaml"

    db_path: Path = Path(os.environ.get("DB_PATH", API_ROOT / "data" / "jobs.sqlite"))
    replay_dir: Path = Path(os.environ.get("REPLAY_DIR", API_ROOT / "data" / "replay"))
    work_dir: Path = Path(os.environ.get("LOCAL_WORK_DIR", API_ROOT / "data" / "work"))

    # 타임아웃(초): 조사 60 + 설명 30 = PRD 90초 예산
    agent_timeout_s: int = int(os.environ.get("AGENT_TIMEOUT_S", "60"))
    explain_timeout_s: int = int(os.environ.get("EXPLAIN_TIMEOUT_S", "30"))
    queue_max: int = int(os.environ.get("QUEUE_MAX", "5"))

    # 사용 도구 허용 목록 (이 밖의 도구는 unexpected_tools로 기록)
    allowed_tools = {"read", "exec"}

    # 임베딩(NeMo Retriever). 키가 없으면 문자 n-gram 검색으로 대체
    nvidia_api_key: str | None = os.environ.get("NVIDIA_API_KEY") or None
    embed_model: str = os.environ.get("EMBED_MODEL", "nvidia/llama-3.2-nv-embedqa-1b-v2")
    embed_url: str = os.environ.get("EMBED_URL", "https://integrate.api.nvidia.com/v1/embeddings")

    # 재생 모드 진행 속도 배율(1.0 = 실제 시연 속도 약 12초)
    replay_speed: float = float(os.environ.get("REPLAY_SPEED", "1.0"))

    cors_origins = [o for o in os.environ.get("CORS_ORIGINS", "").split(",") if o]


settings = Settings()
