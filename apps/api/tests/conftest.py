import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import settings  # noqa: E402


@pytest.fixture()
def tmp_env(tmp_path, monkeypatch):
    """DB·작업·재생 경로를 임시 폴더로 돌린다(샌드박스 모드는 local)."""
    monkeypatch.setattr(settings, "db_path", tmp_path / "jobs.sqlite")
    monkeypatch.setattr(settings, "work_dir", tmp_path / "work")
    monkeypatch.setattr(settings, "replay_dir", tmp_path / "replay")
    monkeypatch.setattr(settings, "sandbox_mode", "local")
    monkeypatch.setattr(settings, "replay_speed", 1000.0)
    return tmp_path
