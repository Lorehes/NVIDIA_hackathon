"""공통 유틸: 작업 폴더 경로, JSON 입출력, 시각 기록."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
DEFAULT_WORK_ROOT = "/sandbox/work"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def work_dir(job_id: str, work_root: str | None = None) -> Path:
    if not JOB_ID_RE.match(job_id or ""):
        raise ValueError("invalid job id")
    root = work_root or os.environ.get("WORK_ROOT") or DEFAULT_WORK_ROOT
    return Path(root) / job_id


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))
