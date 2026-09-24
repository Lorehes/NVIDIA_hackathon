"""SQLite 작업 저장소(D3). 재시작해도 결과가 남는다."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  stage TEXT NOT NULL,
  mode TEXT NOT NULL,
  case_id TEXT,
  owner TEXT,
  input TEXT NOT NULL,
  url TEXT NOT NULL,
  more_urls TEXT NOT NULL DEFAULT '[]',
  steps TEXT NOT NULL DEFAULT '[]',
  open_hosts TEXT NOT NULL DEFAULT '[]',
  blocked_count INTEGER NOT NULL DEFAULT 0,
  result TEXT,
  trace TEXT,
  error TEXT,
  timings TEXT NOT NULL DEFAULT '{}',
  created_at REAL NOT NULL,
  started_at REAL,
  finished_at REAL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, created_at);
"""

_JSON_COLS = {"more_urls", "steps", "open_hosts", "result", "trace", "timings"}


class DB:
    def __init__(self, path: Path | str, retention_s: float | None = None):
        self.retention_s = retention_s  # 주면 끝난 작업이 이 시간이 지난 뒤에는 삭제 전이라도 열리지 않는다
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(jobs)")}
            if "owner" not in cols:  # 소유자 검사 도입 전에 만든 DB: 소유자 없는 기존 작업은 아무도 열람할 수 없다
                self._conn.execute("ALTER TABLE jobs ADD COLUMN owner TEXT")
            self._conn.commit()

    def create(self, job: dict[str, Any]) -> None:
        row = {**job, "created_at": time.time()}
        for c in _JSON_COLS & row.keys():
            row[c] = json.dumps(row[c], ensure_ascii=False)
        cols = ", ".join(row)
        qs = ", ".join("?" for _ in row)
        with self._lock:
            self._conn.execute(f"INSERT INTO jobs ({cols}) VALUES ({qs})", list(row.values()))
            self._conn.commit()

    def update(self, job_id: str, **fields: Any) -> None:
        for c in _JSON_COLS & fields.keys():
            fields[c] = json.dumps(fields[c], ensure_ascii=False)
        sets = ", ".join(f"{k} = ?" for k in fields)
        with self._lock:
            self._conn.execute(f"UPDATE jobs SET {sets} WHERE job_id = ?", [*fields.values(), job_id])
            self._conn.commit()

    def get(self, job_id: str, owner: str | None = None) -> dict[str, Any] | None:
        """owner를 주면 그 세션의 작업만 돌려준다(남의 작업은 없는 것처럼 None)."""
        with self._lock:
            r = self._conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        if r is None or (owner is not None and r["owner"] != owner):
            return None
        if self.retention_s is not None and r["status"] in ("done", "failed")                 and (r["finished_at"] or r["created_at"]) < time.time() - self.retention_s:
            return None  # 보관 기간이 지났다(주기 삭제 전이어도 열지 않는다)
        return self._decode(r)

    def queued_ids(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT job_id FROM jobs WHERE status = 'queued' AND mode = 'live' ORDER BY created_at").fetchall()
        return [r["job_id"] for r in rows]

    def count_status(self, status: str) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM jobs WHERE status = ? AND mode = 'live'",
                                      (status,)).fetchone()[0]

    def purge_expired(self, max_age_s: float) -> int:
        """보관 기간이 지난 끝난 작업을 지운다(문자 원문·URL·결과 포함). 진행 중인 작업은 건드리지 않는다."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM jobs WHERE status IN ('done','failed') AND COALESCE(finished_at, created_at) < ?",
                (time.time() - max_age_s,))
            self._conn.commit()
            return cur.rowcount

    def fail_stale(self) -> int:
        """서버가 죽으면서 남은 queued/running 작업을 실패 처리한다(재시작 시 1회)."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE jobs SET status='failed', error='서버가 다시 시작돼서 조사가 멈췄어요. 다시 확인해 주세요.',"
                " finished_at=? WHERE status IN ('queued','running')", (time.time(),))
            self._conn.commit()
            return cur.rowcount

    @staticmethod
    def _decode(r: sqlite3.Row) -> dict[str, Any]:
        d = dict(r)
        for c in _JSON_COLS:
            if d.get(c) is not None:
                d[c] = json.loads(d[c])
        return d
