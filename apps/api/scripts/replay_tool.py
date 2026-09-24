"""재생 모드 데이터 만들기.

  python -m scripts.replay_tool build            # 로컬 흉내 실행으로 7개 사례 저장(개발용)
  python -m scripts.replay_tool save <job_id> <case_id>   # 실제 조사 결과(DB)를 사례로 저장(운영: VM에서 실제 실행 뒤)

저장 위치: apps/api/data/replay/<case_id>.json. 재생 중에는 화면에 "시연 모드" 표시가 붙는다.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import settings  # noqa: E402
from app.db import DB  # noqa: E402
from app.demo_cases import ALL_CASES  # noqa: E402
from app.kb import get_kb  # noqa: E402
from app.replay import save_replay  # noqa: E402
from app.sandbox import LocalSandbox  # noqa: E402
from app.urls import extract_urls  # noqa: E402
from app.worker import Investigator, new_job_id  # noqa: E402


def build() -> None:
    tmp = Path(tempfile.mkdtemp())
    db = DB(tmp / "replay-build.sqlite")
    for case in ALL_CASES:
        inv = Investigator(db, LocalSandbox(workdir=tmp / "work", force_incomplete=case.get("force_incomplete")),
                           get_kb())
        jid = new_job_id()
        urls = extract_urls(case["input"])
        db.create(dict(job_id=jid, status="queued", stage="parse", mode="live", input=case["input"], url=urls[0],
                       more_urls=urls[1:], steps=[]))
        inv.run(jid)
        job = db.get(jid)
        if job["status"] != "done":
            raise SystemExit(f"{case['id']} failed: {job.get('error')}")
        got = job["result"]["verdict"]
        if got != case["expected_verdict"]:
            raise SystemExit(f"{case['id']}: expected {case['expected_verdict']} got {got}")
        save_replay(case["id"], job["result"], job["trace"], job["steps"])
        print(f"saved {case['id']:14s} {got}")


def save(job_id: str, case_id: str) -> None:
    db = DB(settings.db_path)
    job = db.get(job_id)
    if not job or job["status"] != "done":
        raise SystemExit("job not found or not done")
    save_replay(case_id, job["result"], job["trace"], job["steps"])
    print(f"saved {case_id} from {job_id}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "build":
        build()
    elif len(sys.argv) == 4 and sys.argv[1] == "save":
        save(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
