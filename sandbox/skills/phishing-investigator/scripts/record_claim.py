#!/usr/bin/env python3
"""3-0. 에이전트가 고른 사칭 대상과 목적을 claim.json에 기록한다.

python3 record_claim.py --job <id> --entity <kb_id|none> --purpose <enum> --reason "<60자 이내>"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from checklib.util import now_iso, read_json, work_dir, write_json  # noqa: E402

PURPOSES = ["delivery", "payment", "account_security", "government_notice", "prize_event", "other"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job", required=True)
    ap.add_argument("--entity", required=True)
    ap.add_argument("--purpose", required=True)
    ap.add_argument("--reason", default="")
    ap.add_argument("--name", default="", help="KB에 없는 기관일 때 문자에 나온 이름(선택, 20자 이내)")
    ap.add_argument("--work-root", default=None)
    args = ap.parse_args(argv)

    wd = work_dir(args.job, args.work_root)
    out = wd / "claim.json"
    try:
        inp = read_json(wd / "input.json")
        ids = {c["id"] for c in inp.get("kb_candidates", [])}
        if args.purpose not in PURPOSES:
            raise ValueError(f"purpose must be one of {PURPOSES}")
        if args.entity != "none" and args.entity not in ids:
            raise ValueError("entity must be a kb candidate id or 'none'")
        write_json(out, {
            "ok": True,
            "entity_id": None if args.entity == "none" else args.entity,
            "purpose": args.purpose,
            "reason": args.reason.strip()[:60],
            "name": args.name.strip()[:20] or None,
            "at": now_iso(),
        })
        print(f"claim recorded: entity={args.entity} purpose={args.purpose}")
        return 0
    except Exception as e:  # noqa: BLE001
        write_json(out, {"ok": False, "error": str(e)[:200], "at": now_iso()})
        print(f"claim error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
