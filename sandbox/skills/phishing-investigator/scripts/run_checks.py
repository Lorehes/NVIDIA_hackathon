#!/usr/bin/env python3
"""3-5. 검사 4종을 순서대로 실행하고 결과를 작업 폴더에 JSON으로 기록한다.

python3 run_checks.py --job <id>

parse_url → similarity → fetch_chain → inspect_page.
표준 출력에는 한 줄 요약만 낸다. 실패도 {"ok": false, "error": ...}로 기록하고 재시도하지 않는다.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from checklib import fetch_chain as fc  # noqa: E402
from checklib import inspect_page as ip  # noqa: E402
from checklib import similarity as sim  # noqa: E402
from checklib.parse_url import parse_url  # noqa: E402
from checklib.util import now_iso, read_json, work_dir, write_json  # noqa: E402


def _safe(step: str, fn):
    t0 = time.time()
    try:
        out = fn()
    except Exception as e:  # noqa: BLE001 - 어떤 실패도 기록하고 다음으로
        out = {"ok": False, "error": f"{step}: {type(e).__name__}: {e}"[:300]}
    if isinstance(out, dict):
        out.setdefault("elapsed_ms", int((time.time() - t0) * 1000))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job", required=True)
    ap.add_argument("--work-root", default=None)
    ap.add_argument("--fixtures", default=None, help="개발·테스트 전용: 로컬 픽스처 디렉터리")
    args = ap.parse_args(argv)

    wd = work_dir(args.job, args.work_root)
    inp = read_json(wd / "input.json")
    url = inp["url"]
    started = now_iso()

    parsed = _safe("parse_url", lambda: parse_url(url))
    write_json(wd / "parse_url.json", parsed)

    official = inp.get("kb_official_domains", [])
    if parsed.get("ok"):
        similarity = _safe("similarity", lambda: sim.compare(parsed, official))
    else:
        similarity = {"ok": False, "error": "parse failed"}
    write_json(wd / "similarity.json", similarity)

    html = b""
    if not parsed.get("ok"):
        chain = {"ok": False, "error": "parse failed"}
    elif inp.get("fetch_allowed") is False:
        chain = {"ok": True, "skipped": True, "reason": "fetch not allowed for this host",
                 "chain": [], "final_url": None, "final_registrable_domain": None,
                 "redirect_count": 0, "blocked_count": 0, "html_saved": False}
    else:
        def _fetch():
            nonlocal html
            if args.fixtures:
                fetcher = fc.FixtureFetcher(args.fixtures, parsed["host_ascii"])
            else:
                fetcher = fc.HttpxFetcher()
            try:
                result, html = fc.fetch_chain(url, fetcher)
                return result
            finally:
                fetcher.close()

        chain = _safe("fetch_chain", _fetch)
    write_json(wd / "fetch_chain.json", chain)

    if html:
        (wd / "page.html").write_bytes(html[:1_000_000])
        page_url = chain.get("final_url") or url
        page = _safe("inspect_page", lambda: ip.inspect_page(html, page_url, chain.get("final_content_type_full") or chain.get("final_content_type", "")))
    else:
        page = {"ok": False, "error": "no html"}
    write_json(wd / "page.json", page)
    write_json(wd / "run_meta.json", {"started_at": started, "finished_at": now_iso()})

    blocked = chain.get("blocked_count", 0) if isinstance(chain, dict) else 0
    print(f"checks done: parse={parsed.get('ok')} sim={similarity.get('ok')} "
          f"fetch={chain.get('ok')} blocked={blocked} page={page.get('ok')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
