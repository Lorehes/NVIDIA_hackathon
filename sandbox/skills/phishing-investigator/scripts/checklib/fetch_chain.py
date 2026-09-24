"""3-3. 리다이렉트 경로 추적. 이 모듈이 유일하게 외부에 접속한다.

- 리다이렉트는 수동으로 따라간다(단계마다 호스트·상태·차단 여부를 기록).
- 샌드박스가 허용하지 않은 호스트는 프록시가 403을 돌려주고 httpx.ProxyError가 난다 → blocked: true.
- 본문은 최대 1MB만 저장하고 실행하지 않는다(JavaScript 미실행).
- fixtures 모드: 실제 접속 없이 로컬 픽스처로 같은 동작을 재현한다(개발·테스트 전용).
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .parse_url import parse_url
from .util import now_iso

MAX_BODY = 1_000_000
MAX_HOPS = 5
TIMEOUT = 10.0
MOBILE_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Mobile Safari/537.36"
)


class Blocked(Exception):
    """샌드박스 정책이 접속을 막음."""


class FetchError(Exception):
    pass


class Response:
    def __init__(self, status: int, location: str | None = None, body: bytes = b"",
                 content_type: str = "text/html"):
        self.status, self.location, self.body, self.content_type = status, location, body, content_type


# ── 실제 네트워크 ────────────────────────────────────────────────
class HttpxFetcher:
    def __init__(self, timeout: float = TIMEOUT):
        import httpx  # 지연 import: 테스트·픽스처 모드에서는 필요 없음

        self._httpx = httpx
        self._client = httpx.Client(follow_redirects=False, timeout=timeout,
                                    headers={"User-Agent": MOBILE_UA, "Accept": "text/html,*/*;q=0.8"})

    def get(self, url: str) -> Response:
        httpx = self._httpx
        try:
            with self._client.stream("GET", url) as r:
                body = b""
                for chunk in r.iter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY:
                        body = body[:MAX_BODY]
                        break
                return Response(r.status_code, r.headers.get("location"), body,
                                r.headers.get("content-type", ""))
        except httpx.ProxyError as e:
            raise Blocked(str(e)) from e
        except httpx.HTTPError as e:
            raise FetchError(f"{type(e).__name__}: {e}"[:200]) from e

    def close(self) -> None:
        self._client.close()


# ── 픽스처(로컬 재현) ─────────────────────────────────────────────
class FixtureFetcher:
    """fixtures_dir/sites.json: { "host/path": {"status":200,"file":"x.html","location":"https://.."} }

    허용 호스트는 조사 대상 호스트 하나뿐이다(샌드박스 정책과 동일). 나머지는 Blocked.
    """

    def __init__(self, fixtures_dir: str | Path, allowed_host: str):
        self.dir = Path(fixtures_dir)
        self.allowed_host = allowed_host.lower()
        self.sites = json.loads((self.dir / "sites.json").read_text(encoding="utf-8"))

    def get(self, url: str) -> Response:
        sp = urlsplit(url)
        host = (sp.hostname or "").lower()
        if host != self.allowed_host:
            raise Blocked("403 Forbidden (policy)")
        key = host + (sp.path or "/")
        rec = self.sites.get(key) or self.sites.get(key.rstrip("/")) or self.sites.get(host + "/*")
        if rec is None:
            return Response(404, None, b"not found")
        body = b""
        if rec.get("file"):
            body = (self.dir / rec["file"]).read_bytes()[:MAX_BODY]
        if rec.get("timeout"):
            raise FetchError("ReadTimeout")
        return Response(int(rec.get("status", 200)), rec.get("location"), body, "text/html")

    def close(self) -> None:
        pass


# ── 추적 본체 ────────────────────────────────────────────────────
def fetch_chain(url: str, fetcher, max_hops: int = MAX_HOPS) -> tuple[dict, bytes]:
    chain: list[dict] = []
    html = b""
    current = url
    first_error = None
    tls_verified: bool | None = None

    for _hop in range(max_hops + 1):
        p = parse_url(current)
        entry = {
            "url": current[:500],
            "host": p.get("host_ascii", ""),
            "registrable_domain": p.get("registrable_domain", ""),
            "status": None, "blocked": False, "error": None, "at": now_iso(),
        }
        chain.append(entry)
        try:
            resp = fetcher.get(current)
        except Blocked:
            entry["blocked"] = True
            entry["status"] = 403
            break
        except FetchError as e:
            entry["error"] = str(e)
            if len(chain) == 1:
                first_error = str(e)
            if "SSL" in str(e) or "certificate" in str(e).lower():
                tls_verified = False
            break

        entry["status"] = resp.status
        if current.startswith("https://") and tls_verified is None:
            tls_verified = True
        if resp.body and ("html" in resp.content_type.lower() or not resp.content_type):
            html = resp.body  # 3xx 응답이 본문을 실어 보내는 경우도 저장한다(마지막 성공 응답 우선)
        if 300 <= resp.status < 400 and resp.location:
            current = urljoin(current, resp.location)
            continue
        break

    reached = [c for c in chain if not c["blocked"] and c["error"] is None]
    last_ok = reached[-1] if reached else None
    result = {
        "ok": True,
        "chain": chain,
        "final_url": last_ok["url"] if last_ok else None,
        "final_registrable_domain": last_ok["registrable_domain"] if last_ok else None,
        "redirect_count": max(0, len(chain) - 1),
        "blocked_count": sum(1 for c in chain if c["blocked"]),
        "tls": {"https": url.startswith("https://"), "verified": tls_verified},
        "html_saved": bool(html),
        "first_error": first_error,
    }
    return result, html
