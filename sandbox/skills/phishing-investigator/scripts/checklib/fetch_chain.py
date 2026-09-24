"""3-3. 리다이렉트 경로 추적. 이 모듈이 유일하게 외부에 접속한다.

- 리다이렉트는 수동으로 따라간다(단계마다 호스트·상태·차단 여부를 기록).
- 샌드박스가 허용하지 않은 호스트는 프록시가 403을 돌려주고 httpx.ProxyError가 난다 → blocked: true.
- 본문은 최대 1MB만 저장하고 실행하지 않는다(JavaScript 미실행).
- fixtures 모드: 실제 접속 없이 로컬 픽스처로 같은 동작을 재현한다(개발·테스트 전용).
"""
from __future__ import annotations

import hashlib
import json
import zlib
from pathlib import Path
from urllib.parse import urlsplit

from .parse_url import normalize_url, parse_url, resolve_reference
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
                 content_type: str = "text/html", truncated: bool = False, refresh: str | None = None):
        self.status, self.location, self.body, self.content_type = status, location, body, content_type
        self.truncated = truncated  # 본문이 한도(MAX_BODY)에서 잘렸는가
        self.refresh = refresh  # HTTP `Refresh` 헤더(브라우저가 지연 이동에 쓴다)


# ── 실제 네트워크 ────────────────────────────────────────────────
def _decoder(encoding: str):
    enc = (encoding or "").strip().lower()
    if enc in ("", "identity"):
        return None
    if enc in ("gzip", "x-gzip"):
        return zlib.decompressobj(16 + zlib.MAX_WBITS)
    if enc == "deflate":
        return zlib.decompressobj()
    raise FetchError(f"UnsupportedContentEncoding: {enc[:30]}")  # br·zstd 등은 풀지 않는다(분석 불가)


def _read_bounded(chunks, encoding: str = "") -> tuple[bytes, bool]:
    """원본 조각을 읽어 (본문, 잘렸는가)를 돌려준다. 입력·출력 모두 MAX_BODY를 넘지 않게 자른다.

    압축은 스트림 하나가 끝난 뒤에 데이터가 더 붙어 있으면(이어 붙인 gzip 멤버 등) 오류로 처리한다. 브라우저마다
    뒤 멤버를 푸는지 달라서, 검사기가 본 앞부분과 브라우저가 보는 본문이 다를 수 있기 때문이다.
    스트림이 끝나지 않고 입력이 끊기면 본문이 다 오지 않은 것이므로 잘린 것으로 표시한다."""
    dec = _decoder(encoding)
    out = bytearray()
    raw_total = 0
    for chunk in chunks:
        raw_total += len(chunk)
        if raw_total > MAX_BODY:  # 압축된 상태의 입력도 한도를 둔다
            return bytes(out), True
        if dec is None:
            room = MAX_BODY - len(out)
            out += chunk[:room]
            if len(chunk) > room or len(out) >= MAX_BODY:
                return bytes(out), True
            continue
        if dec.eof and chunk:
            raise FetchError("DecodeError: trailing data after compressed stream")
        data = chunk
        while data:
            room = MAX_BODY - len(out)
            if room <= 0:
                return bytes(out), True
            try:
                out += dec.decompress(data, room)
            except zlib.error as e:
                raise FetchError(f"DecodeError: {e}"[:200]) from e
            if dec.eof and dec.unused_data:
                raise FetchError("DecodeError: trailing data after compressed stream")
            data = dec.unconsumed_tail  # 출력 한도 때문에 남은 입력
            if len(out) >= MAX_BODY and (data or not dec.eof):
                return bytes(out), True
    if dec is not None and not dec.eof:
        return bytes(out), True  # 압축 스트림이 끝나기 전에 끊겼다
    return bytes(out), False


class HttpxFetcher:
    def __init__(self, timeout: float = TIMEOUT):
        import httpx  # 지연 import: 테스트·픽스처 모드에서는 필요 없음

        self._httpx = httpx
        self._client = httpx.Client(follow_redirects=False, timeout=timeout,
                                    headers={"User-Agent": MOBILE_UA, "Accept": "text/html,*/*;q=0.8",
                                             "Accept-Encoding": "gzip, deflate"})

    def get(self, url: str) -> Response:
        httpx = self._httpx
        try:
            with self._client.stream("GET", url) as r:
                # iter_bytes()는 압축을 푼 뒤의 조각을 돌려줘 한도를 넘는 메모리가 먼저 잡힐 수 있다(압축 폭탄).
                # 원본 바이트를 직접 풀면서 출력 크기를 MAX_BODY로 막는다.
                body, truncated = _read_bounded(r.iter_raw(), r.headers.get("content-encoding", ""))
                return Response(r.status_code, r.headers.get("location"), body,
                                r.headers.get("content-type", ""), truncated, r.headers.get("refresh"))
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
        return Response(int(rec.get("status", 200)), rec.get("location"), body, "text/html",
                        refresh=rec.get("refresh"))

    def close(self) -> None:
        pass


# ── 추적 본체 ────────────────────────────────────────────────────
def _refresh_navigates(value: str | None) -> bool:
    """`Refresh` 헤더가 숫자(제자리 새로고침)가 아닌 내용을 담고 있으면 다른 주소로 이동시킬 수 있다고 본다."""
    v = (value or "").strip()
    return bool(v) and not v.replace(".", "", 1).isdigit()


def fetch_chain(url: str, fetcher, max_hops: int = MAX_HOPS) -> tuple[dict, bytes]:
    chain: list[dict] = []
    html = b""
    truncated = False
    final_type = ""
    redirect_html, redirect_truncated = b"", False  # 가장 최근 이동 응답의 본문(최종 응답을 못 얻었을 때만 쓴다)
    got_final = False
    current, _ = normalize_url(url)  # 브라우저가 여는 주소와 같은 곳에 접속한다
    first_error = None
    tls_verified: bool | None = None

    for _hop in range(max_hops + 1):
        p = parse_url(current)
        entry = {
            "url": current[:500],
            "url_sha256": hashlib.sha256(current.encode("utf-8", "surrogatepass")).hexdigest(),  # 표시용으로 자르기 전의 전체 주소
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
        entry["refresh"] = _refresh_navigates(resp.refresh)  # `Refresh` 헤더가 다른 주소로의 지연 이동일 수 있는가
        if current.startswith("https://") and tls_verified is None:
            tls_verified = True
        if 300 <= resp.status < 400 and resp.location:
            # 이동 응답의 본문은 최종 페이지가 아니다. 최종 응답을 얻으면 버리고, 차단·오류로 끊겼을 때만 보여 주는 용도로 쓴다.
            if resp.body and ("html" in (resp.content_type or "").lower() or not resp.content_type):
                redirect_html, redirect_truncated = resp.body, resp.truncated
            else:
                redirect_html, redirect_truncated = b"", False
            current, _ = normalize_url(resolve_reference(current, resp.location))
            continue
        got_final = True
        final_type = resp.content_type or ""
        if resp.body and ("html" in final_type.lower() or not final_type):
            html, truncated = resp.body, resp.truncated
        break

    if not got_final:  # 차단·오류·이동 횟수 한도로 끝났다: 마지막 이동 응답의 본문이 있는 그대로가 유일한 페이지 자료다
        html, truncated = redirect_html, redirect_truncated

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
        "html_from_redirect": bool(html) and not got_final,
        "final_content_type": final_type[:100],
        "body_truncated": truncated,
        "first_error": first_error,
    }
    return result, html
