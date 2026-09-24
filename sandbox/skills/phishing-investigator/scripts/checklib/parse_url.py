"""3-1. URL 분해: 스킴·호스트·경로, IDNA, 등록 도메인(registrable domain) 추출.

네트워크에 접속하지 않는다. tldextract가 있으면 내장 Public Suffix 목록만 쓰고,
없으면 보수적인 내장 규칙으로 대체한다.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import parse_qsl, urlsplit

# tldextract가 없을 때 쓰는 다단계 공개 접미사(자주 쓰는 것만)
_FALLBACK_MULTI_SUFFIXES = {
    "co.kr", "or.kr", "go.kr", "ac.kr", "re.kr", "ne.kr", "pe.kr", "hs.kr", "ms.kr", "es.kr",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "or.jp",
    "ne.jp", "com.cn", "com.br", "co.nz", "co.in", "com.sg", "com.hk", "com.tw",
}

_extractor = None
_extractor_failed = False


def _get_extractor():
    global _extractor, _extractor_failed
    if _extractor is not None or _extractor_failed:
        return _extractor
    try:
        import tldextract  # type: ignore

        _extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    except Exception:  # noqa: BLE001 - 라이브러리 부재·초기화 실패 모두 대체 경로로
        _extractor_failed = True
        _extractor = None
    return _extractor


def split_host(host_ascii: str) -> tuple[list[str], str, str]:
    """(서브도메인 라벨들, 등록 도메인 라벨, 공개 접미사)를 돌려준다."""
    host_ascii = host_ascii.strip(".").lower()
    ext = _get_extractor()
    if ext is not None:
        r = ext(host_ascii)
        if r.domain and r.suffix:
            subs = [s for s in r.subdomain.split(".") if s] if r.subdomain else []
            return subs, r.domain, r.suffix
    labels = host_ascii.split(".")
    if len(labels) < 2:
        return [], host_ascii, ""
    last2 = ".".join(labels[-2:])
    if last2 in _FALLBACK_MULTI_SUFFIXES and len(labels) >= 3:
        return labels[:-3], labels[-3], last2
    return labels[:-2], labels[-2], labels[-1]


def registrable_of(host_ascii: str) -> str:
    _, domain, suffix = split_host(host_ascii)
    return f"{domain}.{suffix}" if suffix else domain


def to_ascii_host(host: str) -> str:
    host = host.strip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def to_unicode_host(host_ascii: str) -> str:
    try:
        return host_ascii.encode("ascii").decode("idna")
    except UnicodeError:
        return host_ascii


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def parse_url(url: str) -> dict:
    raw = (url or "").strip()
    if "://" not in raw:
        raw = "https://" + raw
    try:
        sp = urlsplit(raw)
        host = sp.hostname or ""
        port = sp.port
    except ValueError as e:
        return {"ok": False, "error": f"invalid url: {e}"}
    if not host:
        return {"ok": False, "error": "no host"}

    has_userinfo = "@" in sp.netloc
    userinfo = sp.netloc.rsplit("@", 1)[0] if has_userinfo else ""
    host_ascii = to_ascii_host(host)
    host_unicode = to_unicode_host(host_ascii)
    is_ip = _is_ip(host_ascii)

    if is_ip:
        subs, dom_label, suffix = [], host_ascii, ""
        registrable = host_ascii
    else:
        subs, dom_label, suffix = split_host(host_ascii)
        registrable = f"{dom_label}.{suffix}" if suffix else dom_label

    return {
        "ok": True,
        "scheme": sp.scheme.lower(),
        "host_unicode": host_unicode,
        "host_ascii": host_ascii,
        "registrable_domain": registrable,
        "registrable_domain_unicode": to_unicode_host(registrable),
        "domain_label": dom_label,
        "domain_label_unicode": to_unicode_host(dom_label),
        "suffix": suffix,
        "subdomain_labels": subs,
        "path": (sp.path or "/") + (("?" + sp.query) if sp.query else ""),
        "query_keys": [k for k, _ in parse_qsl(sp.query, keep_blank_values=True)][:20],
        "is_ip_host": is_ip,
        "has_userinfo": has_userinfo,
        "userinfo": userinfo[:60],
        "port": port,
    }
