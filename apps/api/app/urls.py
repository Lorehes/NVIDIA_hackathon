"""입력에서 URL 추출(F1)과 호스트 측 문자열 파싱. 네트워크에 접속하지 않는다."""
from __future__ import annotations

import ipaddress
import re
import sys

from .config import settings

# 검사 라이브러리는 sandbox/ 한 곳에만 두고, 호스트도 같은 코드로 문자열 파싱만 한다.
_scripts = str(settings.scripts_dir)
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from checklib.parse_url import parse_url  # noqa: E402

MAX_INPUT = 2000
_URL_RE = re.compile(r"https?://[^\s<>\"'`　]+", re.I)
_BARE_RE = re.compile(r"^(?:[a-z0-9¡-￿-]+\.)+[a-z¡-￿]{2,}(?::\d+)?(?:[/?#]\S*)?$", re.I)
_TRAIL = ".,;:!?)]}>'\""
_HANGUL = re.compile(r"[가-힣ㄱ-ㆎ]")


def _clean(url: str) -> str:
    # 경로·쿼리에 붙은 한글 조사("…/login으로")는 잘라낸다. 호스트 부분의 한글(IDN)은 유지한다.
    m = re.match(r"^(https?://[^/?#]*)(.*)$", url, re.I | re.S)
    if m:
        host_part, rest = m.groups()
        h = _HANGUL.search(rest)
        if h:
            rest = rest[: h.start()]
        url = host_part + rest
    while url and url[-1] in _TRAIL:
        url = url[:-1]
    return url


def extract_urls(text: str) -> list[str]:
    """본문에서 URL을 순서대로(중복 제거) 뽑는다. 입력 전체가 도메인 하나뿐이면 그것도 URL로 본다."""
    text = (text or "").strip()
    found: list[str] = []
    for m in _URL_RE.finditer(text):
        u = _clean(m.group(0))
        if u and u not in found and parse_url(u).get("ok"):
            found.append(u)
    if not found and " " not in text and _BARE_RE.match(text):
        u = "https://" + _clean(text)
        if parse_url(u).get("ok"):
            found.append(u)
    return found


def input_kind(text: str, urls: list[str]) -> str:
    t = text.strip()
    return "url" if len(urls) == 1 and (t == urls[0] or "https://" + t == urls[0]) else "message"


def is_private_or_ip_host(host_ascii: str) -> bool:
    """조사용 정책을 만들면 안 되는 호스트(IP, 사설, 로컬, 점 없는 이름)인지 문자열만으로 판단."""
    h = host_ascii.strip("[]").lower()
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    if "." not in h or h == "localhost":
        return True
    return h.endswith((".local", ".internal", ".localhost", ".lan", ".home", ".corp", ".intranet"))


_HOST_OK = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


def safe_host_for_policy(host_ascii: str) -> bool:
    """프리셋 YAML에 넣어도 되는 호스트 문자열인가(주입 방지)."""
    return bool(_HOST_OK.match(host_ascii)) and ".." not in host_ascii
