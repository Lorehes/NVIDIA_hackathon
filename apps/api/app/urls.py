"""입력에서 URL 추출(F1)과 호스트 측 문자열 파싱. 네트워크에 접속하지 않는다."""
from __future__ import annotations

import ipaddress
import re
import socket
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


def _clean_flagged(url: str) -> tuple[str, bool]:
    """(정리한 주소, 원문에서 무언가를 잘라 냈는가). 경로·쿼리에 붙은 한글 조사("…/login으로")나 문장 끝 부호
    ("…/login!", "…?a=b;")는 잘라내지만 실제로 주소의 일부일 수도 있다. 서버는 `/login`과 `/login!`을 다르게 다룰 수
    있으므로, 잘라 낸 경우에는 사용자가 뜻한 주소를 조사했는지 알 수 없다고 표시해 안전 판정에서 뺀다.
    호스트의 한글(IDN)은 유지한다."""
    trimmed = False
    m = re.match(r"^(https?://[^/?#]*)(.*)$", url, re.I | re.S)
    if m:
        host_part, rest = m.groups()
        h = _HANGUL.search(rest)
        if h:
            rest, trimmed = rest[: h.start()], True
        url = host_part + rest
    while url and url[-1] in _TRAIL:
        url, trimmed = url[:-1], True
    return url, trimmed


def _clean(url: str) -> str:
    return _clean_flagged(url)[0]


def trimmed_urls(text: str) -> set[str]:
    """본문에서 뒷부분을 잘라 낸 주소들(정리한 형태, `extract_urls`가 돌려주는 것과 같은 모양). 이 주소는 사용자가
    뜻한 주소와 다를 수 있다."""
    text = (text or "").strip()
    out: set[str] = set()
    found = False
    for m in _URL_RE.finditer(text):
        found = True
        u, trimmed = _clean_flagged(m.group(0))
        if trimmed and u:
            out.add(u)
    if not found and " " not in text and _BARE_RE.match(text):
        u, trimmed = _clean_flagged(text)
        if trimmed and u:
            out.add("https://" + u)
    return out


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


def _is_internal_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return True  # 해석할 수 없는 주소는 안전하다고 보지 않는다
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return not a.is_global or a.is_multicast


def resolves_to_internal(host_ascii: str, resolver=socket.getaddrinfo) -> bool:
    """이름이 사설·루프백·링크로컬 등 공용이 아닌 주소로 해석되는가. 해석하지 못하면 False(어차피 접속도 실패한다).

    조사 정책을 열기 직전의 사전 점검이다. 접속 시점의 DNS 재바인딩까지 막지는 못하므로 실제 접속을 맡는
    프록시 계층의 검사(검토 2.4)를 대체하지 않는다.
    """
    try:
        infos = resolver(host_ascii, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return False
    return any(_is_internal_ip(i[4][0]) for i in infos)


_HOST_OK = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


def safe_host_for_policy(host_ascii: str) -> bool:
    """프리셋 YAML에 넣어도 되는 호스트 문자열인가(주입 방지)."""
    return bool(_HOST_OK.match(host_ascii)) and ".." not in host_ascii
