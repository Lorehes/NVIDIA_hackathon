"""Bounded navigation aliases, never a wildcard or an assertion of site trust."""
from __future__ import annotations

import ipaddress
import re
import socket
from functools import lru_cache
from urllib.parse import urlsplit


def resolve_public_destination(url: str, resolver=None) -> tuple[str, list[str]]:
    """Validate each requested destination, independently of identity/trust lists.

    DNS failure and mixed public/private answers fail closed. This preflight
    supplements (does not replace) the egress proxy's connection-time boundary.
    """
    from .parse_url import parse_url
    parsed = parse_url(url)
    if not parsed.get('ok') or parsed.get('ambiguous') or parsed.get('has_userinfo'):
        raise ValueError('ambiguous_destination')
    host = parsed['host_ascii']
    sp = urlsplit(url)
    if sp.scheme not in ('http', 'https') or sp.port not in (None, 80, 443):
        raise ValueError('unsupported_destination')
    if parsed.get('is_ip_host') or '.' not in host or host.endswith(
        ('.local', '.internal', '.localhost', '.lan', '.home', '.corp', '.intranet')):
        raise ValueError('private_destination')
    try:
        infos = (resolver or socket.getaddrinfo)(host, sp.port or (443 if sp.scheme == 'https' else 80),
                                                type=socket.SOCK_STREAM)
        addresses = [ipaddress.ip_address(i[4][0].split('%')[0]) for i in infos]
        if not addresses:
            raise ValueError('dns_unresolved')
        for address in addresses:
            address = getattr(address, 'ipv4_mapped', None) or address
            if not address.is_global or address.is_multicast:
                raise ValueError('private_destination')
    except OSError as exc:
        raise ValueError('dns_unresolved') from exc
    return host, sorted({str(a) for a in addresses})


def public_destination(url: str, resolver=None) -> str:
    return resolve_public_destination(url, resolver)[0]


@lru_cache(maxsize=1024)
def navigation_hosts(host: str) -> tuple[str, ...]:
    """Allow apex/www/m for public registrable domains; keep all other hosts exact.

    Private hosting suffixes (github.io, blogspot.com, etc.) and unknown suffixes
    do not gain aliases. Missing PSL support also keeps the original host only.
    """
    original = (host,)
    if not re.fullmatch(r"[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?", host) or ".." in host:
        return original
    try:
        ipaddress.ip_address(host)
        return original
    except ValueError:
        pass
    try:
        import tldextract
        ext = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                   include_psl_private_domains=True)(host)
    except Exception:
        return original
    if not ext.domain or not ext.suffix or ext.is_private:
        return original
    root = f"{ext.domain}.{ext.suffix}"
    aliases = (root, f"www.{root}", f"m.{root}")
    if host not in aliases:
        return original
    return (host,) + tuple(h for h in aliases if h != host)
