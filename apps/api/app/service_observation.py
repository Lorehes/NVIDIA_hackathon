"""Exact, investigation-local identity from a sourced service's HTTP redirects.

Never persist destination queries as reusable catalog evidence, grant a whole
host, accept user-controlled entry queries, or infer identity from TLS alone.
"""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from urllib.parse import urlsplit

from checklib.parse_url import normalize_url, parse_url


def within_service_path(initial, destination):
    """A directory's fixed non-root entry may redirect within its own path.

    This checks one observed URL, never grants a path prefix to other URLs.
    Ambiguous/encoded paths and queries need separate evidence.
    """
    start, end = urlsplit(initial), urlsplit(destination)
    prefix = start.path.rstrip('/')
    if not prefix or start.query or start.fragment or end.query or end.fragment:
        return False
    for path in (start.path, end.path):
        if ('%' in path or ';' in path or '\\' in path or '//' in path
                or any(part in ('.', '..') for part in path.split('/'))):
            return False
    return (start.hostname == end.hostname and start.scheme == end.scheme == 'https'
            and start.port in (None, 443) and end.port in (None, 443)
            and (end.path.rstrip('/') == prefix or end.path.startswith(prefix + '/')))


def observed_service_destination(kb, fetch, input_url):
    if (not input_url or not fetch or fetch.get('ok') is not True or fetch.get('skipped')
            or (fetch.get('tls') or {}).get('verified') is not True):
        return None
    chain = fetch.get('chain') or []
    if not 2 <= len(chain) <= 6 or fetch.get('final_url') != chain[-1].get('url'):
        return None
    initial = chain[0].get('url', '')
    if normalize_url(input_url)[0].rstrip('/') != initial.rstrip('/'):
        return None
    kb.refresh_catalog()
    source = kb.catalog.lookup(initial)
    if (not source or not source['verified'] or not kb.catalog.fresh(source)
            or source.get('kind') != 'official_service_directory'
            or source.get('evidence_type') != 'publisher_service_link'):
        return None
    # An old directory cannot gain a fresh identity by being observed again.
    if (datetime.now(timezone.utc).date() - datetime.fromisoformat(source['checked']).date()).days > 7:
        return None
    if urlsplit(initial).query:
        return None
    path_entry = urlsplit(initial).path not in ('', '/')
    if path_entry and normalize_url(source['url'])[0] != normalize_url(initial)[0]:
        # A host-scoped record must not turn an arbitrary deep link into the
        # directory's fixed entry point for new redirect evidence.
        return None
    family = source['family']
    for i, hop in enumerate(chain):
        url = hop.get('url', '')
        parsed = parse_url(url)
        parts = urlsplit(url)
        if (not parsed.get('ok') or parsed.get('ambiguous') or parsed.get('has_userinfo')
                or parsed.get('is_ip_host') or parsed.get('registrable_domain') != family
                or parts.scheme != 'https' or parts.port not in (None, 443)
                or (not within_service_path(initial, url) if path_entry else parts.path not in ('', '/'))
                or parts.fragment
                or hop.get('blocked') or hop.get('error') or hop.get('refresh')):
            return None
        # Display URLs may be truncated. Do not derive identity from a prefix.
        if hop.get('url_sha256') != hashlib.sha256(url.encode('utf-8', 'surrogatepass')).hexdigest():
            return None
        status = hop.get('status')
        if i < len(chain) - 1:
            if status not in (301, 302, 303, 307, 308):
                return None
        elif not isinstance(status, int) or not (200 <= status < 300 or status in (401, 403, 429)):
            return None
        # Do not cross a known independently named tenant/service boundary.
        if i and any(r['verified'] and kb.catalog.fresh(r) and r['name'] != source['name']
                     for r in kb.catalog.by_host.get(parsed['host_ascii'], [])):
            return None
    destination = chain[-1]['url']
    host = parse_url(destination)['host_ascii']
    entity = kb._catalog_entity(source)
    return replace(entity, id=entity.id + '_observed_' + hashlib.sha256(destination.encode()).hexdigest()[:16],
                   official_domains=[host], address_scope='url', source_url=destination,
                   observed_from=initial)
