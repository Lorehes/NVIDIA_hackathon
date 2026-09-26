"""Observe canonical home redirects starting only at sourced service homepages.

No user-provided URLs, wildcard ownership, JS execution or reverse inference.
Resolve each destination, connect to that public IP, and verify TLS for the
original hostname. Store only root-to-root HTTPS redirects within a PSL family.
"""
from concurrent.futures import ThreadPoolExecutor
import argparse
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'sandbox/skills/phishing-investigator/scripts'))
from checklib.navigation import resolve_public_destination
from checklib.parse_url import normalize_url, parse_url, resolve_reference
from checklib.fetch_chain import MOBILE_UA


def eligible(url, family):
    p = parse_url(url)
    sp = urlsplit(url)
    return (p.get('ok') and not p.get('ambiguous') and not p.get('has_userinfo')
            and not p.get('is_ip_host') and sp.scheme == 'https' and sp.port in (None, 443)
            and p.get('registrable_domain') == family and sp.path in ('', '/')
            and not sp.query and not sp.fragment)


def pinned_headers(url):
    host, addresses = resolve_public_destination(url)
    # Only headers are needed; close the response without downloading/executing a page.
    last_error = None
    for address in addresses[:3]:
        try:
            with httpx.Client(timeout=8, follow_redirects=False, trust_env=False) as client:
                with client.stream('GET', httpx.URL(url).copy_with(host=address),
                                   headers={'Host': host, 'User-Agent': MOBILE_UA},
                                   extensions={'sni_hostname': host}) as response:
                    return response.status_code, response.headers.get('location')
        except httpx.HTTPError as exc:
            last_error = exc
    raise last_error or ValueError('dns_unresolved')


def observe(row, get_headers=pinned_headers):
    family = parse_url(row['url']).get('registrable_domain')
    if not eligible(row['url'], family):
        return []
    initial = normalize_url(row['url'])[0]
    current, chain, visited = initial, [], set()
    for _ in range(4):
        if current in visited:
            return []
        visited.add(current)
        status, location = get_headers(current)
        chain.append({'url': current, 'status': status})
        # A source-backed redirect can identify its destination even when that
        # destination denies this client. Access denial is NOT page verification.
        if 200 <= status < 300 or status in (401, 403, 429):
            if len(chain) < 2:
                return []
            # The official source's observed destination applies to this exact homepage.
            return [{**row, 'url': current, 'scope': 'url', 'canonical_from': initial,
                     'evidence_type': 'publisher_home_redirect', 'redirect_chain': chain,
                     'page_access_confirmed': 200 <= status < 300,
                     'expires_at': (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}]
        if status not in (301, 302, 303, 307, 308) or not location:
            return []
        current = normalize_url(resolve_reference(current, location))[0]
        if not eligible(current, family):
            return []
    return []


def require_fresh_sources(rows, fallback_checked, today=None):
    today = today or datetime.now(timezone.utc).date()
    if any((today - date.fromisoformat(r.get('checked', fallback_checked))).days not in range(8)
           for r in rows):
        raise ValueError('refresh selected official service sources first')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', help='Refresh only one publisher URL already present in official_services.json')
    args = parser.parse_args()
    directory = ROOT / 'kb/sources'
    data = json.loads((directory / 'official_services.json').read_text())
    selected = [r for r in data['records'] if not args.source or r['source'] == args.source]
    if not selected:
        raise ValueError('publisher source not present in official snapshot')
    require_fresh_sources(selected, data['checked'])
    rows = list({r['url']: r for r in selected}.values())
    def one(row):
        try:
            return observe(row), None
        except (httpx.HTTPError, ValueError, OSError) as exc:
            return [], {'url': row['url'], 'error': type(exc).__name__}
    found, failed = [], []
    with ThreadPoolExecutor(max_workers=3) as pool:
        for records, error in pool.map(one, rows):
            found.extend(records)
            if error:
                failed.append(error)
    target = directory / 'service_redirects.json'
    if args.source and target.exists():
        previous = json.loads(target.read_text())
        found = [r for r in previous['records'] if r['source'] != args.source] + found
        selected_urls = {r['url'] for r in rows}
        failed = [r for r in previous.get('unconfirmed', []) if r['url'] not in selected_urls] + failed
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps({'checked': datetime.now(timezone.utc).date().isoformat(), 'records': found,
                                      'unconfirmed': failed}, ensure_ascii=False, indent=2))
    temporary.replace(target)
    print('canonical service homes:', len(found), 'unconfirmed:', len(failed))


if __name__ == '__main__':
    main()
