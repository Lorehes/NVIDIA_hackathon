"""Source-backed identities, separated from domain families and page safety.

Only sourced, fresh, exact address scopes identify an institution. A family
match is useful context, never an ownership grant for all subdomains.
"""
from collections import defaultdict
from datetime import date, datetime, timezone
from functools import lru_cache
import json
from pathlib import Path
from urllib.parse import urlsplit

from .urls import parse_url


def same_service_port(left, right):
    """Default web ports may share a host identity; other services stay exact."""
    try:
        a, b = urlsplit(left), urlsplit(right)
        if a.scheme not in ('http', 'https') or b.scheme not in ('http', 'https'):
            return False
        if a.port in (None, 80, 443) and b.port in (None, 80, 443):
            return True
        return (a.scheme, a.port) == (b.scheme, b.port)
    except ValueError:
        return False


class SiteCatalog:
    def __init__(self, records):
        self.by_host = defaultdict(list)
        self.by_family = defaultdict(list)
        self.by_id = {}
        for record in records:
            self.by_host[record['host']].append(record)
            self.by_family[record['family']].append(record)
            self.by_id[record['id']] = record

    @staticmethod
    def fresh(record, today=None):
        try:
            if record.get('expires_at') and datetime.fromisoformat(record['expires_at']) <= datetime.now(timezone.utc):
                return False
            age = ((today or datetime.now(timezone.utc).date()) - date.fromisoformat(record['checked'])).days
            return 0 <= age <= 90
        except (ValueError, KeyError, TypeError):
            return False

    def lookup_all(self, url):
        parsed = parse_url(url)
        if not parsed.get('ok'):
            return []
        absolute = url if '://' in url else 'https://' + url
        sp = urlsplit(absolute)
        records = self.by_host.get(parsed['host_ascii'], [])
        matches = [r for r in records if same_service_port(r['url'], absolute) and (r['scope'] == 'host' or
                   ((urlsplit(r['url']).path or '/') == (sp.path or '/') and urlsplit(r['url']).query == sp.query))]
        matches.sort(key=lambda r: (not (r['verified'] and self.fresh(r)),
                                    r.get('evidence_type') == 'publisher_home_redirect', r['id']))
        return matches

    def lookup(self, url):
        matches = self.lookup_all(url)
        return matches[0] if matches else None

    def name_matches(self, text, limit=3):
        norm = ''.join(text.lower().split())
        found = [r for r in self.by_id.values() if r['verified'] and self.fresh(r) and len(r['name']) >= 3
                 and ''.join(r['name'].lower().split()) in norm]
        found.sort(key=lambda r: (-len(r['name']), r['id']))
        return found[:limit]

    def related_hosts(self, matches):
        """Only explicit, fresh home redirects relate hosts; a PSL family does not.

        School/tenant addresses can share one registered domain with unrelated
        institutions. An edge must still have its fresh source homepage present.
        This display metadata never changes lookup scopes or egress permissions.
        """
        verified = [r for r in matches if r['verified'] and self.fresh(r)]
        ids = {r['id'] for r in verified}
        hosts = {r['host'] for r in verified}
        for family in {r['family'] for r in verified}:
            for edge in self.by_family.get(family, []):
                if (not edge['verified'] or not self.fresh(edge) or edge.get('scope') != 'url'
                        or edge.get('evidence_type') != 'publisher_home_redirect' or not edge.get('canonical_from')
                        or not edge.get('expires_at')):
                    continue
                origins = [r for r in self.lookup_all(edge['canonical_from']) if r['verified'] and self.fresh(r)
                           and r.get('scope') == 'url' and r.get('source') == edge.get('source')
                           and r.get('evidence_type') != 'publisher_home_redirect']
                if origins and (edge['id'] in ids or any(r['id'] in ids for r in origins)):
                    hosts.add(edge['host'])
                    hosts.update(r['host'] for r in origins)
        return sorted(hosts)[:20]

    def describe(self, url):
        p = parse_url(url)
        matches = self.lookup_all(url)
        r = matches[0] if matches else None
        fresh = bool(r and self.fresh(r))
        # Several institutions may publish the same homepage. Show each name
        # without extending any institution's URL scope or merging identities.
        entities = {}
        for match in matches:
            if match['verified'] and self.fresh(match) and match['name'] not in entities:
                entities[match['name']] = {k: match[k] for k in ('id', 'name', 'source', 'checked')}
        return {'host': p.get('host_ascii'), 'site_family': p.get('registrable_domain'),
                'status': 'verified' if r and r['verified'] and fresh else 'unverified',
                'name': r['name'] if r else None,
                'source': r['source'] if r else None, 'checked': r['checked'] if r else None,
                'canonical_from': r.get('canonical_from') if r else None,
                'expires_at': r.get('expires_at') if r else None,
                'inspection_supported': r.get('inspection_supported', True) if r else None,
                'inspection_limit_reason': r.get('inspection_limit_reason') if r else None,
                'reason': (r.get('evidence_type', 'official_directory') if r['verified'] else 'popularity_only') if fresh else
                          'source_expired' if r else 'no_identity_evidence',
                'matched_entities': list(entities.values())[:20], 'matched_entities_total': len(entities),
                'related_addresses': self.related_hosts(matches)}


@lru_cache(maxsize=2)
def _load(path, modified):
    return SiteCatalog(json.loads(Path(path).read_text())['records'])


def load_catalog(path):
    path = Path(path)
    return _load(str(path), path.stat().st_mtime_ns) if path.exists() else SiteCatalog([])
