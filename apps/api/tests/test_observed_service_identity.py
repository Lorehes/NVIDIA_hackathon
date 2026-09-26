from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib

import pytest

from app.kb import KB
from app.site_catalog import SiteCatalog
from app.service_observation import observed_service_destination
from app.verdict import Evidence, decide
from checklib.parse_url import parse_url
from checklib.similarity import compare
from checklib.inspect_page import inspect_page

ENTRY = 'https://www.service.example/'
FINAL = 'https://m.service.example?display=mobile'


def fixture():
    r = {'id': 'service', 'name': '공식 서비스', 'host': 'www.service.example', 'family': 'service.example',
         'url': ENTRY, 'scope': 'url', 'verified': True, 'kind': 'official_service_directory',
         'evidence_type': 'publisher_service_link', 'checked': datetime.now(timezone.utc).date().isoformat(),
         'source': 'https://corp.example/services'}
    fetch = {'ok': True, 'tls': {'verified': True}, 'final_url': FINAL,
             'final_registrable_domain': 'service.example', 'chain': [
                 {'url': u, 'url_sha256': hashlib.sha256(u.encode()).hexdigest(), 'status': status}
                 for u, status in [(ENTRY, 302), (FINAL, 200)]]}
    return KB([], SiteCatalog([r])), fetch


def test_observed_query_identity_is_exact_and_not_added_to_reusable_catalog():
    kb, fetch = fixture()
    entity = observed_service_destination(kb, fetch, ENTRY)
    assert entity.identity_verified and entity.matches('m.service.example', FINAL)
    for other in ['https://m.service.example/', 'https://m.service.example?display=other',
                  'https://m.service.example/login', 'https://customer.service.example/']:
        assert not entity.matches(parse_url(other)['host_ascii'], other)
    assert kb.address_candidates(FINAL) == []
    assert entity.id not in kb.by_id and len(kb.catalog.by_id) == 1


@pytest.mark.parametrize('change', ['entry_query', 'school', 'affiliate', 'popular', 'old', 'http', 'cross_family',
                                  'path', 'blocked', 'bad_hash', 'refresh', 'bad_tls', 'terminal_500',
                                  'unrelated_entry', 'known_other_service'])
def test_unproven_or_independent_boundaries_do_not_derive_identity(change):
    kb, fetch = fixture()
    source = kb.catalog.by_id['service']
    entry = ENTRY
    if change == 'entry_query':
        entry = ENTRY + '?next=target'
        fetch['chain'][0]['url'] = entry
        fetch['chain'][0]['url_sha256'] = hashlib.sha256(entry.encode()).hexdigest()
    elif change == 'school': source['kind'] = 'school'
    elif change == 'affiliate':
        source['kind'] = 'official_affiliate_directory'
        source['evidence_type'] = 'publisher_affiliate_link'
    elif change == 'popular': source['verified'] = False
    elif change == 'old': source['checked'] = (datetime.now(timezone.utc).date() - timedelta(days=8)).isoformat()
    elif change in ('http', 'cross_family', 'path'):
        url = {'http':'http://m.service.example/', 'cross_family':'https://elsewhere.example/',
               'path':'https://m.service.example/tenant/'}[change]
        fetch['final_url'] = fetch['chain'][-1]['url'] = url
        fetch['chain'][-1]['url_sha256'] = hashlib.sha256(url.encode()).hexdigest()
    elif change == 'blocked': fetch['chain'][-1]['blocked'] = True
    elif change == 'bad_hash': fetch['chain'][-1]['url_sha256'] = 'truncated-display-url'
    elif change == 'refresh': fetch['chain'][0]['refresh'] = True
    elif change == 'bad_tls': fetch['tls']['verified'] = False
    elif change == 'terminal_500': fetch['chain'][-1]['status'] = 500
    elif change == 'unrelated_entry': entry = 'https://unknown.example/'
    elif change == 'known_other_service':
        kb.catalog = SiteCatalog([source, {**source, 'id':'other', 'name':'다른 기관',
                                           'host':'m.service.example', 'url':'https://m.service.example/tenant/'}])
    assert observed_service_destination(kb, fetch, entry) is None


def test_same_page_form_is_not_foreign_but_behavior_and_tls_remain_independent():
    kb, fetch = fixture()
    p = parse_url(ENTRY)
    page = inspect_page(b'<form><input type="text" name="q"></form><script src="https://external.example/code.js"></script>', FINAL)
    ev = Evidence(parse=p, input_url=ENTRY, address_only=True, fetch=fetch, page=page,
                  candidates=kb.address_candidates(ENTRY), similarity=compare(p, []))
    result = decide(ev, kb)
    from app.models import ClaimedEntity
    ClaimedEntity.model_validate({'id': result.entity.id, 'name': result.entity.name,
                                 'source': result.entity_source})
    assert result.verdict == 'unknown'
    assert 'official_match' in {s['type'] for s in result.signals}
    assert 'cross_domain_form' not in {s['type'] for s in result.signals}
    summary = kb.identity_summary(FINAL, result)
    assert summary['status'] == 'verified' and summary['behavior'] == 'incomplete'
    assert summary['canonical_from'] == ENTRY and summary['evidence_scope'] == 'this_investigation'
    assert summary['source'] == 'https://corp.example/services'
    risky = deepcopy(ev)
    risky.page = inspect_page(b'<form action="https://other.example/"><input type=password></form>', FINAL)
    out = decide(risky, kb)
    assert out.verdict != 'safe' and 'cross_domain_form' in {s['type'] for s in out.signals}
