from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import pytest
from app.kb import KB
from app.site_catalog import SiteCatalog
from app.verdict import Evidence, decide
from app.presentation import build_explanation, build_comparison
from checklib.parse_url import parse_url
from checklib.similarity import compare
from checklib.inspect_page import inspect_page

ENTRY = 'https://school.example/old/'
FINAL = 'https://school.example/new/'


def evidence(final=FINAL):
    row = {'id':'school', 'name':'학교', 'host':'school.example', 'family':'school.example',
           'url':ENTRY, 'scope':'url', 'verified':True, 'kind':'school',
           'source':'https://directory.example/', 'checked':datetime.now(timezone.utc).date().isoformat()}
    kb = KB([], SiteCatalog([row]))
    fetch = {'ok':True, 'chain':[{**parse_url(u), 'status':s} for u,s in [(ENTRY,301),(final,200)]],
             'final_url':final, 'final_registrable_domain':parse_url(final)['registrable_domain'], 'tls':{'verified':True}}
    ev = Evidence(parse=parse_url(ENTRY), input_url=ENTRY, address_only=True, fetch=fetch,
                  page=inspect_page(b'<p>hello</p>', final), candidates=kb.address_candidates(ENTRY),
                  similarity=compare(parse_url(ENTRY), []))
    return kb, ev


def test_sourced_entry_is_not_a_claim_about_an_unlisted_path():
    kb, ev = evidence()
    out = decide(ev, kb)
    assert out.verdict == 'unknown' and out.unknown_reason == 'destination_unverified'
    assert 'domain_not_official' not in {s['type'] for s in out.signals}
    assert out.entity is not None
    info = kb.identity_summary(FINAL, out, ENTRY)
    assert info['status'] == 'unverified' and info['source_address']['name'] == '학교'
    assert info['source_address']['source'] == 'https://directory.example/'
    assert kb.address_candidates(FINAL) == []
    ex = build_explanation(out, ev.page, 'school.example', None, False)
    assert '이동한 주소는 아직 미확인' in ex['headline'] and ex['suspicion_evidence'] == []
    comp = build_comparison(out, ev.page, ev.fetch, ev.parse, None, False)
    assert comp[0]['status'] == 'unknown' and comp[0]['said'] == '링크만 입력했어요'


def test_explicit_claim_still_checks_final_address_against_claimed_institution():
    kb, ev = evidence()
    ev.address_only = False
    ev.candidates = [(ev.candidates[0][0], 'exact')]
    out = decide(ev, kb)
    assert out.verdict == 'caution' and 'domain_not_official' in {s['type'] for s in out.signals}


@pytest.mark.parametrize('risk', ['cross_family', 'password', 'other_tenant', 'apk'])
def test_missing_destination_evidence_never_suppresses_observed_risk(risk):
    kb, ev = evidence('https://other.example/' if risk == 'cross_family' else FINAL)
    html = {'password':b'<form action="https://other.example/" method="post"><input type="password"></form>',
            'other_tenant':b'<form action="https://school.example/tenant/" method="post"><input name="q"></form>',
            'apk':b'<a href="https://other.example/install.apk">Install</a>'}
    if risk in html: ev.page = inspect_page(html[risk], FINAL)
    out = decide(ev, kb)
    expected = {'cross_family':'redirect_other_domain','password':'credential_form',
                'other_tenant':'cross_domain_form','apk':'apk_download'}[risk]
    assert expected in {s['type'] for s in out.signals}
    assert out.verdict in ('caution', 'suspected_impersonation')
    assert kb.identity_summary(ev.fetch['final_url'], out, ENTRY)['status'] == 'unverified'


def test_stale_and_popularity_entries_do_not_get_verified_start_label():
    for changes in ({'verified':False}, {'checked':'2020-01-01'}):
        kb, ev = evidence()
        kb.catalog.by_id['school'].update(changes)
        assert 'source_address' not in kb.identity_summary(FINAL, decide(ev,kb), ENTRY)


def test_independently_listed_destination_does_not_make_http_hop_safe():
    kb, ev = evidence()
    row = deepcopy(kb.catalog.by_id['school'])
    kb.catalog = SiteCatalog([row, {**row, 'id':'new', 'name':'새 목록', 'url':FINAL}])
    ev.fetch['chain'].insert(1, {**parse_url('http://school.example/new/'), 'status':301})
    out = decide(ev,kb)
    assert out.verdict == 'unknown' and 'not_https' in out.verification_gaps
    assert kb.identity_summary(FINAL,out,ENTRY)['status'] == 'verified'
    explanation = build_explanation(out,ev.page,'school.example',None,False)
    assert 'HTTP' in explanation['detail']
    assert '1~2분' not in explanation['recommended_action']
    assert any('HTTP' in b for b in explanation['action_bullets'])


def test_reviewed_navigation_selector_does_not_collect_other_links():
    root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location('navigation_collector',root/'scripts/catalog/collect_services.py')
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    config = {'name':'Publisher','url':'https://publisher.example/','link_href':'/games/',
              'service_name':'제작 게임 목록','scope':'url'}
    rows = collector.extract_services('<a href="/games/">Games</a><a href="/games/">Again</a>'
                                     '<a href="/games/?user=1">Other</a><a href="https://ad.example/">Ad</a>',config)
    assert len(rows)==1 and rows[0]['url']=='https://publisher.example/games/' and rows[0]['scope']=='url'


def test_reviewed_current_game_listing_matches_default_port_only_and_exact_path():
    kb = KB.load()
    for url in ['https://www.nhn-playart.com/game/', 'https://www.nhn-playart.com:443/game/']:
        info = kb.catalog.describe(url)
        assert info['status'] == 'verified' and info['name'] == 'NHN PlayArt 제작 게임 목록'
        assert info['source'] == 'https://www.nhn-playart.com/'
    for url in ['https://www.nhn-playart.com/game/unlisted/', 'https://www.nhn-playart.com/game/?tenant=1',
                'https://www.nhn-playart.com:444/game/']:
        assert kb.catalog.describe(url)['status'] == 'unverified'
