import hashlib
import json
from copy import deepcopy

import pytest

from tests.test_observed_service_identity import fixture
from app.service_observation import observed_service_destination
from app.presentation import build_explanation
from app.verdict import Evidence, decide
from checklib.inspect_page import inspect_page
from checklib.parse_url import parse_url
from checklib.similarity import compare

ENTRY = 'https://www.service.example/ko'
FINAL = ENTRY + '/campaign'


def with_path(final=FINAL, initial=ENTRY):
    kb, fetch = fixture()
    kb.catalog.by_id['service']['url'] = initial
    fetch['final_url'] = final
    fetch['chain'] = [
        {'url': u, 'url_sha256': hashlib.sha256(u.encode()).hexdigest(), 'status': status}
        for u, status in [(initial, 302), (final, 200)]]
    return kb, fetch


def test_official_path_redirect_applies_only_to_exact_observed_destination():
    kb, fetch = with_path()
    entity = observed_service_destination(kb, fetch, ENTRY)
    assert entity and entity.matches('www.service.example', FINAL)
    for other in [ENTRY, FINAL + '/user', FINAL + '?next=elsewhere', ENTRY + '/another-campaign']:
        assert not entity.matches('www.service.example', other)
    assert kb.address_candidates(FINAL) == []
    assert len(kb.catalog.by_id) == 1
    # A later request without this evidence has no destination identity.
    assert observed_service_destination(kb, {}, FINAL) is None


def test_host_identity_does_not_substitute_for_exact_directory_entry():
    kb, fetch = with_path()
    source = kb.catalog.by_id['service']
    source.update(url='https://www.service.example/', scope='host')
    assert kb.catalog.lookup(ENTRY) is source
    assert observed_service_destination(kb, fetch, ENTRY) is None


@pytest.mark.parametrize('destination', [
    'https://www.service.example/ko-other/campaign', 'https://www.service.example/other',
    'https://www.service.example/', 'https://m.service.example/ko/campaign',
    'http://www.service.example/ko/campaign', 'https://www.service.example:444/ko/campaign',
    'https://www.service.example/ko/campaign?tenant=other', 'https://www.service.example/ko/campaign#hash',
    'https://www.service.example/ko/../other', 'https://www.service.example/ko/%2e%2e/other',
    'https://www.service.example/ko/%252e%252e/other', 'https://www.service.example/ko//other',
    'https://www.service.example/ko/..;x/other', 'https://www.service.example/ko/a%2fb',
    'https://user@www.service.example/ko/campaign', 'https://evil.example/ko/campaign',
])
def test_path_boundary_and_ambiguous_destinations_are_not_promoted(destination):
    kb, fetch = with_path(destination)
    assert observed_service_destination(kb, fetch, ENTRY) is None


@pytest.mark.parametrize('change', ['school', 'affiliate', 'shared_host', 'query_entry', 'bad_hash',
                                   'bad_tls', 'refresh', 'intermediate_escape'])
def test_only_reviewed_service_and_complete_in_boundary_chain_qualify(change):
    kb, fetch = with_path(); entry=ENTRY
    if change in ('school', 'affiliate'):
        kb.catalog.by_id['service']['kind'] = 'school' if change=='school' else 'official_affiliate_directory'
    if change == 'shared_host':
        row={**kb.catalog.by_id['service'], 'id':'another', 'name':'다른 서비스', 'url':ENTRY+'/tenant'}
        kb.catalog.by_host['www.service.example'].append(row)
    if change == 'query_entry':
        entry=ENTRY+'?next=campaign';kb,fetch=with_path(initial=entry)
    if change == 'bad_hash': fetch['chain'][-1]['url_sha256']='wrong'
    if change == 'bad_tls': fetch['tls']['verified']=False
    if change == 'refresh': fetch['chain'][0]['refresh']=True
    if change == 'intermediate_escape':
        url='https://www.service.example/other'
        fetch['chain'].insert(1, {'url':url,'url_sha256':hashlib.sha256(url.encode()).hexdigest(),'status':302})
    assert observed_service_destination(kb,fetch,entry) is None


def test_verified_event_identity_keeps_form_risk_and_no_sms_claim_for_url_input():
    kb, fetch = with_path()
    page=inspect_page(b'<form method=post action=/submit><input name=q></form>', FINAL)
    ev=Evidence(parse=parse_url(ENTRY),input_url=ENTRY,address_only=True,fetch=fetch,page=page,
                candidates=kb.address_candidates(ENTRY),similarity=compare(parse_url(ENTRY),[]))
    out=decide(ev,kb)
    assert out.verdict=='caution'
    assert kb.identity_summary(FINAL,out)['status']=='verified'
    assert {'official_match','cross_domain_form'} <= {s['type'] for s in out.signals}
    assert kb.identity_summary(FINAL,out)['evidence_scope']=='this_investigation'
    text=json.dumps(build_explanation(out,page,'service.example',None,False),ensure_ascii=False)
    assert '문자' not in text and '처리 경로는 미확인' in text
    risky=deepcopy(ev);risky.page=inspect_page(b'<form action="https://other.example/"><input type=password></form>',FINAL)
    bad=decide(risky,kb)
    assert bad.verdict!='safe' and 'cross_domain_form' in {s['type'] for s in bad.signals}


@pytest.mark.parametrize('message_given',[False,True])
def test_unverified_destination_does_not_invent_sms_context(message_given):
    kb,fetch=with_path('https://www.service.example/other')
    page=inspect_page(b'<form method=post action=/submit><input name=q></form>',fetch['final_url'])
    ev=Evidence(parse=parse_url(ENTRY),input_url=ENTRY,address_only=True,fetch=fetch,page=page,
                candidates=kb.address_candidates(ENTRY),similarity=compare(parse_url(ENTRY),[]))
    out=decide(ev,kb)
    assert out.verdict=='caution'
    explanation=build_explanation(out,page,'service.example',None,message_given)
    assert ('문자' in json.dumps(explanation,ensure_ascii=False)) == message_given


@pytest.mark.parametrize('verdict',['suspected_impersonation','safe','caution'])
@pytest.mark.parametrize('message_given',[False,True])
def test_explanation_sms_advice_requires_message_context(verdict,message_given):
    from app.verdict import Outcome
    kb,_=with_path();entity=kb._catalog_entity(kb.catalog.by_id['service'])
    signals=([{'type':'official_match','strength':'strong','data':{}}] if verdict=='safe' else [])
    out=Outcome(verdict,entity if verdict!='caution' else None,'address',signals,'other')
    page=inspect_page(b'<input type=password name=password>',FINAL)
    explanation=build_explanation(out,page,'service.example',None,message_given)
    text=json.dumps(explanation,ensure_ascii=False)
    assert ('문자' in text)==message_given
