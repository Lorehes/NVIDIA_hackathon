from datetime import datetime,timedelta,timezone
import importlib.util
from pathlib import Path

import pytest
from tests.test_same_origin_search import evidence,ENTRY
from tests.test_external_search_explanation import search

path=Path(__file__).resolve().parents[3]/'scripts/catalog/refresh_search_relations.py'
spec=importlib.util.spec_from_file_location('refresh_search',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


@pytest.fixture
def case():
    kb,_=evidence(ENTRY);now=datetime.now(timezone.utc)
    proof='https://directory.example/review';dest='https://search.example/query'
    edge={'source_id':'school','source_url':ENTRY,'source_record_sha256':module.record_digest(kb.catalog.by_id['school']),
          'destination_url':dest,'destination_title':'Official search','method':'post'}
    cfg={'publishers':[{'operator':'School','reviewed_at':now.isoformat(),'evidence_url':proof,
                       'evidence_tag':'p','evidence_text_sha256':module.text_digest('Operator statement'),'edges':[edge]}]}
    bodies={proof:b'<p>Operator statement</p>',ENTRY:search().encode(),dest:b'<title>Official search</title>'}
    return kb,now,cfg,bodies


def test_fresh_evidence_renews_exact_edge_and_uses_cached_fetches(case):
    kb,now,cfg,bodies=case;calls=[]
    def fetch(url):calls.append(url);return bodies[url]
    rows,report=module.refresh(kb,cfg,[],fetch,now)
    assert len(rows)==1 and report[0]['status']=='refreshed'
    assert rows[0]['expires_at']==(now+timedelta(hours=24)).isoformat()
    assert rows[0]['refresh_evidence']['operator_text_sha256']==cfg['publishers'][0]['evidence_text_sha256']
    assert len(calls)==3
    calls.clear();same,report=module.refresh(kb,cfg,rows,fetch,now)
    assert same==rows and not calls and report[0]['status']=='not_due'


@pytest.mark.parametrize('change',['operator','duplicated_proof','missing_form','sensitive','method','target','title','record','stale_review','failed_get'])
def test_changed_or_unavailable_evidence_revokes_selected_edge(case,change):
    kb,now,cfg,bodies=case
    prior,_=module.refresh(kb,cfg,[],bodies.__getitem__,now)
    proof=cfg['publishers'][0]['evidence_url'];dest=cfg['publishers'][0]['edges'][0]['destination_url']
    if change=='operator':bodies[proof]=b'<p>Different operator</p>'
    if change=='duplicated_proof':bodies[proof]*=2
    if change=='missing_form':bodies[ENTRY]=b'<p>No form</p>'
    if change=='sensitive':bodies[ENTRY]=search('<input type=password>').encode()
    if change=='method':bodies[ENTRY]=search(method='get').encode()
    if change=='target':bodies[ENTRY]=search(action='https://new.example/query').encode()
    if change=='title':bodies[dest]=b'<title>Expired site</title>'
    if change=='record':kb.catalog.by_id['school']['name']='Different institution'
    if change=='stale_review':cfg['publishers'][0]['reviewed_at']=(now-timedelta(days=91)).isoformat()
    def fetch(url):
        if change=='failed_get':raise OSError('offline')
        return bodies[url]
    rows,report=module.refresh(kb,cfg,prior,fetch,now,force=True)
    assert rows==[] and report[0]['status']=='unconfirmed'
    if change in ('method','target'):assert report[0]['candidates'][0]['status']=='unreviewed'


def test_failure_preserves_unrelated_publisher(case):
    kb,now,cfg,_=case
    other={'source_id':'elsewhere','expires_at':now.isoformat()}
    def failed(url):raise OSError('timeout')
    rows,_=module.refresh(kb,cfg,[other],failed,now)
    assert rows==[other]


@pytest.mark.parametrize('url',['http://example.com','https://user@example.com','https://example.com:444/','https://example.com/#frag'])
def test_transport_rejected_before_any_dns_or_http(url,monkeypatch):
    monkeypatch.setattr(module,'resolve_public_destination',lambda u:pytest.fail('must reject before DNS'))
    with pytest.raises(ValueError):module.pinned_html(url)
