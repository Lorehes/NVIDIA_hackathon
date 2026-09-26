import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.search_relations import record_digest
from app.verdict import decide
from app.presentation import build_comparison, build_explanation
from app.trace import page_trace
from checklib.inspect_page import inspect_page
from tests.test_same_origin_search import ENTRY, evidence
from tests.test_external_search_explanation import search
from tests.test_form_destination_explanation import form


@pytest.fixture
def reviewed(tmp_path):
    kb, ev = evidence(ENTRY)
    kb.catalog_path = tmp_path / 'site_catalog.json'
    # The fixture has an in-memory catalog; refresh would replace it from disk.
    kb.refresh_catalog = lambda: None
    ev.page = inspect_page(search().encode(), ENTRY)
    now = datetime.now(timezone.utc)
    row = dict(source_id='school', source_url=ENTRY,
               source_record_sha256=record_digest(kb.catalog.by_id['school']),
               destination_url='https://search.example/query', method='post', operator='학교 운영기관',
               review_kind='publisher_search_and_operator_evidence',
               operator_evidence={'url':'https://directory.example/operator','sha256':'a'*64},
               checked_at=now.isoformat(), expires_at=(now+timedelta(hours=24)).isoformat())
    path=tmp_path/'sources'/'reviewed_search_relations.json'; path.parent.mkdir()
    def save(): path.write_text(json.dumps({'relations':[row]}))
    save()
    return kb, ev, row, save, path


def test_reviewed_exact_edge_is_not_blanket_identity_or_safety(reviewed):
    kb, ev, _, _, _ = reviewed
    out=decide(ev,kb)
    assert out.verdict == 'unknown'
    assert 'search_submission_unverified' in out.verification_gaps
    assert 'reviewed_search_destination' in {s['type'] for s in out.signals}
    assert 'cross_domain_form' not in {s['type'] for s in out.signals}
    assert kb.catalog.describe('https://search.example/query')['status']=='unverified'
    assert '운영 관계를 확인' in str(build_comparison(out,ev.page,ev.fetch,ev.parse,None,False))
    assert '실제 입력 전송' in build_explanation(out,ev.page,'school.example',None,False)['detail']
    assert '처리 과정은 검사하지' in page_trace(ev.page,out,out.entity,'school.example')['sends_sentence']
    assert page_trace(ev.page,out,out.entity,'school.example')['sends_cross_domain'] is True


@pytest.mark.parametrize('field,value', [
    ('source_url','https://school.example/another-tenant/'),
    ('source_id','different-school'),('source_record_sha256','b'*64),
    ('destination_url','https://search.example/query?changed=1'),
    ('destination_url','https://search.example/other'),
    ('destination_url','https://other.search.example/query'),
    ('method','get'),('review_kind','unreviewed'),
    ('checked_at','2099-01-01T00:00:00+00:00'),
    ('expires_at','2020-01-01T00:00:00+00:00'),
    ('expires_at','2099-01-01T00:00:00+00:00'),
    ('expires_at','2026-09-27T00:00:00'),
    ('operator_evidence',{}),
])
def test_changed_expired_future_or_unanchored_relation_never_exempts_warning(reviewed,field,value):
    kb,ev,row,save,_=reviewed;row[field]=value;save()
    assert decide(ev,kb).verdict=='caution'


@pytest.mark.parametrize('extra', [
    '<input type=password>', '<input type=file>', '<input name=phone>',
    '<input name=unlabelled>', '<button formaction="https://evil.example/">Go</button>',
    '<button formmethod=get>Go</button>',
])
def test_reviewed_endpoint_does_not_exempt_changed_form(reviewed,extra):
    kb,ev,_,_,_=reviewed;ev.page=inspect_page(search(extra).encode(),ENTRY)
    assert decide(ev,kb).verdict=='caution'


@pytest.mark.parametrize('first',[True,False])
def test_another_unreviewed_form_keeps_warning(reviewed,first):
    kb,ev,_,_,_=reviewed;other=form('https://elsewhere.example/submit')
    ev.page=inspect_page((search()+other if first else other+search()).encode(),ENTRY)
    out=decide(ev,kb);assert out.verdict=='caution'
    assert any(s['type']=='cross_domain_form' for s in out.signals)


@pytest.mark.parametrize('change',['missing','broken','large','source_stale','source_changed','legacy'])
def test_unavailable_or_changed_evidence_fails_closed(reviewed,change):
    kb,ev,_,_,path=reviewed
    if change=='missing': path.unlink()
    elif change=='broken': path.write_text('{')
    elif change=='large': path.write_text(' '*262145)
    elif change=='source_stale': kb.catalog.by_id['school']['checked']='2020-01-01'
    elif change=='source_changed': kb.catalog.by_id['school']['source']='https://elsewhere.example/'
    elif change=='legacy': ev.page['forms'][0].pop('submission_methods')
    out=decide(ev,kb);assert out.verdict!='safe'
    assert any(s['type']=='cross_domain_form' for s in out.signals)
