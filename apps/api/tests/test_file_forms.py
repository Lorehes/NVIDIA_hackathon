import pytest

from app.models import PageTrace
from app.presentation import build_comparison, build_explanation
from app.trace import page_trace
from app.verdict import decide
from checklib.inspect_page import inspect_page
from tests.test_same_origin_search import ENTRY, evidence


@pytest.mark.parametrize('method', ['get', 'post'])
@pytest.mark.parametrize('external_control', [False, True])
def test_file_control_cannot_be_hidden_by_search_role(method, external_control):
    kb, ev = evidence(ENTRY)
    upload = '<input type=file name=upload form=f>'
    html = f'<form id=f role=search method={method} action=/other-tenant/><input type=search name=q>'
    html += ('</form>' + upload) if external_control else (upload + '</form>')
    ev.page = inspect_page(html.encode(), ENTRY)
    form = ev.page['forms'][0]
    assert 'file' in form['field_types']
    assert not form['same_origin_search'] and not form['search_only']
    out = decide(ev, kb)
    assert out.verdict == 'caution'
    assert 'cross_domain_form' in {s['type'] for s in out.signals}
    assert 'same_site_search' not in {s['type'] for s in out.signals}


@pytest.mark.parametrize('control', [
    '<input type=file>',
    '<input type=FILE name=password autocomplete=cc-number>',
    '<input type=file multiple accept=image/*>',
])
def test_official_upload_is_observed_but_not_assumed_safe(control):
    kb, ev = evidence(ENTRY)
    ev.page = inspect_page(f'<form action="{ENTRY}">{control}</form>'.encode(), ENTRY)
    assert ev.page['forms'][0]['field_types'] == ['file']
    out = decide(ev, kb)
    assert out.verdict == 'unknown'
    assert 'file_submission_unverified' in out.verification_gaps
    assert 'credential_form' not in {s['type'] for s in out.signals}
    assert kb.identity_summary(ENTRY, out)['status'] == 'verified'
    row = next(r for r in build_comparison(out, ev.page, ev.fetch, ev.parse, None, False) if r['key'] == 'fields')
    assert row['found'] == '첨부 파일' and row['status'] == 'unknown'
    trace = page_trace(ev.page, out, out.entity, 'school.example', False)
    PageTrace.model_validate(trace)
    assert trace['field_rows'][0]['verdict'] == 'unknown'
    explanation = build_explanation(out, ev.page, 'school.example', None, False)
    assert '파일 첨부란' in explanation['detail']
    assert '1~2분' not in explanation['recommended_action']


def test_hidden_search_token_does_not_become_file_upload():
    kb, ev = evidence(ENTRY)
    ev.page = inspect_page(b'<form role=search action=/search><input type=search><input type=hidden name=csrf></form>', ENTRY)
    assert ev.page['forms'][0]['field_types'] == ['other']
    assert ev.page['forms'][0]['search_only']
    out = decide(ev, kb)
    assert 'file_submission_unverified' not in out.verification_gaps
