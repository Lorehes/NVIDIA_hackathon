import json

import pytest

from app.presentation import build_comparison, build_explanation, build_risks
from app.verdict import decide
from app.trace import page_trace
from checklib.inspect_page import inspect_page
from tests.test_same_origin_search import ENTRY, evidence


def form(action='/another-tenant/submit', extra=''):
    return f'<form method="post" action="{action}"><input name="q">{extra}</form>'


def evaluate(html):
    kb, ev = evidence(ENTRY)
    ev.page = inspect_page(html.encode(), ENTRY)
    out = decide(ev, kb)
    warning = next(s for s in out.signals if s['type'] == 'cross_domain_form')
    assert out.verdict == 'caution'
    assert warning['strength'] == 'mid'
    return kb, ev, out, warning


@pytest.mark.parametrize('action', ['/another-tenant/submit', 'https://school.example:443/search?q=x'])
def test_same_origin_keeps_caution_but_explains_unverified_path(action):
    kb, ev, out, warning = evaluate(form(action))
    assert warning['data']['same_origin_unverified'] is True
    assert kb.catalog.describe('https://school.example/another-tenant/submit')['status'] == 'unverified'
    explanation = build_explanation(out, ev.page, 'school.example', None, False)
    comparison = build_comparison(out, ev.page, ev.fetch, ev.parse, None, False)
    risks, _ = build_risks(out, ev.page)
    trace = page_trace(ev.page, out, out.entity, 'school.example')
    assert trace['sends_cross_domain'] is False and '미확인' in trace['sends_sentence']
    text = json.dumps([explanation, comparison, risks, trace], ensure_ascii=False)
    assert '입력 정보의 처리 경로는 미확인' in explanation['headline']
    assert '다른 사이트' not in text
    assert '문자 내용과 맞지' not in text
    assert '홈페이지이나' not in text
    assert '입력 처리 경로 미확인' in text


@pytest.mark.parametrize('action', [
    'http://school.example/submit', 'https://school.example:444/submit',
    'https://school.example:0/submit', 'https://other.school.example/submit',
    'https://external.example/submit',
])
def test_different_transport_or_host_is_not_described_as_same_origin(action):
    _, _, _, warning = evaluate(form(action))
    assert warning['data']['same_origin_unverified'] is False


@pytest.mark.parametrize('external_first', [False, True])
def test_external_form_not_hidden_by_local_form_order(external_first):
    local, external = form(), form('https://external.example/submit')
    _, ev, out, warning = evaluate(external + local if external_first else local + external)
    assert warning['data']['action_host'] == 'external.example'
    assert not warning['data']['same_origin_unverified']
    trace = page_trace(ev.page, out, out.entity, 'school.example')
    assert trace['sends_cross_domain'] is True
    assert 'external.example' in trace['sends_sentence']
    assert '적는 순간' not in trace['sends_sentence']
    assert '다른 사이트(external.example)' in str(build_comparison(out, ev.page, ev.fetch, ev.parse, None, False))


def test_external_button_and_sensitive_fields_retain_warnings():
    _, _, out, warning = evaluate(form(extra='<input type=password><button formaction="https://external.example/">Go</button>'))
    assert not warning['data']['same_origin_unverified']
    assert warning['data']['action_host'] == 'external.example'
    assert 'credential_form' in {s['type'] for s in out.signals}


@pytest.mark.parametrize('alter', ['overflow', 'missing_urls'])
def test_incomplete_destinations_do_not_assert_same_origin(alter):
    kb, ev = evidence(ENTRY)
    ev.page = inspect_page(form().encode(), ENTRY)
    if alter == 'overflow':
        ev.page['forms'][0]['destinations_overflow'] = True
    else:
        ev.page['forms'][0]['action_urls'] = []
        ev.page['forms'][0]['cross_domain'] = True
        ev.page['forms'][0]['destinations'] = [{'host':'external.example', 'cross_domain':True}]
    out = decide(ev, kb)
    warning = next(s for s in out.signals if s['type'] == 'cross_domain_form')
    assert out.verdict == 'caution'
    assert not warning['data'].get('same_origin_unverified')


def test_search_trace_does_not_claim_input_stays_inside_page():
    kb, ev = evidence(ENTRY)
    ev.page = inspect_page(b'<form method=post action=/search><input type=search name=q></form>', ENTRY)
    out = decide(ev, kb)
    trace = page_trace(ev.page, out, out.entity, 'school.example')
    assert 'same_site_search' in {s['type'] for s in out.signals}
    assert '확인하지 못했어요' in trace['sends_sentence']
    assert '안에서만' not in trace['sends_sentence']
