"""Search shape refines wording, never trust, severity, or submission permission."""
import pytest

from app.presentation import build_comparison, build_explanation, build_risks
from app.trace import page_trace
from tests.test_form_destination_explanation import evaluate, form


def search(extra='', action='https://search.example/query', method='post'):
    return (f'<form method="{method}" action="{action}">'
            '<input type=hidden name=category value=TOTAL>'
            '<input type=text name=total_search title="검색어 입력">'
            f'{extra}<input type=submit title="검색"></form>')


@pytest.mark.parametrize('method', ['get', 'post'])
def test_external_search_is_explained_but_warning_and_unverified_identity_remain(method):
    kb, ev, out, warning = evaluate(search(method=method))
    assert warning['data']['search_form'] is True
    assert warning['strength'] == 'mid' and out.verdict == 'caution'
    assert kb.catalog.describe('https://search.example/query')['status'] == 'unverified'
    assert ev.page['forms'][0]['same_origin_search'] is False
    explanation = build_explanation(out, ev.page, 'school.example', None, False)
    assert '검색 전송 대상과의 운영 관계는 미확인' in explanation['headline']
    risks, _ = build_risks(out, ev.page)
    assert '검색 전송 대상 미확인' in str(risks)
    comparison = build_comparison(out, ev.page, ev.fetch, ev.parse, None, False)
    row = next(r for r in comparison if r['key'] == 'destination')
    assert row['status'] == 'warn' and '실제 전송은 미확인' in row['found']
    trace = page_trace(ev.page, out, out.entity, 'school.example')
    assert trace['sends_cross_domain'] is True
    assert '실제 전송은 확인하지 못했어요' in trace['sends_sentence']


@pytest.mark.parametrize('extra,action,method', [
    ('<input type=password>', 'https://search.example/query', 'post'),
    ('<input name=phone>', 'https://search.example/query', 'post'),
    ('<input type=file>', 'https://search.example/query', 'post'),
    ('<input name=unknown>', 'https://search.example/query', 'post'),
    ('<textarea title="검색"></textarea>', 'https://search.example/query', 'post'),
    ('<button formaction="https://elsewhere.example/">send</button>', 'https://search.example/query', 'post'),
    ('<button formmethod=get>send</button>', 'https://search.example/query', 'post'),
    ('', 'http://search.example/query', 'post'),
    ('', 'https://search.example:444/query', 'post'),
])
def test_sensitive_ambiguous_multi_destination_and_insecure_forms_keep_generic_warning(extra, action, method):
    _, ev, out, warning = evaluate(search(extra, action, method))
    assert not warning['data'].get('search_form')
    assert not ev.page['forms'][0]['search_form']
    if action.startswith('http:'):
        assert 'insecure_form_action' in {s['type'] for s in out.signals}


@pytest.mark.parametrize('search_first', [True, False])
def test_search_form_cannot_hide_another_form(search_first):
    other = form('https://receiver.example/submit', '<input type=password>')
    _, _, out, warning = evaluate(search()+other if search_first else other+search())
    assert warning['data']['action_host'] == 'receiver.example'
    assert not warning['data'].get('search_form')
    assert 'credential_form' in {s['type'] for s in out.signals}
