import html

import pytest

from app.presentation import build_explanation
from tests.test_form_transport import ENTRY, evaluate


@pytest.mark.parametrize('markup', [
    '<script>fetch("/submit", {method:"POST"})</script>',
    '<script src="/app.js"></script>',
    '<script type=module src="/app.mjs"></script>',
    '<script type=" Text/JavaScript ">doWork()</script>',
    '<script language=JavaScript1.5>doWork()</script>',
    '<script type="" language=unsupported>doWork()</script>',
    '<button onclick="send()">보내기</button>',
    '<form onsubmit="send()"><input name=q></form>',
    '<svg><script href="/app.js" /></svg>',
    '<script type=speculationrules>{"prefetch":[]}</script>',
    '<script type=importmap>{"imports":{}}</script>',
    '<iframe srcdoc="' + html.escape('<button onclick="send()">send</button>', quote=True) + '"></iframe>',
])
def test_official_identity_does_not_verify_unexecuted_code(markup):
    kb, ev, out = evaluate(markup)
    assert ev.page['unexecuted_code']
    assert out.verdict == 'unknown'
    assert 'unexecuted_code' in out.verification_gaps
    assert kb.identity_summary(ENTRY, out)['status'] == 'verified'
    explanation = build_explanation(out, ev.page, 'hanbit.example', None, False)
    assert '공식 주소' in explanation['headline']
    assert '스크립트 실행 후' in explanation['detail']
    assert not explanation['suspicion_evidence']
    assert '1~2분' not in explanation['recommended_action']


@pytest.mark.parametrize('markup', [
    '<p>정적 안내</p>', '<script></script>', '<script>  </script>',
    '<script type=application/json>{"sample":"location.href=1"}</script>',
    '<script type=application/ld+json>{"@type":"Organization"}</script>',
    '<script type=text/plain src="https://elsewhere.example/a.js">fetch("/x")</script>',
    '<script type="text/javascript; charset=utf-8">doWork()</script>',
    '<script language=unsupported>doWork()</script>',
])
def test_inert_data_does_not_become_executed_code_or_redirect(markup):
    _, ev, out = evaluate(markup)
    assert not ev.page['unexecuted_code']
    assert not ev.page['js_redirect_hint']
    assert out.verdict == 'safe'


def test_script_uncertainty_does_not_hide_observed_http_form_risk():
    _, ev, out = evaluate('<script>doWork()</script><form action="http://hanbit.example/form"><input type=password></form>')
    assert out.verdict == 'caution'
    assert 'unexecuted_code' in out.verification_gaps
    assert 'insecure_form_action' in {s['type'] for s in out.signals}
