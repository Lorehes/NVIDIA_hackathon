import pytest
from app.kb import KB
from app.presentation import build_comparison,build_explanation
from app.trace import page_trace
from app.verdict import Evidence,decide
from checklib.inspect_page import inspect_page
from checklib.parse_url import parse_url
from checklib.similarity import compare
ENTRY='https://hanbit.example/form'
def evaluate(html):
 kb=KB.load();p=parse_url(ENTRY)
 ev=Evidence(parse=p,input_url=ENTRY,address_only=True,fetch={'ok':True,'final_url':ENTRY,'final_registrable_domain':'hanbit.example','chain':[{'url':ENTRY,'status':200}],'tls':{'verified':True}},page=inspect_page(html.encode(),ENTRY),similarity=compare(p,kb.official_records()),candidates=kb.address_candidates(ENTRY))
 return kb,ev,decide(ev,kb)
@pytest.mark.parametrize('field',['<input name=q>','<input type=password>','<input type=hidden name=token value=x>','<input type=file>'])
def test_official_https_page_does_not_make_http_submission_safe(field):
 kb,ev,out=evaluate('<form method=post action="http://hanbit.example/form">'+field+'</form>')
 assert out.verdict=='caution'
 assert {'official_match','insecure_form_action'} <= {s['type'] for s in out.signals}
 assert kb.identity_summary(ENTRY,out)['status']=='verified'
 assert ev.page['forms'][0]['insecure_submission']
 explanation=build_explanation(out,ev.page,'hanbit.example',None,False)
 assert '암호화되지 않은 주소' in explanation['headline']
 assert any('HTTP' in x for x in explanation['suspicion_evidence'])
 comparison=build_comparison(out,ev.page,ev.fetch,ev.parse,None,False)
 assert next(r for r in comparison if r['key']=='destination')['status']=='warn'
 trace=page_trace(ev.page,out,out.entity,'hanbit.example')
 assert 'HTTP' in trace['sends_sentence'] and '실행하지' in trace['sends_sentence']
@pytest.mark.parametrize('html',[
 '<form action=/ok><input name=q><button formaction="http://hanbit.example/submit">Go</button></form>',
 '<form id=f action=/ok><input name=q></form><button form=f formaction="http://hanbit.example/submit">Go</button>',
 '<base href="http://hanbit.example/"><form action=submit><input name=q></form>',
 '<form action="hTtP://hanbit.example/submit"><input name=q></form>',
 '<form role=search action="http://hanbit.example/search"><input type=search name=q></form>'])
def test_all_actions_and_search_preserve_transport_warning(html):
 _,_,out=evaluate(html)
 assert out.verdict=='caution' and 'insecure_form_action' in {s['type'] for s in out.signals}
def test_action_beyond_display_cap_still_warns():
 buttons=''.join(f'<button formaction="https://hanbit.example/{i}">Go</button>' for i in range(25))
 _,ev,out=evaluate('<form action=/ok><input name=q>'+buttons+'<button formaction="http://hanbit.example/last">Go</button></form>')
 f=ev.page['forms'][0]
 assert len(f['action_urls'])==20 and all(u.startswith('https:') for u in f['action_urls'])
 assert f['insecure_submission'] and out.verdict=='caution'
def test_legacy_evidence_without_new_flag_checks_urls():
 kb,ev,_=evaluate('<form action="http://hanbit.example/post"><input name=q></form>')
 del ev.page['forms'][0]['insecure_submission']
 assert decide(ev,kb).verdict=='caution'
@pytest.mark.parametrize('action',['/form','https://hanbit.example/submit','//hanbit.example/submit'])
def test_https_actions_are_not_insecure_or_claimed_browser_only(action):
 _,ev,out=evaluate(f'<form action="{action}"><input name=q></form>')
 assert 'insecure_form_action' not in {s['type'] for s in out.signals}
 row=next(r for r in build_comparison(out,ev.page,ev.fetch,ev.parse,None,False) if r['key']=='destination')
 assert row['status']=='unknown' and '서버의 처리 과정은 검사하지' in row['found']
 assert '안에서만' not in page_trace(ev.page,out,out.entity,'hanbit.example')['sends_sentence']
