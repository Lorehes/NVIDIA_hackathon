import pytest
from app.presentation import build_comparison
from app.verdict import decide
from checklib.inspect_page import inspect_page
from datetime import datetime, timezone
from app.kb import KB
from app.site_catalog import SiteCatalog
from app.verdict import Evidence
from checklib.parse_url import parse_url
from checklib.similarity import compare

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




def search(action='/search', extra='', method='post'):
    return (f'<form id=f method={method} action="{action}"><input type=search name=q>'
            '<input type=text name=qt title="검색어 입력"><button>검색</button>'
            f'{extra}</form>').encode()


def test_legacy_typed_search_is_a_gap_not_a_cross_site_claim_or_safety_grant():
    kb, ev = evidence(FINAL)
    ev.page = inspect_page(search(), FINAL)
    assert ev.page['forms'][0]['same_origin_search'] is True
    assert ev.page['forms'][0]['search_only'] is False
    out = decide(ev, kb)
    assert out.verdict == 'unknown'
    assert 'same_site_search' in {s['type'] for s in out.signals}
    assert 'cross_domain_form' not in {s['type'] for s in out.signals}
    assert 'search_destination_unverified' in out.verification_gaps
    rows = build_comparison(out, ev.page, ev.fetch, ev.parse, None, False)
    destination = next(r for r in rows if r['key'] == 'destination')
    assert destination['status'] == 'unknown' and '미확인' == destination['status_label']
    assert kb.catalog.describe('https://school.example/search')['status'] == 'unverified'


@pytest.mark.parametrize('action,extra,method', [
    ('https://other.school.example/search','','post'),
    ('https://unrelated.example/search','','post'),
    ('http://school.example/search','','post'),
    ('https://school.example:444/search','','post'),
    ('/search','<input type=password name=password>','post'),
    ('/search','<input name=phone title="전화번호">','post'),
    ('/search','<input type=text name=unlabelled>','post'),
    ('/search','<button formaction="https://other.example/">Go</button>','post'),
    ('/search','<button formmethod=post>Go</button>','get'),
])
def test_search_hint_never_suppresses_other_origins_sensitive_or_ambiguous_inputs(action, extra, method):
    kb, ev = evidence(FINAL)
    ev.page = inspect_page(search(action, extra, method), FINAL)
    assert ev.page['forms'][0]['same_origin_search'] is False
    out = decide(ev, kb)
    assert out.verdict == 'caution'
    assert 'cross_domain_form' in {s['type'] for s in out.signals}


def test_non_search_shared_tenant_post_is_still_risk():
    kb, ev = evidence(FINAL)
    ev.page = inspect_page(b'<form action="/another-tenant/" method=post><input name=q></form>', FINAL)
    assert not ev.page['forms'][0]['same_origin_search']
    assert 'cross_domain_form' in {s['type'] for s in decide(ev,kb).signals}


def filtered_search(query='<input name=query placeholder="검색어 입력">',
                    selector='<select title="검색항목"><option>전체</option><option>업무</option></select>',
                    extra='', action='/search', method='post'):
    return (f'<form id=f method={method} action="{action}">{query}{selector}{extra}</form>').encode()


@pytest.mark.parametrize('query,selector,method', [
    ('<input name=query placeholder="검색어 입력">', '<select title="검색항목"><option>전체</option></select>', 'post'),
    ('<input name=searchKeyword placeholder="검색">', '<select name=searchCondition><option>업무</option><option>전화번호</option></select>', 'get'),
    ('<input type=search>', '<select aria-label="Search category"><optgroup label="Scope"><option>All</option></optgroup></select>', 'post'),
    ('<label for=q>Search</label><input id=q>', '', 'get'),
])
def test_filtered_search_remains_unverified_and_never_registers_destination(query, selector, method):
    kb, ev = evidence()
    ev.page = inspect_page(filtered_search(query, selector, method=method), FINAL)
    assert ev.page['forms'][0]['same_origin_search'] is True
    out = decide(ev, kb)
    assert out.verdict == 'unknown'
    assert 'cross_domain_form' not in {s['type'] for s in out.signals}
    assert 'search_destination_unverified' in out.verification_gaps
    assert kb.catalog.describe('https://school.example/search')['status'] == 'unverified'


@pytest.mark.parametrize('query,selector,extra,action,method', [
    ('<input name=unidentified placeholder="검색">', '', '', '/search', 'post'),
    ('<input name=query>', '', '', '/search', 'post'),
    ('', '<select title="검색"><option>전체</option></select>', '', '/search', 'post'),
    ('<input name=query placeholder="검색">', '<select><option>전체</option></select>', '', '/search', 'post'),
    ('<input name=query placeholder="검색">', '<select title="검색"></select>', '', '/search', 'post'),
    ('<input name=query placeholder="검색">', '<select title="검색" multiple><option>전체</option></select>', '', '/search', 'post'),
    ('<input name=query placeholder="검색">', '<select title="검색">'+'<option>전체</option>'*51+'</select>', '', '/search', 'post'),
    ('<input name=query placeholder="검색">', '<select title="검색" name=bankaccount><option>전체</option></select>', '', '/search', 'post'),
    ('<input name=query placeholder="검색" title="비밀번호">', '', '', '/search', 'post'),
    ('<input name=query placeholder="검색">', '', '<input type=file name=query>', '/search', 'post'),
    ('<input name=query placeholder="검색">', '', '<input type=password>', '/search', 'post'),
    ('<input name=query placeholder="검색">', '', '<textarea placeholder="검색"></textarea>', '/search', 'post'),
    ('<input name=query placeholder="검색">', '', '<input name=phone>', '/search', 'post'),
    ('<input name=query placeholder="검색">', '', '<input name=another placeholder="검색">', '/search', 'post'),
    ('<input name=query placeholder="검색">', '', '', 'https://other.school.example/search', 'post'),
    ('<input name=query placeholder="검색">', '', '', 'http://school.example/search', 'post'),
    ('<input name=query placeholder="검색">', '', '', 'https://school.example:444/search', 'post'),
    ('<input name=query placeholder="검색">', '', '<button formaction="https://other.example/">Search</button>', '/search', 'post'),
    ('<input name=query placeholder="검색">', '', '<button formmethod=post>Search</button>', '/search', 'get'),
])
def test_filtered_search_does_not_hide_ambiguous_sensitive_or_external_forms(query, selector, extra, action, method):
    kb, ev = evidence()
    ev.page = inspect_page(filtered_search(query, selector, extra, action, method), FINAL)
    assert ev.page['forms'][0]['same_origin_search'] is False
    assert decide(ev, kb).verdict == 'caution'


def test_filtered_search_preserves_external_form_warning_and_external_form_owner():
    kb, ev = evidence()
    body = (filtered_search() + b'<form id=other action="https://outside.example/" method=post>'
            b'<input type=password></form><input type=file form=other>')
    ev.page = inspect_page(body, FINAL)
    assert ev.page['forms'][0]['same_origin_search'] is True
    assert ev.page['forms'][1]['same_origin_search'] is False
    out = decide(ev, kb)
    assert out.verdict == 'caution'
    assert 'cross_domain_form' in {s['type'] for s in out.signals}
