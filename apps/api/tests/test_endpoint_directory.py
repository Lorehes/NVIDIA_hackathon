import copy
import importlib.util
import json
from pathlib import Path
import pytest
from app.kb import KB
from app.site_catalog import SiteCatalog

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('endpoint_collector', ROOT / 'scripts/catalog/collect_services.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
CONFIG = {'name':'발행자','url':'https://publisher.example/games','endpoint_element_id':'contents',
          'endpoint_attribute':'data-api','endpoint_base':'https://data.example', 'endpoint_path':'/games',
          'data_url':'https://data.example/games','success_fields':{'status':200},'records_path':['games'],
          'title_path':['name'],'home_paths':[['home','pc'],['home','mobile']], 'schemes':['https','http'],
          'maximum_records':3}
PAGE = '<div id="contents" data-api="https://data.example"></div>'

def payload(pc='https://game.example/ko', mobile='https://m.game.example/home?ref=publisher'):
    return {'status':200,'games':[{'name':'게임','home':{'pc':pc,'mobile':mobile},
            'banner':'https://ad.example/','community':'https://forum.example/','store':'https://store.example/app'}]}

def extract(data, config=CONFIG, page=PAGE):
    return collector.extract_endpoint_directory(json.dumps(data),config,page)

def test_only_home_fields_preserving_variants_and_queries():
    rows = extract(payload())
    assert [r['url'] for r in rows] == ['https://game.example/ko','https://m.game.example/home?ref=publisher']
    assert all(r['scope']=='url' and r['source']==CONFIG['url'] and r['data_source']==CONFIG['data_url'] for r in rows)
    assert all(r['kind']=='official_service_directory' and r['evidence_type']=='publisher_service_link' for r in rows)
    rows=extract(payload('http://game.example/','http://game.example/'))
    assert len(rows)==1 and rows[0]['home_fields']==['home.pc','home.mobile']

@pytest.mark.parametrize('url',['javascript:alert(1)','https://u@bad.example/','https://bad.example:0/',
    'https://bad.example:abc/','https://bad.example:444/','https://bad.example/a.apk',
    'https://bad.example/https://other.example/','https://bad.example\\@other.example/',
    'https://{device}.example/','https://white space.example/'])
def test_invalid_home_does_not_fall_back_to_banner_or_community(url):
    assert extract(payload(url,None)) == []

@pytest.mark.parametrize('page',[PAGE+PAGE,PAGE.replace('data-api','data-changed'),PAGE.replace('data.example','other.example'),''])
def test_changed_page_endpoint_rejects(page):
    with pytest.raises(ValueError): extract(payload(),page=page)

@pytest.mark.parametrize('change',['status','status_type','list_type','missing_home','missing_title','too_many','home_type'])
def test_changed_or_failed_response_rejects(change):
    d=payload()
    if change=='status': d['status']=500
    if change=='status_type': d['status']='200'
    if change=='list_type': d['games']={}
    if change=='missing_home': del d['games'][0]['home']['pc']
    if change=='missing_title': del d['games'][0]['name']
    if change=='too_many': d['games']*=4
    if change=='home_type': d['games'][0]['home']['pc']={}
    with pytest.raises(ValueError): extract(d)

def test_duplicate_json_keys_and_oversize_rejected():
    for body in ['{"status":200,"status":200,"games":[]}', ' '*2_000_001]:
        with pytest.raises(ValueError): collector.extract_endpoint_directory(body,CONFIG,PAGE)

def test_failure_keeps_previous_snapshot(tmp_path, monkeypatch):
    directory=tmp_path/'kb/sources'; directory.mkdir(parents=True)
    p={**CONFIG,'format':'json_endpoint_directory','minimum_records':1}
    (directory/'service_publishers.json').write_text(json.dumps({'publishers':[p]}))
    target=directory/'official_services.json'; original=b'{"checked":"2026-09-25","records":[]}'
    target.write_bytes(original)
    class Response:
        is_redirect=False
        def __init__(self,text): self.text=text
        def raise_for_status(self): pass
    class Client:
        def __init__(self,**kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def get(self,url):
            return Response(PAGE if url==CONFIG['url'] else '{"status":500,"games":[]}')
    monkeypatch.setattr(collector,'ROOT',tmp_path)
    monkeypatch.setattr(collector.httpx,'Client',Client)
    monkeypatch.setattr('sys.argv',['collect_services'])
    with pytest.raises(ValueError): collector.main()
    assert target.read_bytes()==original

def test_real_directory_exact_urls_not_all_game_subdomains_or_shortener_paths():
    kb=KB.load()
    rows=[r for r in kb.catalog.by_id.values() if r.get('source')=='https://www.nexon.com/Home/Game']
    assert len(rows)==45
    exact=SiteCatalog(rows)
    for r in rows:
        assert exact.describe(r['url'])['status']=='verified'
        assert exact.lookup(r['url'].split('#')[0]+('&unexpected=1' if '?' in r['url'] else '?unexpected=1')) is None
    for u in ['https://other.nexon.com/','https://abr.ge/other','https://m.fconline.nexon.com/',
              'https://maplestoryidle.nexon.com/user-world','https://bluearchive.nexon.com.unrelated.example/']:
        assert exact.lookup(u) is None
