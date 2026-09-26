import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import pytest
from app.kb import KB
from app.site_catalog import SiteCatalog

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('paginated_collector', ROOT/'scripts/catalog/collect_services.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
SCRIPT = 'reviewed pagination and home-link contract'
PAGE = '<script>'+SCRIPT+'</script>'
CONFIG = {'name':'발행자','url':'https://publisher.example/games','format':'paginated_json_directory',
    'reviewed_script_sha256':[hashlib.sha256(SCRIPT.encode()).hexdigest()],
    'endpoint_template':'/api/{category}/{page}','categories':['mobile'],'maximum_pages':3,'page_size':2,
    'success_fields':{},'records_path':['gameList'],'title_path':['gameName'],'home_paths':[['gameSiteUrl']],
    'schemes':['http','https'],'minimum_records':1,'maximum_records':10}

def payloads():
    def card(i):
        return {'seq':i,'total':3,'gameKindName':'mobile','serviceFlag':'Y','gameName':f'게임{i}',
            'gameSiteUrl':f'https://games.example/service/{i}?ref=directory',
            'googleplayUrl':'https://store.example/app','appstoreUrl':'https://store.example/other'}
    return [{'gameList':[card(1),card(2)],'pagingManager':{'currentPage':1,'theEndBlockNo':2}},
            {'gameList':[card(3)],'pagingManager':{'currentPage':2,'theEndBlockNo':2}}]

class Response:
    is_redirect=False
    def __init__(self,text): self.text=text
    def raise_for_status(self): pass
class Client:
    def __init__(self,data): self.data=data; self.urls=[]
    def get(self,url):
        self.urls.append(url)
        return Response(json.dumps(self.data[int(url.rsplit('/',1)[1])-1]))

def test_complete_pages_only_home_fields_and_exact_scope():
    data=payloads();data[0]['gameList'][1]['serviceFlag']='N'
    data[1]['gameList'][0]['gameSiteUrl']='http://games.example/three'
    client=Client(data);rows=collector.collect_paginated_directory(client,CONFIG,PAGE)
    assert len(rows)==2 and rows[1]['url']=='http://games.example/three'
    assert client.urls==['https://publisher.example/api/mobile/1','https://publisher.example/api/mobile/2']
    assert all(r['scope']=='url' and r['home_fields']==['gameSiteUrl'] for r in rows)
    assert rows[0]['source_sha256']==hashlib.sha256(json.dumps(data[0]).encode()).hexdigest()

@pytest.mark.parametrize('case',['repeat','total_change','page_change','end_change','too_many_pages',
    'short_middle','missing_last','wrong_category','wrong_flag','boolean_total','duplicate_json','redirect','script'])
def test_incomplete_or_changed_directory_fails_closed(case):
    data=payloads();page=PAGE
    if case=='repeat': data[1]['gameList'][0]['seq']=1
    if case=='total_change': data[1]['gameList'][0]['total']=4
    if case=='page_change': data[1]['pagingManager']['currentPage']=1
    if case=='end_change': data[1]['pagingManager']['theEndBlockNo']=3
    if case=='too_many_pages': data[0]['pagingManager']['theEndBlockNo']=10000
    if case=='short_middle': data[0]['gameList'].pop()
    if case=='missing_last': data[1]['gameList']=[]
    if case=='wrong_category': data[0]['gameList'][0]['gameKindName']='ad'
    if case=='wrong_flag': data[0]['gameList'][0]['serviceFlag']=True
    if case=='boolean_total': data[0]['gameList'][0]['total']=True
    if case=='script': page=PAGE.replace('contract','changed')
    client=Client(data)
    if case=='duplicate_json': client.get=lambda url: Response('{"gameList":[],"gameList":[]}')
    if case=='redirect':
        response=Response('{}');response.is_redirect=True;client.get=lambda url:response
    with pytest.raises(ValueError): collector.collect_paginated_directory(client,CONFIG,page)

def test_failed_last_page_preserves_snapshot(tmp_path,monkeypatch):
    directory=tmp_path/'kb/sources';directory.mkdir(parents=True)
    (directory/'service_publishers.json').write_text(json.dumps({'publishers':[CONFIG]}))
    target=directory/'official_services.json';original=b'{"records":[],"checked":"2026-09-25"}';target.write_bytes(original)
    data=payloads();data[1]['gameList']=[]
    class ContextClient(Client):
        def __init__(self,**kwargs): super().__init__(data)
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def get(self,url): return Response(PAGE) if url==CONFIG['url'] else super().get(url)
    monkeypatch.setattr(collector,'ROOT',tmp_path);monkeypatch.setattr(collector.httpx,'Client',ContextClient)
    monkeypatch.setattr('sys.argv',['collect_services'])
    with pytest.raises(ValueError): collector.main()
    assert target.read_bytes()==original

def test_real_directory_shared_paths_do_not_grant_whole_portal():
    rows=[r for r in KB.load().catalog.by_id.values() if r.get('source')=='https://company.netmarble.com/business/games']
    assert len(rows)==35
    catalog=SiteCatalog(rows)
    for r in rows:
        assert catalog.describe(r['url'])['status']=='verified'
        assert catalog.lookup(r['url']+('&unexpected=1' if '?' in r['url'] else '?unexpected=1')) is None
    for url in ['https://unlisted.netmarble.com/','https://www.netmarble.net/mobile/other',
        'https://poker.winjoygame.com/other','https://apps.apple.com/kr/anything']:
        assert catalog.lookup(url) is None
