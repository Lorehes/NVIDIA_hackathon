from copy import deepcopy
from datetime import date
import importlib.util
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('fingerprint_corrections',ROOT/'scripts/catalog/source_corrections.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixture():
    row={'name':'대학원','url':'','kind':'university','source':'https://directory.example','source_updated':'2026-03-18'}
    data={'checked':'2026-09-25','records':[row]}
    patch={'source_dataset':'universities','source_id':None,'source_row_sha256':m.source_fingerprint(row),
           'source_snapshot_sha256':m.source_fingerprint(data),'name':row['name'],'original_url':'',
           'url':'https://university.example/graduate/a','scope':'url','source':'https://university.example/graduate/a',
           'checked':'2026-09-25','reason':'reviewed','evidence':[{'kind':'official_institution_page'}]}
    return row,data,patch


def test_exact_row_and_snapshot_allow_correction_without_fabricating_institution_id():
    row,data,p=fixture(); original=deepcopy(data)
    prepared,inactive=m.prepare_corrections({'universities':data},[p],date(2026,9,25))
    out=m.apply_correction('universities',row,data['checked'],prepared)
    assert not inactive and out['url']==p['url'] and data==original
    assert out['correction_source_id'] is None and 'source_id' not in out
    assert out['correction_source_row_sha256']==p['source_row_sha256']
    assert out['correction_source_snapshot_sha256']==p['source_snapshot_sha256']
    assert out['original_source']==row['source'] and out['original_url']==''
    assert m.source_fingerprint(dict(reversed(list(row.items()))))==p['source_row_sha256']

@pytest.mark.parametrize('change',['other_row','row_metadata','checked','new_id','same_name_other_source','remove_row'])
def test_any_snapshot_or_row_change_deactivates_review(change):
    row,data,p=fixture(); modified=deepcopy(data)
    if change=='other_row': modified['records'].append({**row,'name':'다른대학원'})
    if change=='row_metadata': modified['records'][0]['source_updated']='2026-04-01'
    if change=='checked': modified['checked']='2026-09-26'
    if change=='new_id': modified['records'][0]['source_id']='now-assigned'
    if change=='same_name_other_source': modified['records'][0]['source']='https://other.example/'
    if change=='remove_row': modified['records']=[]
    prepared,inactive=m.prepare_corrections({'universities':modified},[p],date(2026,9,25))
    assert not prepared and inactive[0]['reason']=='source_snapshot_missing_or_changed'
    assert inactive[0]['source_row_sha256']==p['source_row_sha256']


def test_duplicate_identical_rows_are_ambiguous_even_in_reviewed_snapshot():
    row,data,p=fixture();data['records'].append(deepcopy(row));p['source_snapshot_sha256']=m.source_fingerprint(data)
    prepared,inactive=m.prepare_corrections({'universities':data},[p],date(2026,9,25))
    assert not prepared and inactive[0]['reason']=='ambiguous_source_row'

@pytest.mark.parametrize('field',['name','original_url','source_row_sha256'])
def test_same_snapshot_does_not_permit_wrong_name_url_or_row(field):
    row,data,p=fixture();p[field]='0'*64 if field=='source_row_sha256' else 'other'
    prepared,inactive=m.prepare_corrections({'universities':data},[p],date(2026,9,25))
    assert not prepared and inactive[0]['reason']=='source_row_missing_or_changed'

@pytest.mark.parametrize('change',['no_row_hash','no_snapshot_hash','short_hash','mixed_identity'])
def test_missing_or_mixed_identity_is_rejected(change):
    row,data,p=fixture()
    if change=='no_row_hash':del p['source_row_sha256']
    if change=='no_snapshot_hash':del p['source_snapshot_sha256']
    if change=='short_hash':p['source_row_sha256']='a'*63
    if change=='mixed_identity':p['source_id']='institution-id'
    with pytest.raises(ValueError):m.prepare_corrections({'universities':data},[p],date(2026,9,25))


def test_duplicate_configuration_is_rejected_and_expiry_still_applies():
    row,data,p=fixture()
    with pytest.raises(ValueError):m.prepare_corrections({'universities':data},[p,p],date(2026,9,25))
    prepared,inactive=m.prepare_corrections({'universities':data},[p],date(2027,1,1))
    assert not prepared and inactive[0]['reason']=='evidence_expired_or_future'


def test_real_reviewed_graduate_pages_are_distinct_and_keep_original_data():
    import json
    from app.kb import KB
    from app.site_catalog import SiteCatalog
    patches=json.loads((ROOT/'kb/sources/verified_corrections.json').read_text())['records']
    patches=[r for r in patches if r.get('source_row_sha256') and r['source_dataset']=='universities']
    assert len([p for p in patches if p['name'].startswith('평택대학교 ')])==7
    raw=json.loads((ROOT/'kb/sources/universities.json').read_text())
    records=[r for r in KB.load().catalog.by_id.values() if r.get('correction_source_row_sha256') and r['kind']=='university']
    assert {r['correction_source_row_sha256'] for r in records}=={p['source_row_sha256'] for p in patches}
    assert len(records)==len(patches)
    isolated=SiteCatalog(records)
    for p in patches:
        assert p['source_id'] is None and p['source_snapshot_sha256']==m.source_fingerprint(raw)
        source,=[r for r in raw['records'] if m.source_fingerprint(r)==p['source_row_sha256']]
        assert source['name']==p['name'] and source['url']==p['original_url']
        assert isolated.describe(p['url'])['name']==p['name']
        assert isolated.lookup(p['url']+('&' if '?' in p['url'] else '?')+'other=1') is None
    translation=isolated.describe('https://www.ptu.ac.kr/graduate/3556/subview.do')
    assert translation['name']=='평택대학교 통번역대학원'
    assert {r['name'] for r in translation['matched_entities']}=={'평택대학교 통번역대학원'}
    for url in ['https://www.ptu.ac.kr/','https://www.ptu.ac.kr/graduate/index.do',
                'https://other.ptu.ac.kr/graduate/3556/subview.do']:
        assert isolated.lookup(url) is None
    coverage=json.loads((ROOT/'kb/sources/coverage.json').read_text())
    excluded={r['name'] for r in coverage['excluded']}
    assert {'평택대학교 물류·정보·경영대학원','평택대학교 문화·예술융합대학원'}<=excluded
