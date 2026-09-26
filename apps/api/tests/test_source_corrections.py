from datetime import date
import importlib.util
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from app.kb import KB
from app.site_catalog import SiteCatalog

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('source_corrections', ROOT / 'scripts/catalog/source_corrections.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    row = {'source_id':'id-one', 'name':'동명유치원', 'url':'http:// old .example', 'source':'https://directory.example/'}
    patch = {'source_dataset':'kindergartens', 'source_id':'id-one', 'name':row['name'],
             'original_url':row['url'], 'url':'https://schools.example/tenant-a/?id=1', 'scope':'url',
             'source':'https://schools.example/tenant-a/?id=1', 'checked':'2026-09-25',
             'evidence':[{'kind':'official_institution_page'}], 'reason':'official_institution_page_confirmed'}
    return row, patch


def test_exact_source_id_name_and_original_value_are_required_not_name_only():
    row, patch = fixture()
    snapshots = {'kindergartens':{'records':[row, {**row,'source_id':'id-two'}]}}
    prepared, inactive = module.prepare_corrections(snapshots,[patch],date(2026,9,25))
    new = module.apply_correction('kindergartens',row,'2026-09-20',prepared)
    assert new['url'] == patch['url'] and new['scope']=='url'
    assert new['original_url']==row['url'] and new['original_checked']=='2026-09-20'
    assert row['url']=='http:// old .example' and not inactive
    for other in [{**row,'source_id':'id-two'}, {**row,'url':'https://new.example/'}, {**row,'name':'다른유치원'}]:
        assert module.apply_correction('kindergartens',other,'2026-09-20',prepared) is other


def test_stale_changed_and_ambiguous_corrections_are_reported_without_application():
    row, patch = fixture()
    for rows, checked, reason in [([row],'2026-01-01','evidence_expired_or_future'),
                                 ([row],'2026-09-26','evidence_expired_or_future'),
                                 ([{**row,'url':'https://updated.example/'}],'2026-09-25','source_row_missing_or_changed'),
                                 ([row,row],'2026-09-25','ambiguous_source_row')]:
        prepared, inactive = module.prepare_corrections({'kindergartens':{'records':rows}},
                                                       [{**patch,'checked':checked}],date(2026,9,25))
        assert not prepared and inactive[0]['reason']==reason
    with pytest.raises(ValueError):
        module.prepare_corrections({'kindergartens':{'records':[row]}},[patch,patch],date(2026,9,25))
    with pytest.raises(ValueError):
        module.prepare_corrections({'kindergartens':{'records':[row]}},[{**patch,'scope':'host'}],date(2026,9,25))


def test_reviewed_real_rows_keep_raw_data_and_exact_school_tenant_scopes():
    patches=json.loads((ROOT/'kb/sources/verified_corrections.json').read_text())['records']
    coverage=json.loads((ROOT/'kb/sources/coverage.json').read_text())
    assert len(patches)==len(coverage['corrected_source_rows']) and not coverage['inactive_corrections']
    kb=KB.load()
    for patch in patches:
        raw=json.loads((ROOT/'kb/sources'/f"{patch['source_dataset']}.json").read_text())
        source,=[r for r in raw['records'] if (r.get('source_id')==patch['source_id'] if patch.get('source_id')
                 else module.source_fingerprint(r)==patch['source_row_sha256'])]
        assert source['url']==patch['original_url']
        record,=[r for r in kb.catalog.by_id.values() if (r.get('correction_source_id')==patch['source_id'] if patch.get('source_id')
                 else r.get('correction_source_row_sha256')==patch['source_row_sha256'])]
        assert record['url']==patch['url'] and record['source']==patch['source']
        assert record['original_source']==source['source'] and record['correction_evidence']==patch['evidence']
        assert record['scope']=='url' and kb.catalog.describe(record['url'])['status']=='verified'
        isolated=SiteCatalog([record])
        for other in ['https://'+record['host']+'/other-school/', patch['url']+('&other=1' if '?' in patch['url'] else '?other=1')]:
            assert isolated.lookup(other) is None
        root = 'https://' + record['host'] + '/'
        if urlsplit(record['url']).path in ('', '/') and not urlsplit(record['url']).query:
            assert isolated.lookup(root) is not None
        else:
            assert isolated.lookup(root) is None


def test_school_moves_use_current_official_sources_without_name_or_host_merging():
    kb = KB.load()
    rows = list(kb.catalog.by_id.values())
    corrected = {r.get('correction_source_id'): r for r in rows if r.get('correction_source_id')}
    assert corrected['8011152']['url'] == 'https://school.cbe.go.kr/dsg-m'
    assert corrected['8011152']['original_url'] == 'http://210.106.100.174/dsg-m/M01/'
    assert corrected['8382063']['url'] == 'https://school.jbedu.kr/paekku/'
    assert corrected['a1080b4366c7a35b6b79']['name'] == '죽백초등학교병설유치원'
    assert 'mi=4431&bbsId=2349' in corrected['a1080b4366c7a35b6b79']['url']
    # The similarly named Gwangju school and other shared-school paths stay independent.
    assert kb.catalog.describe('https://kds.gen.ms.kr:452')['name'] == '대성여자중학교'
    assert kb.catalog.describe('https://kds.gen.ms.kr:452')['inspection_supported'] is False
    for url in ['https://school.cbe.go.kr/unlisted-school/', 'https://school.jbedu.kr/unlisted-school/',
                'https://jb-e.goept.kr/jb-e/na/ntt/selectNttList.do?mi=4431&bbsId=other']:
        assert kb.catalog.describe(url)['status'] == 'unverified'
    coverage = json.loads((ROOT/'kb/sources/coverage.json').read_text())
    assert any(r.get('source_id') == '645ee1250e6a8d918049' for r in coverage['excluded'])
    assert not any(r['host'] == 'www.paekku.es.kr' for r in rows)


def test_multiple_homepages_and_future_closure_notice_do_not_expand_identity():
    kb = KB.load()
    corrected = {r.get('correction_source_id'): r for r in kb.catalog.by_id.values()}
    soyang = corrected['97139b6b4a1b721d18a2']
    yongam = corrected['32cb390f03fac7e2d64c']
    assert soyang['name'] == '인천소양초등학교병설유치원'
    assert 'schoolbell-e.com' in soyang['original_url']
    scoped = SiteCatalog([soyang, yongam])
    for url in ['https://schoolbell-e.com/', 'https://soyang.icees.kr/',
                soyang['url'].replace('256323', '256457'),
                'https://school.cbe.go.kr/cjyongam-e/', 'https://y-am.gwe.es.kr/']:
        assert scoped.lookup(url) is None
    notice, = [e for e in yongam['correction_evidence'] if e['kind'] == 'institution_status_notice']
    assert notice['status'] == 'closure_administrative_notice'
    assert notice['proposed_effective_date'] == '2027-03-01'
    # A future administrative notice is neither a completed closure nor proof of operation.
    assert notice['published'] == '2026-09-03'
    coverage = json.loads((ROOT/'kb/sources/coverage.json').read_text())
    assert any(r.get('source_id') == '50def7906b105b66ff3c' for r in coverage['excluded'])


def test_school_menu_review_keeps_regions_email_and_board_boundaries():
    kb = KB.load()
    corrected = {r.get('correction_source_id'): r for r in kb.catalog.by_id.values()}
    sangsan = corrected['cd0f7e01f51e07f54b1c']
    assert sangsan['original_url'] == 'ssan2092@daum.net'
    assert sangsan['url'].startswith('https://school.gyo6.net/sangsanes/')
    for source_id in ['1445d0fb16038e8b68c0', 'af9d6a6b5fcbdc9d58a0']:
        row = corrected[source_id]
        assert '.jge.es.kr/' in row['url'] and row['scope'] == 'url'
        assert any(e.get('verification_method') == 'browser_menu_navigation' for e in row['correction_evidence'])
    for source_id in ['8502025', '8522042', '8652023']:
        row = corrected[source_id]
        assert 'main.do?sysId=' in row['url'] and row['scope'] == 'url'
    isolated = SiteCatalog([corrected[i] for i in ['cd0f7e01f51e07f54b1c', '1445d0fb16038e8b68c0', 'af9d6a6b5fcbdc9d58a0']])
    for url in ['https://daum.net/', 'https://school.gyo6.net/other-school/',
                'https://school.cbe.go.kr/haksan-e/',
                corrected['af9d6a6b5fcbdc9d58a0']['url'].replace('10217567', '10217568')]:
        assert isolated.lookup(url) is None
    excluded = {r.get('source_id') for r in json.loads((ROOT/'kb/sources/coverage.json').read_text())['excluded']}
    assert {'9c138dcb48d5ac6a06bd', 'dcc762912bb47e2c0507', 'd7fffac535c0f2cc812e', '8171103'} <= excluded


def test_missing_school_homepages_keep_source_identity_and_shared_boundaries():
    kb = KB.load()
    corrected = {r.get('correction_source_id'): r for r in kb.catalog.by_id.values()}
    middle, arts = corrected['7041274'], corrected['7011149']
    assert middle['name'] == '지구촌학교 중학교'
    assert arts['name'] == '학력인정 한림연예예술고등학교'
    assert middle['original_url'] == arts['original_url'] == 'http://'
    scoped = SiteCatalog([middle, arts])
    for row in [middle, arts]:
        assert row['scope'] == 'url' and scoped.describe(row['url'])['status'] == 'verified'
        assert scoped.lookup(row['url'] + '?other=1') is None
    for url in ['https://globalsarang.sen.sc.kr/other', 'https://other.sen.sc.kr/',
                'https://www.gcfskorea.org/', 'https://www.hlyes.hs.kr/',
                'https://www.hlyes.hs.kr/html/sub0402.html', 'https://www.hl.hs.kr/']:
        assert scoped.lookup(url) is None
    names = {r['name'] for r in kb.catalog.describe(middle['url'])['matched_entities']}
    assert {'지구촌학교', '지구촌학교 중학교', '지구촌학교 고등학교'} <= names
    excluded = {r.get('source_id') for r in json.loads((ROOT/'kb/sources/coverage.json').read_text())['excluded']}
    assert '7041274' not in excluded and '7011149' not in excluded
    assert {'dcc2ade6fc90ea65b36f', '2cf59f2e9ca2f3302e0b'} <= excluded
