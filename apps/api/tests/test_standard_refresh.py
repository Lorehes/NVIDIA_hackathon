"""Offline refresh integration: preserve reviewed data and source ambiguity."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/catalog'))
try:
    spec = importlib.util.spec_from_file_location('standard_refresh', ROOT / 'scripts/catalog/collect_education.py')
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
finally:
    sys.path.pop(0)


@pytest.fixture
def directory(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, 'OUT', tmp_path)
    old = {'checked': '2026-09-25', 'records': [{
        'name': '반송보건진료소', 'url': '', 'kind': 'public_health',
        'source_updated': '2026-07-01',
        'source': 'https://www.data.go.kr/data/15107750/standard.do'}], 'published_count': 1}
    patch = {'source_dataset': 'public_health', 'source_id': None,
             'source_row_sha256': collector.source_fingerprint(old['records'][0]),
             'source_snapshot_sha256': collector.source_fingerprint(old),
             'name': '반송보건진료소', 'original_url': '',
             'url': 'https://health.example/directory', 'scope': 'url',
             'source': 'https://health.example/directory',
             'checked': datetime.now(timezone.utc).date().isoformat(),
             'evidence': [{'kind': 'official_institution_page'}]}
    for name, data in [('public_health', old), ('verified_corrections', {'records': [patch]})]:
        (tmp_path / (name + '.json')).write_text(json.dumps(data, ensure_ascii=False))
    return tmp_path


def collect(rows, total=None, columns=None):
    columns = columns or {'HT_INST_NM': '보건기관명', 'HMPG_ADDR': '홈페이지주소',
                          'CRTR_YMD': '데이터기준일자', **collector.STANDARD_CONTEXT}
    meta = {'totalCount': len(rows) if total is None else total,
            'columList': [{'columCode': k, 'columNm': v} for k, v in columns.items()],
            'tableVO': {'svcTableNm': 'fixture', 'colNmList': ['HT_INST_NM', 'HMPG_ADDR', 'CRTR_YMD']}}
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=meta if len(requests) == 1 else rows)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = collector.standard(client, 'public_health', '15107750', 'HT_INST_NM', 'public_health')
    return result, requests


def row(**kwargs):
    return {'HT_INST_NM': '반송보건진료소', 'HMPG_ADDR': '', 'CRTR_YMD': '2026-07-01',
            'CTPV_NM': '지역A', 'SGG_NM': '군A', 'INSTT_CODE': '00123', 'INSTT_NM': '제공청',
            'LCTN_ROAD_NM_ADDR': '공공시설 주소', 'TELNO': 'omit-phone',
            'UNEXPECTED': 'omit-extra', **kwargs}


def test_refresh_keeps_active_and_reviews_duplicate_names_and_old_corrections(directory):
    before = {p: p.read_bytes() for p in directory.glob('*.json')}
    candidate, requests = collect([row(), row(CTPV_NM='지역B', SGG_NM='군B')])
    assert all(p.read_bytes() == value for p, value in before.items())
    records = candidate['snapshot']['records']
    assert len(records) == 2 and records[0]['source_context']['SGG_NM'] == '군A'
    assert records[1]['source_context']['SGG_NM'] == '군B'
    assert records[0]['source_context']['INSTT_CODE'] == '00123'
    assert all('source_id' not in r for r in records)
    assert 'omit-phone' not in json.dumps(candidate) and 'omit-extra' not in json.dumps(candidate)
    assert candidate['repeated_names'] == {'반송보건진료소': 2}
    assert candidate['correction_review']['applicable'] == 0
    assert candidate['correction_review']['inactive'][0]['reason'] == 'source_snapshot_missing_or_changed'
    assert candidate['baseline_snapshot_sha256'] == collector.source_fingerprint(json.loads(before[directory / 'public_health.json']))
    assert candidate['status'] == 'requires_source_review'
    assert {'INSTT_CODE', 'SGG_NM'} <= set(requests[1].url.params.get_list('colNmList'))
    saved = json.loads((directory / 'refresh_candidates/public_health.json').read_text())
    assert saved == candidate


@pytest.mark.parametrize('case', ['short', 'empty', 'not_list', 'bad_row', 'missing_name', 'bad_context', 'bad_url'])
def test_invalid_response_never_replaces_active_or_previous_candidate(directory, case):
    collect([row()])
    before = {p: p.read_bytes() for p in directory.rglob('*.json')}
    rows, total = [row()], 1
    if case == 'short': total = 2
    if case == 'empty': rows, total = [], 0
    if case == 'not_list': rows = {'error': 'failed'}
    if case == 'bad_row': rows = ['bad']
    if case == 'missing_name': rows = [row(HT_INST_NM='')]
    if case == 'bad_context': rows = [row(SGG_NM={'unexpected': 'nested'})]
    if case == 'bad_url': rows = [row(HMPG_ADDR=['multiple'])]
    with pytest.raises(ValueError): collect(rows, total)
    assert all(p.read_bytes() == value for p, value in before.items())


def test_unknown_or_missing_context_is_not_inferred_and_raw_spelling_is_kept(directory):
    columns = {'HT_INST_NM': '보건기관명', 'HMPG_ADDR': '홈페이지주소', 'CRTR_YMD': '데이터기준일자',
               'CTPV_NM': 'unexpected renamed meaning', 'INSTT_CODE': '제공기관코드'}
    candidate, _ = collect([row(HT_INST_NM=' 수항보건진료소 ', HMPG_ADDR='bad url value')], columns=columns)
    record, = candidate['snapshot']['records']
    assert record['name'] == ' 수항보건진료소 ' and record['url'] == 'bad url value'
    assert record['source_context'] == {'INSTT_CODE': '00123'}
    assert 'source_id' not in record


def test_university_branch_context_does_not_become_an_identity(directory):
    candidate, _ = collect([row(MAINBRANCH_NM='분교', CTPV_CD='01')])
    context = candidate['snapshot']['records'][0]['source_context']
    assert context['MAINBRANCH_NM'] == '분교' and context['CTPV_CD'] == '01'
