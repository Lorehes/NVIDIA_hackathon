from copy import deepcopy
import importlib.util
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts/catalog'))
spec=importlib.util.spec_from_file_location('coverage_audit',ROOT/'scripts/catalog/audit_coverage.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixtures():
    rows=[{'name':'동명학교','url':'','source_id':str(i),'region':region,'source':'https://directory.example'}
          for i,region in enumerate(['서울','부산'])]
    coverage={'excluded':[dict(r,source_dataset='schools',reason='missing_homepage') for r in rows]}
    return coverage,{'schools':{'records':rows}}


def test_same_name_distinct_region_and_id_remain_separate_without_invented_homepage():
    coverage,snapshots=fixtures();before=deepcopy(snapshots)
    result=m.audit(coverage,snapshots,[])
    assert result['excluded_count']==2 and result['ambiguous_names']==2
    assert result['source_join_failures']==0
    assert {r['region'] for r in result['records']}=={'서울','부산'}
    assert len({r['review_id'] for r in result['records']})==2
    assert all(r['original_url']=='' and r['status']=='needs_official_evidence' for r in result['records'])
    assert snapshots==before


def test_review_invalidated_by_any_source_snapshot_change():
    coverage,snapshots=fixtures();row=snapshots['schools']['records'][0]
    reviews=[{'dataset':'schools','source_row_sha256':m.source_fingerprint(row),
              'source_snapshot_sha256':m.source_fingerprint(snapshots['schools']),
              'status':'historical_name_reorganized','evidence':{'source':'https://school.example'}}]
    assert m.audit(coverage,snapshots,reviews)['records'][0]['status']=='historical_name_reorganized'
    snapshots['schools']['records'][1]['region']='인천'
    assert m.audit(coverage,snapshots,reviews)['records'][0]['status']=='needs_official_evidence'


def test_duplicate_source_rows_never_silently_join_or_drop_excluded_occurrences():
    coverage,snapshots=fixtures()
    snapshots['schools']['records'].append(deepcopy(snapshots['schools']['records'][0]))
    coverage['excluded'].append(deepcopy(coverage['excluded'][0]))
    result=m.audit(coverage,snapshots,[])
    assert result['excluded_count']==3 and result['source_join_failures']==2
    assert result['by_status']=={'needs_source_disambiguation':2,'needs_official_evidence':1}
    assert len({r['review_id'] for r in result['records']})==3
    assert 'source_row_sha256' not in result['records'][0]


def test_real_queue_preserves_every_exclusion_and_all_counts():
    import json
    p=ROOT/'kb/sources';coverage=json.loads((p/'coverage.json').read_text())
    snapshots={n:json.loads((p/(n+'.json')).read_text()) for n in {r['source_dataset'] for r in coverage['excluded']}}
    report=m.audit(coverage,snapshots,json.loads((p/'institution_status_reviews.json').read_text())['records'])
    assert len(report['records'])==len(coverage['excluded'])==sum(report['by_status'].values())
    assert len({r['review_id'] for r in report['records']})==len(report['records'])
    assert sum(report['by_source'].values())==report['excluded_count']


def test_colliding_source_id_is_not_resolved_by_different_homepage_alone():
    coverage,snapshots=fixtures()
    snapshots['schools']['records'].append(dict(snapshots['schools']['records'][0],url='https://other.example',region='제주'))
    report=m.audit(coverage,snapshots,[])
    row=report['records'][0]
    assert row['matching_source_rows']==1 and row['source_id_rows']==2
    assert row['status']=='needs_source_disambiguation'
    assert report['nonunique_source_id_rows']==1
