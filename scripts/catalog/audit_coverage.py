"""Give every excluded source row a stable review identity without inventing URLs."""
from collections import Counter, defaultdict
import json
from pathlib import Path
from source_corrections import source_fingerprint

ROOT=Path(__file__).resolve().parents[2]


def audit(coverage, snapshots, reviews):
    names=Counter(row['name'] for data in snapshots.values() for row in data['records'])
    indexes={}
    snapshot_hashes={dataset:source_fingerprint(data) for dataset,data in snapshots.items()}
    identity_counts={dataset:Counter(r.get('source_id') for r in data['records'] if r.get('source_id'))
                     for dataset,data in snapshots.items()}
    for dataset,data in snapshots.items():
        idx=defaultdict(list)
        for row in data['records']:
            idx[(row.get('source_id'),row['name'],row.get('url'))].append(row)
        indexes[dataset]=idx
    approved={(r['dataset'],r['source_row_sha256'],r['source_snapshot_sha256']):r for r in reviews}
    rows=[]
    for position,excluded in enumerate(coverage['excluded']):
        dataset=excluded['source_dataset'];data=snapshots[dataset]
        matched=indexes[dataset].get((excluded.get('source_id'),excluded['name'],excluded.get('url')),[])
        id_count=identity_counts[dataset].get(excluded.get('source_id'),0)
        row={'dataset':dataset,'name':excluded['name'],'original_url':excluded.get('url'),
             'reason':excluded['reason'],'source':excluded['source'],'source_id':excluded.get('source_id'),
             'same_name_source_rows':names[excluded['name']], 'matching_source_rows':len(matched),
             'coverage_row_index':position,
             'source_id_rows':id_count,
             'status':'needs_source_disambiguation' if len(matched)!=1 or id_count>1 else 'needs_official_evidence'}
        if len(matched)==1:
            original=matched[0];digest=source_fingerprint(original);snapshot=snapshot_hashes[dataset]
            row.update(source_row_sha256=digest,source_snapshot_sha256=snapshot,
                       region=original.get('region'),education_office=original.get('education_office'),
                       source_updated=original.get('source_updated'))
            review=approved.get((dataset,digest,snapshot))
            if review and id_count<=1:row.update(status=review['status'],review_evidence=review['evidence'])
        row['review_id']=source_fingerprint({k:row.get(k) for k in ('dataset','source_id','name','original_url','source_row_sha256','coverage_row_index')})
        rows.append(row)
    return {'excluded_count':len(rows),'by_status':dict(Counter(r['status'] for r in rows)),
            'by_source':dict(Counter(r['dataset'] for r in rows)),
            'ambiguous_names':sum(r['same_name_source_rows']>1 for r in rows),
            'source_join_failures':sum(r['matching_source_rows']!=1 for r in rows),
            'nonunique_source_id_rows':sum(r['source_id_rows']>1 for r in rows),
            'note':'Review queue only; reviewed status is not a registered homepage or proof of current operation.',
            'records':rows}


def main():
    directory=ROOT/'kb/sources';coverage=json.loads((directory/'coverage.json').read_text())
    names={r['source_dataset'] for r in coverage['excluded']}
    snapshots={n:json.loads((directory/(n+'.json')).read_text()) for n in names}
    review_path=directory/'institution_status_reviews.json'
    reviews=json.loads(review_path.read_text())['records'] if review_path.exists() else []
    report=audit(coverage,snapshots,reviews)
    target=directory/'coverage_review_queue.json'
    temp=target.with_suffix('.tmp');temp.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');temp.replace(target)
    print(json.dumps({k:v for k,v in report.items() if k!='records'},ensure_ascii=False))


if __name__=='__main__':main()
