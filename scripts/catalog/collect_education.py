"""Refresh official school/university/health directories without private API keys.

Honor the NEIS download service's duplicate/concurrency limits. Standard dataset
refreshes are staged for source review; they never replace reviewed snapshots.
"""
import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone
from tempfile import NamedTemporaryFile
from pathlib import Path
import httpx
from collect_directories import OUT
from source_corrections import prepare_corrections, source_fingerprint


# Published context, not institution IDs. Keep source spelling and empty values.
STANDARD_CONTEXT = {
    'CTPV_CD': '시도코드', 'CTPV_NM': '시도명', 'SGG_NM': '시군구명',
    'HTCT_TYPE_NM': '보건기관유형명', 'LCTN_ROAD_NM_ADDR': '소재지도로명주소',
    'LCTN_LOTNO_ADDR': '소재지지번주소', 'INSTT_CODE': '제공기관코드',
    'INSTT_NM': '제공기관명', 'MAINBRANCH_NM': '본분교구분명',
    'UNIV_SE_NM': '대학구분명', 'SCHL_SE_NM': '학교구분명',
}


def stage_standard(name, records, published_count):
    """Keep reviewed active snapshots intact until an explicit evidence review.

    Candidate hashes bind later review to the active baseline. They do not
    migrate old row-hash corrections, prove closure, or authorize promotion.
    """
    if not records or len(records) != published_count:
        raise ValueError('incomplete standard candidate')
    active = OUT / (name + '.json')
    baseline = json.loads(active.read_text()) if active.exists() else None
    snapshot = {'checked': datetime.now(timezone.utc).date().isoformat(),
                'records': records, 'published_count': published_count}
    correction_file = OUT / 'verified_corrections.json'
    corrections = json.loads(correction_file.read_text())['records'] if correction_file.exists() else []
    relevant = [c for c in corrections if c['source_dataset'] == name]
    matched, inactive = prepare_corrections({name: snapshot}, relevant)
    candidate = {
        'schema_version': 1, 'status': 'requires_source_review',
        'dataset': name,
        'baseline_snapshot_sha256': source_fingerprint(baseline) if baseline else None,
        'corrections_sha256': source_fingerprint(corrections),
        'snapshot_sha256': source_fingerprint(snapshot), 'snapshot': snapshot,
        'correction_review': {'configured': len(relevant), 'applicable': len(matched),
                              'inactive': inactive},
        'repeated_names': {n: count for n, count in Counter(r['name'] for r in records).items()
                           if count > 1},
    }
    directory = OUT / 'refresh_candidates'
    directory.mkdir(exist_ok=True)
    target = directory / (name + '.json')
    # Serialize first: invalid content never replaces a previous candidate.
    content = json.dumps(candidate, ensure_ascii=False, indent=2, allow_nan=False)
    with NamedTemporaryFile(mode='w', encoding='utf-8', dir=directory, delete=False) as f:
        temporary = Path(f.name)
        try:
            f.write(content)
            f.flush()
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    print(name, len(records), 'staged; active snapshot unchanged;',
          len(inactive), 'corrections need review', flush=True)
    return candidate


def save(name, records, **meta):
    if not records:
        raise ValueError('empty snapshot')
    target = OUT / (name + '.json')
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps({'checked': datetime.now(timezone.utc).date().isoformat(), 'records': records, **meta}, ensure_ascii=False, indent=2))
    temporary.replace(target)
    print(name, len(records), flush=True)


def schools(client):
    base = 'https://open.neis.go.kr/portal/data/sheet/'
    inf = 'OPEN17020190531110010104913'
    r = client.post(base + 'checkValidBfrAllDownlaod.do', data={'infId': inf})
    r.raise_for_status()
    status = r.json()['data']
    if status.get('dpcnDwlnYn') == 'Y' or int(status.get('totlDwlnCnt', 0)) >= 4:
        raise RuntimeError('NEIS download cooldown/concurrency limit; retry later')
    client.post(base + 'insertOpenDownload.do', data={'infId': inf}).raise_for_status()
    data = {'infId': inf, 'infSeq': '1', 'downloadType': 'C_ALL',
            **{k: '' for k in ('ATPT_OFCDC_SC_CODE', 'SCHUL_NM', 'SCHUL_KND_SC_NM', 'LCTN_SC_NM', 'FOND_SC_NM')}}
    r = client.post(base + 'downloadSheetData.do', data=data)
    r.raise_for_status()
    if 'csv' not in r.headers.get('content-type', '').lower():
        raise ValueError('NEIS did not return CSV')
    rows = csv.DictReader(io.StringIO(r.content.decode('utf-8-sig')))
    source = 'https://open.neis.go.kr/portal/data/service/selectServicePage.do?infId=' + inf + '&infSeq=1'
    records = [{'name': row['학교명'], 'url': row['홈페이지주소'], 'source_id': row['행정표준코드'],
                'kind': 'school', 'school_type': row['학교종류명'], 'region': row['시도명'],
                'source_updated': row['수정일자'], 'source': source}
               for row in rows if row.get('학교명') and row.get('행정표준코드')]
    save('schools', records)


def standard(client, name, pk, name_key, kind):
    base = 'https://www.data.go.kr'
    r = client.get(base + '/download/columList.json', params={'pk': pk, 'ext': 'JSON'})
    r.raise_for_status()
    meta = r.json()
    published_columns = {c['columCode']: c['columNm'] for c in meta['columList']}
    context_columns = {key: label for key, label in STANDARD_CONTEXT.items()
                       if published_columns.get(key) == label}
    columns = list(dict.fromkeys([*meta['tableVO']['colNmList'], *context_columns]))
    params = [('publicDataPk', pk), ('totalCount', str(meta['totalCount'])),
              ('svcTableNm', meta['tableVO']['svcTableNm']), ('perPage', '10000'), ('page', '1')]
    params += [('colNmList', col) for col in columns]
    r = client.get(base + '/download/standard.json', params=params)
    r.raise_for_status()
    rows = r.json()
    if not isinstance(rows, list) or len(rows) != int(meta['totalCount']):
        raise ValueError('incomplete standard dataset; keep previous snapshot')
    records = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get(name_key), str) or not row[name_key].strip():
            raise ValueError('standard row has no institution name; keep previous snapshot')
        selected = {k: row[k] for k in context_columns if k in row}
        if any(v is not None and not isinstance(v, str)
               for v in [row.get('HMPG_ADDR', ''), row.get('CRTR_YMD'), *selected.values()]):
            raise ValueError('unexpected standard field type; keep previous snapshot')
        records.append({'name': row[name_key], 'url': row.get('HMPG_ADDR', ''), 'kind': kind,
                        'source_updated': row.get('CRTR_YMD'), 'source': f'{base}/data/{pk}/standard.do',
                        'source_context': selected})
    return stage_standard(name, records, int(meta['totalCount']))


if __name__ == '__main__':
    with httpx.Client(timeout=150, follow_redirects=True) as client:
        schools(client)
        standard(client, 'universities', '15107736', 'SCHL_NM', 'university')
        standard(client, 'public_health', '15107750', 'HT_INST_NM', 'public_health')
