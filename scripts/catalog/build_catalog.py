"""Build a sourced address index. Popularity is not official identity or safety."""
from pathlib import Path
import hashlib
import json
import sys
from collections import Counter, defaultdict
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'sandbox/skills/phishing-investigator/scripts'))
from checklib.parse_url import parse_url, normalize_url
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_corrections import prepare_corrections, apply_correction


def clean_with_reason(row):
    value = (row.get('url') or '').strip()
    # A leading export BOM is metadata, not part of the authority. Do not
    # repair spelling, internal spaces, punctuation, or concatenated URLs.
    original = value
    value = value.lstrip('\ufeff')
    normalizations = ['leading_export_bom_removed'] if value != original else []
    # Some directory homepage fields include this literal field label. Keep
    # the supplied absolute URL intact; never fix the URL itself or choose
    # among multiple addresses. Extracted entries retain exact URL scope.
    if value.startswith(('홈페이지http://', '홈페이지https://')):
        value = value[len('홈페이지'):]
        if value.count('://') != 1:
            return None, 'malformed_or_multiple_values'
        normalizations.append('homepage_label_removed')
    if not value or value.lower() in ('http://', 'https://'):
        return None, 'missing_homepage'
    if any(c.isspace() for c in value) or '<' in value or '>' in value:
        return None, 'malformed_or_multiple_values'
    if '://' in value and not value.startswith(('http://', 'https://')):
        return None, 'unsupported_or_malformed_scheme'
    if not value.startswith(('http://', 'https://')):
        value = 'https://' + value
    p = parse_url(value)
    if p.get('has_userinfo'):
        return None, 'userinfo_or_email'
    if p.get('is_ip_host'):
        return None, 'ip_literal_not_supported'
    if not p.get('ok') or p.get('ambiguous'):
        return None, 'invalid_or_ambiguous_url'
    sp = urlsplit(normalize_url(value)[0])
    if '.' not in p['host_ascii']:
        return None, 'invalid_hostname'
    if sp.port == 0:
        return None, 'invalid_port'
    inspection_supported = sp.port in (None, 80, 443)
    return {**row, 'url': normalize_url(value)[0], 'host': p['host_ascii'],
            'family': p['registrable_domain'], 'path': sp.path or '/', 'query': sp.query,
            **({'inspection_supported': False, 'inspection_limit_reason': 'unsupported_port'}
               if not inspection_supported else {}),
            **({'scope': 'url'} if 'homepage_label_removed' in normalizations else {}),
            **({'original_url': row['url'], 'normalization': '+'.join(normalizations)}
               if normalizations else {})}, None


def clean(row):
    return clean_with_reason(row)[0]


def identity_scope(row, names):
    # A single listed tenant is not evidence that it owns every path of a
    # shared host. Any sourced path/query is kept exact, even with one name.
    if (row.get('scope') == 'url' or row.get('inspection_supported') is False
            or row['path'] != '/' or row['query'] or len(names) > 1):
        return 'url'
    return 'host'


def main():
    source_dir = ROOT / 'kb/sources'
    groups = defaultdict(list)
    rejected = []
    counts = {}
    snapshots = {name: json.loads((source_dir / f'{name}.json').read_text()) for name in
                 ('government24', 'alio', 'schools', 'universities', 'public_hospitals',
                  'public_health', 'official_services', 'kindergartens')}
    correction_file = source_dir / 'verified_corrections.json'
    corrections = json.loads(correction_file.read_text())['records'] if correction_file.exists() else []
    prepared, inactive_corrections = prepare_corrections(snapshots, corrections)
    applied_corrections = []
    for name in ('government24', 'alio', 'schools', 'universities', 'public_hospitals', 'public_health', 'official_services', 'kindergartens'):
        data = snapshots[name]
        if not data.get('records') or data.get('errors'):
            raise ValueError(f'{name}: incomplete source snapshot')
        counts[name] = len(data['records'])
        for row in data['records']:
            original = row
            row = apply_correction(name, row, row.get('checked', data['checked']), prepared)
            rec, reason = clean_with_reason(row)
            if row is not original:
                if not rec:
                    raise ValueError('reviewed correction has an invalid URL')
                applied_corrections.append({'source_dataset': name, 'source_id': row['correction_source_id'],
                                           **{k: row[k] for k in ('correction_source_row_sha256',
                                                                  'correction_source_snapshot_sha256') if k in row},
                                           'name': row['name'], 'original_url': row['original_url'],
                                           'url': rec['url'], 'source': row['source'],
                                           'original_exclusion_reason': clean_with_reason(original)[1]})
            if rec:
                groups[rec['host']].append({**rec, 'checked': rec.get('checked', data['checked']), 'verified': True})
            else:
                rejected.append({'name': row['name'], 'url': row.get('url'), 'source': row.get('source'),
                                 'source_dataset': name, 'source_id': row.get('source_id'), 'reason': reason})
    redirects = source_dir / 'service_redirects.json'
    if redirects.exists():
        data = json.loads(redirects.read_text())
        counts['service_redirects'] = len(data['records'])
        for row in data['records']:
            rec = clean(row)
            if rec:
                groups[rec['host']].append({**rec, 'checked': data['checked'], 'verified': True})
    data = json.loads((source_dir / 'korea_traffic.json').read_text())
    popular = {}
    for row in data['records']:
        rec = clean(row)
        if rec and rec.get('inspection_supported', True) and (rec['family'] not in popular or rec.get('visits', 0) > popular[rec['family']].get('visits', 0)):
            popular[rec['family']] = rec
    selected = sorted(popular.values(), key=lambda r: (-r.get('visits', 0), r['family']))[:1000]
    if len(selected) != 1000 or data.get('errors'):
        raise ValueError('incomplete popularity snapshot')
    for rec in selected:
        groups[rec['host']].append({**rec, 'checked': data['checked'], 'verified': False})
    records = []
    for host, rows in sorted(groups.items()):
        names = {r['name'] for r in rows if r['verified']}
        # Shared hosts must not inherit identity across school/hospital paths.
        for row in rows:
            authority = host
            if row.get('inspection_supported') is False:
                sp = urlsplit(row['url'])
                authority = f'{sp.scheme}://{host}:{sp.port}'
            key = authority + row['path'] + ('?' + row['query'] if row['query'] else '')
            record = {'id': 'site_' + hashlib.sha256((key + row['name']).encode()).hexdigest()[:20],
                      'name': row['name'], 'host': host, 'family': row['family'], 'url': row['url'],
                      'scope': identity_scope(row, names), 'kind': row['kind'],
                      'verified': row['verified'], 'checked': row['checked'],
                      'source': row['source'], 'source_updated': row.get('source_updated'),
                      **{k: row[k] for k in ('publisher', 'service_name', 'evidence_type', 'source_sha256',
                                           'canonical_from', 'redirect_chain', 'expires_at',
                                           'page_access_confirmed',
                                           'inspection_supported', 'inspection_limit_reason',
                                           'original_url', 'normalization', 'original_source', 'original_checked',
                                           'correction_source_id', 'correction_source_row_sha256',
                                           'correction_source_snapshot_sha256',
                                           'correction_reason', 'correction_evidence') if k in row}}
            records.append(record)
    records = list({r['id']: r for r in records}.values())
    report = {'source_rows': counts, 'popular_selected': len(selected),
              'popular_unique_families_available': len(popular), 'indexed_records': len(records),
              'indexed_hosts': len(groups), 'excluded': rejected,
              'corrected_source_rows': applied_corrections, 'inactive_corrections': inactive_corrections,
              'excluded_by_source': dict(sorted(Counter(r['source_dataset'] for r in rejected).items())),
              'excluded_by_reason': dict(sorted(Counter(r['reason'] for r in rejected).items())),
              'excluded_source_reasons': {name: dict(sorted(Counter(r['reason'] for r in rejected
                                          if r['source_dataset'] == name).items()))
                                          for name in sorted({r['source_dataset'] for r in rejected})},
              'normalized_records': sum(bool(r.get('normalization')) for r in records),
              'identity_scopes': dict(sorted(Counter(r['scope'] for r in records if r['verified']).items())),
              'inspection_limited': [{k: r[k] for k in ('name', 'url', 'source', 'inspection_limit_reason')}
                                     for r in records if r.get('inspection_supported') is False],
              'coverage_gaps': ['주소 미제공/유효하지 않은 기관',
                                '공식 명부 자체의 누락·폐지·주소 변경 검증 필요'],
              'ranking_note': '한국 카테고리별 추정 방문량 자료에서 선정. 종합 상위 1000위가 아님.'}
    target = ROOT / 'kb/site_catalog.json'
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps({'version': 1, 'records': records}, ensure_ascii=False))
    temporary.replace(target)
    (ROOT / 'kb/sources/coverage.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k not in ('excluded', 'inspection_limited')}, ensure_ascii=False))
    print('inspection_limited', len(report['inspection_limited']))
    print('excluded', len(rejected))


if __name__ == '__main__':
    main()
