"""Apply reviewed official evidence to exact source rows, without typo guessing."""
from datetime import datetime, timezone
from collections import Counter
import hashlib
import json
import re
from urllib.parse import urlsplit


def source_fingerprint(value):
    """Canonical JSON content hash; not an institution identifier."""
    body = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(body.encode()).hexdigest()


def correction_key(dataset, row):
    identity = ('id', row['source_id']) if row.get('source_id') else ('row', source_fingerprint(row))
    return dataset, identity, row['name'], row.get('url')


def prepare_corrections(snapshots, corrections, today=None):
    today = today or datetime.now(timezone.utc).date()
    available = Counter(correction_key(dataset, row) for dataset, data in snapshots.items()
                        for row in data['records'])
    snapshot_hashes = {name: source_fingerprint(data) for name, data in snapshots.items()}
    matched, inactive = {}, []
    seen = set()
    for item in corrections:
        source_id = item.get('source_id')
        row_hash, snapshot_hash = item.get('source_row_sha256'), item.get('source_snapshot_sha256')
        if source_id:
            if row_hash is not None or snapshot_hash is not None:
                raise ValueError('correction must use one source identity method')
            identity = ('id', source_id)
        else:
            if not all(isinstance(h, str) and re.fullmatch('[0-9a-f]{64}', h)
                       for h in (row_hash, snapshot_hash)):
                raise ValueError('ID-less correction requires exact row and snapshot hashes')
            identity = ('row', row_hash)
        key = (item['source_dataset'], identity, item['name'], item['original_url'])
        if key in seen:
            raise ValueError('duplicate correction for source row')
        seen.add(key)
        if item.get('scope') != 'url' or not item.get('evidence'):
            raise ValueError('correction requires source identity, exact scope and evidence')
        proof = urlsplit(item['source'])
        if proof.scheme != 'https' or not proof.hostname or proof.username or proof.password:
            raise ValueError('correction requires an official HTTPS evidence URL')
        age = (today - datetime.fromisoformat(item['checked']).date()).days
        reason = ('evidence_expired_or_future' if not 0 <= age <= 90 else
                  'source_snapshot_missing_or_changed' if not source_id and
                  snapshot_hashes.get(item['source_dataset']) != snapshot_hash else
                  'source_row_missing_or_changed' if available[key] == 0 else
                  'ambiguous_source_row' if available[key] != 1 else None)
        if reason:
            inactive.append({'source_dataset': item['source_dataset'], 'source_id': source_id,
                             **({'source_row_sha256': row_hash} if not source_id else {}),
                             'name': item['name'], 'reason': reason})
        else:
            matched[key] = item
    return matched, inactive


def apply_correction(dataset, row, original_checked, prepared):
    item = prepared.get(correction_key(dataset, row))
    if not item:
        return row
    return {**row, 'url': item['url'], 'source': item['source'], 'checked': item['checked'],
            'scope': 'url', 'evidence_type': 'reviewed_official_source_correction',
            'original_url': row.get('url'), 'original_source': row['source'],
            'original_checked': original_checked, 'correction_source_id': item.get('source_id'),
            **({'correction_source_row_sha256': item['source_row_sha256'],
                'correction_source_snapshot_sha256': item['source_snapshot_sha256']}
               if not item.get('source_id') else {}),
            'correction_reason': item['reason'], 'correction_evidence': item['evidence']}
