"""Reviewed exact search edges; never general domain trust or network permission."""
from datetime import datetime, timezone, timedelta
import hashlib
import json
import re
from urllib.parse import urlsplit


def record_digest(record):
    return hashlib.sha256(json.dumps(record, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def _https(url):
    p = urlsplit(url)
    return (p.scheme == 'https' and bool(p.hostname) and not p.username and not p.password
            and p.port in (None, 443) and not p.fragment and not any(c.isspace() for c in url))


def reviewed_search_relation(kb, entity, source_url, form):
    if (not entity or not entity.identity_verified or not kb.catalog_path
            or form.get('search_form') is not True or form.get('field_types') != ['other']
            or form.get('destinations_overflow') or form.get('insecure_submission')
            or len(form.get('action_urls', [])) != 1
            or form.get('submission_methods') not in (['get'], ['post'])):
        return None
    path = kb.catalog_path.parent / 'sources' / 'reviewed_search_relations.json'
    try:
        if path.stat().st_size > 262144:
            return None
        rows = json.loads(path.read_text())['relations']
        if not isinstance(rows, list):
            return None
        now = datetime.now(timezone.utc)
        record = kb.catalog.by_id.get(entity.id)
        if not record or not record.get('verified') or not kb.catalog.fresh(record):
            return None
        if source_url != record['url'] or not _https(source_url):
            return None
        for row in rows:
            try:
                if (row['source_url'] != source_url or row['source_record_sha256'] != record_digest(record)
                        or row['source_id'] != entity.id or row['destination_url'] != form['action_urls'][0]
                        or [row['method']] != form['submission_methods'] or not _https(row['destination_url'])
                        or row['review_kind'] != 'publisher_search_and_operator_evidence'
                        or not row['operator'] or not _https(row['operator_evidence']['url'])
                        or not re.fullmatch('[a-f0-9]{64}', row['operator_evidence']['sha256'])):
                    continue
                checked = datetime.fromisoformat(row['checked_at'])
                expires = datetime.fromisoformat(row['expires_at'])
                if checked <= now < expires <= checked + timedelta(hours=24):
                    return row
            except (KeyError, TypeError, ValueError):
                continue
    except (OSError, KeyError, TypeError, ValueError):
        return None
    return None
