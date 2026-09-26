"""Revalidate reviewed search edges; unreviewed targets are candidates only.

Run on demand. This command creates no scheduler and never submits a form.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit

import html5lib
import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'apps/api'), str(ROOT/'sandbox/skills/phishing-investigator/scripts')]
from app.kb import KB
from app.search_relations import record_digest, _https
from checklib.inspect_page import inspect_page
from checklib.navigation import resolve_public_destination


def text_of(element):
    return ' '.join(' '.join(element.itertext()).split())


def text_digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def pinned_html(url):
    if not _https(url):
        raise ValueError('HTTPS default-port URL required')
    host, addresses = resolve_public_destination(url)
    # One pinned public IP per request. A failure is not evidence of a changed owner.
    with httpx.Client(timeout=8, trust_env=False, follow_redirects=False) as client:
        start=time.monotonic()
        with client.stream('GET', httpx.URL(url).copy_with(host=addresses[0]),
                           headers={'Host':host, 'User-Agent':'OfficialRelationVerifier/1.0'},
                           extensions={'sni_hostname':host}) as response:
            if response.status_code != 200 or 'text/html' not in response.headers.get('content-type','').lower():
                raise ValueError('non-200 HTML response or redirect')
            body=bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body)>2_000_000 or time.monotonic()-start>12:
                    raise ValueError('response limit exceeded')
    return bytes(body)


def refresh(kb, config, previous, fetch=pinned_html, now=None, force=False):
    now=now or datetime.now(timezone.utc)
    result=list(previous); reports=[]; cache={}
    def get(url):
        if url not in cache: cache[url]=fetch(url)
        return cache[url]
    for publisher in config['publishers']:
        edges=publisher['edges']; ids={e['source_id'] for e in edges}
        old=[r for r in previous if r['source_id'] in ids]
        if not force and len(old)==len(edges) and all(
                datetime.fromisoformat(r['expires_at'])>now+timedelta(hours=4) for r in old):
            reports.append({'publisher':publisher['operator'],'status':'not_due','retained':len(old)})
            continue
        confirmed=[]; candidates=[]; failures=[]
        try:
            reviewed=datetime.fromisoformat(publisher['reviewed_at'])
            if not reviewed <= now <= reviewed+timedelta(days=90):
                raise ValueError('publisher review expired or future')
            proof=get(publisher['evidence_url'])
            tree=html5lib.parse(proof,namespaceHTMLElements=False)
            hashes=[text_digest(text_of(p)) for p in tree.iter(publisher['evidence_tag'])]
            if hashes.count(publisher['evidence_text_sha256'])!=1:
                raise ValueError('operator statement missing, changed or duplicated')
            for edge in edges:
                try:
                    record=kb.catalog.by_id[edge['source_id']]
                    if (not record['verified'] or not kb.catalog.fresh(record)
                            or record_digest(record)!=edge['source_record_sha256']
                            or record['url']!=edge['source_url']):
                        raise ValueError('source record changed or stale')
                    body=get(edge['source_url']); page=inspect_page(body,edge['source_url'])
                    if not page.get('ok'): raise ValueError('source HTML parse failed')
                    forms=[f for f in page['forms'] if f.get('search_form') and not f.get('insecure_submission')
                           and not f.get('destinations_overflow') and f.get('field_types')==['other']]
                    candidates.extend({'source_id':edge['source_id'],'action_urls':f['action_urls'],
                                       'methods':f['submission_methods'],'status':'unreviewed'} for f in forms
                                      if f['action_urls']!=[edge['destination_url']] or f['submission_methods']!=[edge['method']])
                    if not any(f['action_urls']==[edge['destination_url']] and f['submission_methods']==[edge['method']] for f in forms):
                        raise ValueError('reviewed search form missing or changed')
                    destination=get(edge['destination_url'])
                    dest_tree=html5lib.parse(destination,namespaceHTMLElements=False)
                    titles=list(dest_tree.iter('title'))
                    if len(titles)!=1 or text_of(titles[0])!=edge['destination_title']:
                        raise ValueError('destination title changed')
                    confirmed.append({k:edge[k] for k in ('source_id','source_url','source_record_sha256','destination_url','method')} | {
                        'operator':publisher['operator'],'review_kind':'publisher_search_and_operator_evidence',
                        'operator_evidence':{'url':publisher['evidence_url'],'sha256':hashlib.sha256(proof).hexdigest()},
                        'checked_at':now.isoformat(),'expires_at':(now+timedelta(hours=24)).isoformat(),
                        'refresh_evidence':{'source_body_sha256':hashlib.sha256(body).hexdigest(),
                                            'destination_body_sha256':hashlib.sha256(destination).hexdigest(),
                                            'operator_text_sha256':publisher['evidence_text_sha256']}})
                except (OSError,ValueError,KeyError,httpx.HTTPError) as exc:
                    failures.append({'source_id':edge['source_id'],'error':str(exc)[:160]})
        except (OSError,ValueError,KeyError,httpx.HTTPError) as exc:
            failures.append({'publisher':publisher['operator'],'error':str(exc)[:160]})
        # Remove failed selected edges immediately; don't extend stale evidence.
        result=[r for r in result if r['source_id'] not in ids]+confirmed
        reports.append({'publisher':publisher['operator'],'status':'refreshed' if not failures else 'unconfirmed',
                        'confirmed':len(confirmed),'failures':failures,'candidates':candidates})
    return result,reports


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--force',action='store_true');args=p.parse_args()
    directory=ROOT/'kb/sources'; target=directory/'reviewed_search_relations.json'
    config=json.loads((directory/'search_relation_publishers.json').read_text())
    data=json.loads(target.read_text())
    records,report=refresh(KB.load(),config,data['relations'],force=args.force)
    temporary=target.with_suffix('.tmp')
    temporary.write_text(json.dumps({'schema_version':1,'relations':records},ensure_ascii=False,indent=2)+'\n')
    temporary.replace(target)
    output=directory/'search_relation_refresh_report.json'
    output.write_text(json.dumps({'checked_at':datetime.now(timezone.utc).isoformat(),'publishers':report},ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'relations':len(records),'report':str(output)},ensure_ascii=False))


if __name__=='__main__': main()
