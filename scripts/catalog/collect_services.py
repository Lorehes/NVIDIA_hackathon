"""Extract service identities from reviewed publishers' service directories.

Publisher pages/selectors are data, not hostname exceptions in the classifier.
Only service-home links or explicitly reviewed affiliate groups qualify;
app-store, unrelated footer and arbitrary links do not.
The resulting identity says who lists the service, not who authored every page.
"""
from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urljoin, urlsplit

import html5lib
import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from literal_state import read_nuxt_literal


def has_class(element, name):
    return name in element.get('class', '').split()


def json_path(value, path):
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise ValueError('service JSON structure changed')
        value = value[key]
    return value


def extract_endpoint_directory(body, publisher, page_html):
    """Parse a reviewed public JSON endpoint linked by the publisher page.

    Never execute its scripts or follow URLs from arbitrary JSON fields.
    """
    tree = html5lib.parse(page_html, namespaceHTMLElements=False)
    anchors = [e for e in tree.iter() if e.get('id') == publisher['endpoint_element_id']]
    if (len(anchors) != 1 or anchors[0].get(publisher['endpoint_attribute']) != publisher['endpoint_base']
            or publisher['data_url'] != publisher['endpoint_base'] + publisher['endpoint_path']):
        raise ValueError('publisher endpoint reference changed')
    return extract_endpoint_payload(body, publisher, page_html)


def load_service_json(body):
    if len(body) > 2_000_000:
        raise ValueError('oversized service JSON')
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result or key in ('__proto__', 'prototype', 'constructor'):
                raise ValueError('ambiguous service JSON key')
            result[key] = value
        return result
    return json.loads(body, object_pairs_hook=unique_object)


def extract_endpoint_payload(body, publisher, page_html):
    data = load_service_json(body)
    for key, expected in publisher['success_fields'].items():
        actual = json_path(data, [key])
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError('unsuccessful service JSON response')
    cards = json_path(data, publisher['records_path'])
    if not isinstance(cards, list) or len(cards) > publisher['maximum_records']:
        raise ValueError('invalid or oversized service list')
    rows = {}
    for card in cards:
        name = json_path(card, publisher['title_path'])
        if not isinstance(name, str) or not name.strip():
            raise ValueError('missing service name')
        name = ' '.join(name.split())
        for field_path in publisher['home_paths']:
            url = json_path(card, field_path)
            if url is None or url == '':
                continue
            if not isinstance(url, str):
                raise ValueError('invalid service home field')
            if any(c.isspace() or c in '{}<>\\' for c in url) or url.count('://') != 1:
                continue
            try:
                p = urlsplit(url)
                valid = (p.scheme in publisher['schemes'] and p.hostname and not p.username
                         and not p.password and p.port in (None, 80, 443)
                         and not p.path.lower().endswith(('.exe', '.dmg', '.zip', '.apk')))
            except ValueError:
                valid = False
            if not valid:
                continue
            key = (name, url)
            if key in rows:
                rows[key]['home_fields'].append('.'.join(field_path))
                continue
            rows[key] = {'name': publisher['name'] + ' ' + name, 'service_name': name,
                         'publisher': publisher['name'], 'url': url, 'scope': 'url',
                         'source': publisher['url'], 'data_source': publisher['data_url'],
                         'home_fields': ['.'.join(field_path)],
                         'kind': 'official_service_directory', 'evidence_type': 'publisher_service_link',
                         'source_sha256': hashlib.sha256(body.encode()).hexdigest(),
                         'publisher_page_sha256': hashlib.sha256(page_html.encode()).hexdigest()}
    if len(rows) > publisher['maximum_records']:
        raise ValueError('service directory scope changed')
    return list(rows.values())


def collect_paginated_directory(client, publisher, page_html):
    """Read reviewed same-origin category pages; incomplete refreshes never publish."""
    tree = html5lib.parse(page_html, namespaceHTMLElements=False)
    scripts = [e.text or '' for e in tree.iter('script')]
    for expected in publisher['reviewed_script_sha256']:
        if sum(hashlib.sha256(text.encode()).hexdigest() == expected for text in scripts) != 1:
            raise ValueError('publisher pagination or home-link template changed')
    source = urlsplit(publisher['url'])
    rows = []
    for category in publisher['categories']:
        seen = set()
        total = last = None
        page = 1
        while True:
            path = publisher['endpoint_template'].format(category=category, page=page)
            data_url = urljoin(publisher['url'], path)
            if urlsplit(data_url).netloc != source.netloc or urlsplit(data_url).scheme != 'https':
                raise ValueError('pagination endpoint origin changed')
            response = client.get(data_url)
            response.raise_for_status()
            if response.is_redirect:
                raise ValueError('publisher data location changed')
            data = load_service_json(response.text)
            paging = json_path(data, ['pagingManager'])
            current = json_path(paging, ['currentPage'])
            end = json_path(paging, ['theEndBlockNo'])
            if (type(current) is not int or current != page or type(end) is not int
                    or not 1 <= end <= publisher['maximum_pages'] or (last is not None and last != end)):
                raise ValueError('inconsistent pagination')
            last = end
            cards = json_path(data, publisher['records_path'])
            if not isinstance(cards, list) or not 1 <= len(cards) <= publisher['page_size']:
                raise ValueError('missing or oversized category page')
            for card in cards:
                row_id = json_path(card, ['seq'])
                count = json_path(card, ['total'])
                if (type(row_id) is not int or row_id in seen or type(count) is not int
                        or not 1 <= count <= publisher['maximum_records']
                        or (total is not None and total != count)
                        or json_path(card, ['gameKindName']) != category
                        or json_path(card, ['serviceFlag']) not in ('Y', 'N')):
                    raise ValueError('inconsistent category rows')
                total = count
                seen.add(row_id)
            if last != (total + publisher['page_size'] - 1) // publisher['page_size']:
                raise ValueError('pagination total mismatch')
            # The reviewed template shows home links only for serviceFlag=Y.
            eligible = [c for c in cards if c['serviceFlag'] == 'Y']
            payload = json.dumps({'gameList': eligible}, ensure_ascii=False)
            extracted = extract_endpoint_payload(payload, {**publisher, 'data_url': data_url}, page_html)
            for row in extracted:
                row['source_sha256'] = hashlib.sha256(response.text.encode()).hexdigest()
                row['directory_category'] = category
            rows.extend(extracted)
            if page == last:
                if len(seen) != total:
                    raise ValueError('incomplete category directory')
                break
            if len(cards) != publisher['page_size']:
                raise ValueError('incomplete intermediate page')
            page += 1
    if len(rows) > publisher['maximum_records']:
        raise ValueError('service directory scope changed')
    return list({(r['name'], r['url']): r for r in rows}.values())


def extract_services(html, publisher):
    tree = html5lib.parse(html, namespaceHTMLElements=False)
    if publisher.get('format') == 'named_affiliate_group':
        return extract_affiliate_group(tree, html, publisher)
    if publisher.get('format') == 'nuxt_literal_directory':
        return extract_literal_directory(tree, html, publisher)
    if publisher.get('format') == 'json_directory':
        return extract_json_directory(tree, html, publisher)
    rows = []
    for card in tree.iter():
        if publisher.get('card_class') and not has_class(card, publisher['card_class']):
            continue
        if publisher.get('link_class') and not (card.tag == 'a' and has_class(card, publisher['link_class'])):
            continue
        if publisher.get('link_href') and not (card.tag == 'a' and card.get('href') == publisher['link_href']):
            continue
        heading = next(card.iter(publisher.get('heading_tag', 'h4')), None)
        name = publisher.get('service_name') or (' '.join(''.join(heading.itertext()).split()) if heading is not None else '')
        if not name:
            continue
        for a in card.iter('a'):
            if publisher.get('home_icon_class') and not any(has_class(e, publisher['home_icon_class']) for e in a.iter()):
                continue
            url = urljoin(publisher['url'], a.get('href', '').strip())
            p = urlsplit(url)
            if p.scheme != 'https' or not p.hostname or p.username or p.password or p.port not in (None, 443):
                continue
            rows.append({'name': name if name.startswith(publisher['name']) else publisher['name'] + ' ' + name,
                         'service_name': name, 'publisher': publisher['name'], 'url': url,
                         'source': publisher['url'], 'kind': 'official_service_directory',
                         **({'scope': publisher['scope']} if publisher.get('scope') else {}),
                         'evidence_type': 'publisher_service_link',
                         'source_sha256': hashlib.sha256(html.encode()).hexdigest()})
    return list({(r['name'], r['url']): r for r in rows}.values())


def extract_affiliate_group(tree, html, publisher):
    """Read one named affiliate list, not every link in its footer or page."""
    groups = []
    for group in tree.iter():
        if not has_class(group, publisher['group_class']):
            continue
        headings = [c for c in group if c.tag == publisher['group_heading_tag']
                    and ' '.join(''.join(c.itertext()).split()) == publisher['group_heading']]
        if len(headings) == 1:
            groups.append(group)
    if len(groups) != 1:
        raise ValueError('missing or ambiguous affiliate group')
    lists = [c for c in groups[0] if c.tag == 'ul']
    if len(lists) != 1:
        raise ValueError('missing or ambiguous affiliate list')
    rows = []
    for item in lists[0]:
        if item.tag != 'li':
            continue
        links = [c for c in item if c.tag == 'a']
        if len(links) != 1:
            raise ValueError('ambiguous affiliate item')
        a = links[0]
        name = ' '.join(''.join(a.itertext()).split())
        url = a.get('href', '').strip()
        if not name or any(c.isspace() or c in '{}<>\\' for c in url):
            continue
        try:
            p = urlsplit(url)
            valid = (p.scheme == 'https' and p.hostname and not p.username and not p.password
                     and p.port in (None, 443) and url.count('://') == 1
                     and not p.path.lower().endswith(('.exe', '.dmg', '.zip', '.apk')))
        except ValueError:
            valid = False
        if valid:
            rows.append({'name': name, 'service_name': name, 'publisher': publisher['name'],
                         'url': url, 'source': publisher['url'], 'scope': 'url',
                         'kind': 'official_affiliate_directory', 'evidence_type': 'publisher_affiliate_link',
                         'source_sha256': hashlib.sha256(html.encode()).hexdigest()})
    rows = list({(r['name'], r['url']): r for r in rows}.values())
    if len(rows) > publisher['maximum_records']:
        raise ValueError('affiliate directory scope changed')
    return rows


def extract_json_directory(tree, html, publisher):
    """Read only the reviewed JSON field path; never execute page scripts."""
    scripts = [e.text or '' for e in tree.iter('script')
               if e.get('id') == publisher['script_id'] and e.get('type') == 'application/json']
    if len(scripts) != 1 or len(scripts[0]) > 2_000_000:
        raise ValueError('missing, ambiguous or oversized service JSON')
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result or key in ('__proto__', 'prototype', 'constructor'):
                raise ValueError('ambiguous service JSON key')
            result[key] = value
        return result
    data = json.loads(scripts[0], object_pairs_hook=unique_object)
    for key in publisher['state_path']:
        data = data[key]
    rows = []
    shape = publisher.get('group_shape', 'list')
    if shape not in ('list', 'object'):
        raise ValueError('unreviewed service group shape')
    for group in publisher['groups']:
        cards = data[group]
        if shape == 'object':
            if not isinstance(cards, dict):
                raise ValueError('invalid service object')
            cards = [cards]
        if not isinstance(cards, list):
            raise ValueError('invalid service group')
        for card in cards:
            if not isinstance(card, dict):
                raise ValueError('invalid service card')
            name, url = card.get(publisher['title_key']), card.get(publisher['url_key'])
            if not isinstance(name, str) or not name.strip() or not isinstance(url, str):
                continue
            # Template branches, concatenated values and downloads are not home URLs.
            if any(c.isspace() or c in '{}<>\\' for c in url) or url.count('://') != 1:
                continue
            try:
                p = urlsplit(url)
                valid = (p.scheme in publisher.get('schemes', ['https']) and p.hostname
                         and not p.username and not p.password and p.port in (None, 80, 443)
                         and not p.path.lower().endswith(('.exe', '.dmg', '.zip', '.apk')))
            except ValueError:
                valid = False
            if not valid:
                continue
            rows.append({'name': name if name.startswith(publisher['name']) else publisher['name'] + ' ' + name,
                         'service_name': name, 'publisher': publisher['name'], 'url': url,
                         'source': publisher['url'], 'kind': 'official_service_directory',
                         'scope': 'url', 'evidence_type': 'publisher_service_link',
                         'source_sha256': hashlib.sha256(html.encode()).hexdigest()})
    return list({(r['name'], r['url']): r for r in rows}.values())


def extract_literal_directory(tree, html, publisher):
    scripts = [e.text for e in tree.iter('script') if (e.text or '').lstrip().startswith('window.__NUXT__=')]
    if len(scripts) != 1:
        raise ValueError('missing or ambiguous service state')
    data = read_nuxt_literal(scripts[0])
    for key in publisher['state_path']:
        data = data[key]
    rows = []
    for group_name, cards in data.items():
        for card in cards:
            if (card.get('deleteYn') != 'N' or card.get('temporaryYn') != 'N'
                    or card.get('contentType') != publisher['content_type']):
                continue
            for group in card.get('linkGroups', []):
                for link in group.get('links', []):
                    web_link = (link.get('linkTitle') in publisher['web_link_titles'] or
                                (link.get('linkTitle') is None and link.get('resourceType') == publisher['web_icon_type']))
                    if link.get('deleteYn') != 'N' or link.get('templateType') != 'LINKS' or not web_link:
                        continue
                    url = link.get('linkUrl') or ''
                    try:
                        p = urlsplit(url)
                        valid = (p.scheme == 'https' and p.hostname and not p.username and not p.password
                                 and p.port in (None, 443) and not p.path.lower().endswith(('.exe', '.dmg', '.zip', '.apk')))
                    except ValueError:
                        valid = False
                    if not valid or not card.get('title'):
                        continue
                    rows.append({'name': card['title'], 'service_name': card['title'], 'publisher': group_name,
                                 'url': url, 'source': publisher['url'], 'kind': 'official_service_directory',
                                 'evidence_type': 'publisher_service_link',
                                 **({'scope': publisher['scope']} if publisher.get('scope') else {}),
                                 'source_sha256': hashlib.sha256(html.encode()).hexdigest()})
    return list({(r['name'], r['url']): r for r in rows}.values())


def refresh_rows(existing, updates, selected_sources):
    """A partial refresh must not renew evidence that was not fetched."""
    return [{**r, 'checked': r.get('checked', existing['checked'])}
            for r in existing['records'] if r['source'] not in selected_sources] + updates


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', action='append', help='Refresh only this configured source URL')
    args = parser.parse_args()
    directory = ROOT / 'kb/sources'
    publishers = json.loads((directory / 'service_publishers.json').read_text())['publishers']
    selected = set(args.source or [p['url'] for p in publishers])
    if selected - {p['url'] for p in publishers}:
        raise ValueError('unreviewed publisher source')
    target = directory / 'official_services.json'
    checked = datetime.now(timezone.utc).date().isoformat()
    existing = json.loads(target.read_text()) if target.exists() else {'checked': checked, 'records': []}
    rows = []
    with httpx.Client(timeout=30, follow_redirects=False) as client:
        for publisher in publishers:
            if publisher['url'] not in selected:
                continue
            response = client.get(publisher['url'])
            response.raise_for_status()
            # A changed publisher location must be reviewed before granting identity.
            if response.is_redirect:
                raise ValueError('publisher location changed')
            if publisher.get('format') == 'paginated_json_directory':
                extracted = collect_paginated_directory(client, publisher, response.text)
            elif publisher.get('format') == 'json_endpoint_directory':
                data_response = client.get(publisher['data_url'])
                data_response.raise_for_status()
                if data_response.is_redirect:
                    raise ValueError('publisher data location changed')
                extracted = extract_endpoint_directory(data_response.text, publisher, response.text)
            else:
                extracted = extract_services(response.text, publisher)
            if len(extracted) < publisher['minimum_records']:
                raise ValueError('incomplete service directory; retaining previous snapshot')
            rows.extend({**r, 'checked': checked} for r in extracted)
    rows = refresh_rows(existing, rows, selected)
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps({'checked': checked, 'records': rows}, ensure_ascii=False, indent=2))
    temporary.replace(target)
    print('official service links:', len(rows))


if __name__ == '__main__':
    main()
