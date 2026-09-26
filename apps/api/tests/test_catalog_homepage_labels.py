"""A source field label may be removed; URL repairs and scope expansion may not."""
import importlib.util
import json
from pathlib import Path

import pytest

from app.site_catalog import SiteCatalog

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('catalog_label_builder', ROOT / 'scripts/catalog/build_catalog.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


@pytest.mark.parametrize('raw', [
    '홈페이지https://school. example/',
    '홈페이지https://one.example/,https://two.example/',
    '홈페이지https://one.example/https://two.example/',
    '홈페이지https://owner@school.example/',
    '홈페이지https://127.0.0.1/',
    '홈페이지htp://school.example/',
    '<a href="https://school.example/">홈페이지</a>',
])
def test_label_extraction_never_repairs_or_selects_urls(raw):
    assert builder.clean({'url': raw}) is None


def test_label_and_bom_keep_auditable_original_and_exact_scope():
    raw = '\ufeff홈페이지https://schools.example/kinder/?id=7'
    row = builder.clean({'url': raw})
    assert row['url'] == 'https://schools.example/kinder/?id=7'
    assert row['original_url'] == raw
    assert row['normalization'] == 'leading_export_bom_removed+homepage_label_removed'
    assert builder.identity_scope(row, {'one listed institution'}) == 'url'


def test_actual_source_labels_are_registered_without_changing_source_or_scope():
    source = json.loads((ROOT / 'kb/sources/kindergartens.json').read_text())
    rows = [r for r in source['records'] if r.get('url', '').startswith('홈페이지')]
    catalog = json.loads((ROOT / 'kb/site_catalog.json').read_text())['records']
    recovered = [r for r in catalog if r.get('normalization') == 'homepage_label_removed']
    assert len(rows) == len(recovered) == 5
    combined = SiteCatalog(catalog)
    for raw in rows:
        r, = [r for r in recovered if r['name'] == raw['name'] and r['original_url'] == raw['url']]
        assert r['url'].rstrip('/') == raw['url'][len('홈페이지'):].rstrip('/')
        assert r['checked'] == source['checked'] and r['source'] == raw['source']
        assert r['scope'] == 'url'
        scoped = SiteCatalog([r])
        assert scoped.describe(r['url'])['status'] == 'verified'
        assert scoped.lookup(r['url'].rstrip('/') + '/unlisted-tenant/') is None
        # The school and its kindergarten share the sourced homepage. The
        # single displayed match may be either; no tenant gets extra paths.
        assert combined.describe(r['url'])['status'] == 'verified'
        assert combined.lookup(r['url'].rstrip('/') + '/unlisted-tenant/') is None
