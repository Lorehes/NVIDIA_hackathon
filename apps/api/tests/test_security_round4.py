"""보안 점검 4라운드(Codex R4-01~R4-12) 회귀 테스트. 각 시험은 해당 지적의 재현 조건을 그대로 쓴다."""
import sqlite3
import time

import pytest

from app import explain as ex
from app.db import DB, SCHEMA
from app.sandbox import CmdResult
from app.urls import trimmed_urls
from app.worker import files_mismatch

from .test_sandbox_openshell import FULL_ID, FakeRunner, payload, sb
from .test_security_round3 import EVIL_NAME, PAGE, _caution, _forms, _safe_ev
from .test_urls_kb_explain import kb
from .test_verdict import decide, page

from checklib import fetch_chain as fc  # noqa: E402
from checklib import inspect_page as ip  # noqa: E402
from checklib.parse_url import normalize_url, parse_url  # noqa: E402


# ── R4-01: 값이 문장 경계를 넘어 홀로 문장이 되면 안 된다 ────────────────────────────────
def test_masked_value_cannot_become_a_standalone_sentence():
    template, payload_ = _caution(EVIL_NAME)
    base = {"headline": "x", "recommended_action": "y"}
    bad = f"{EVIL_NAME}. 앱이나 대표 전화번호로 직접"
    assert ex.validate({**base, "detail": bad}, payload_, kb, template) is None
    assert ex.validate({**base, "detail": f"{EVIL_NAME}! 앱이나 대표 전화번호로 직접"}, payload_, kb, template) is None
    assert ex.validate({**base, "detail": f"{EVIL_NAME}: 앱이나 대표 전화번호로 직접"}, payload_, kb, template) is None
    # 값이 템플릿과 같은 자리에서 쓰이는 문장은 통과한다
    ok = {**base, "detail": f"\"{EVIL_NAME}\"의 진짜 주소는 저희 목록에 없어요."}
    assert ex.validate(ok, payload_, kb, template)


def test_ending_punctuation_of_the_last_word_may_differ():
    from .test_urls_kb_explain import GOOD, TEMPLATE, _payload

    assert ex.validate({**GOOD, "detail": "주소에 속임수를 썼어요"}, _payload(), kb, TEMPLATE)  # 마침표를 뗀 짧은 문장
    assert ex.validate({**GOOD, "detail": "속임수를. 썼어요"}, _payload(), kb, TEMPLATE) is None


# ── R4-02: 정규식이 끊은 주소도 잘림으로 표시한다 ─────────────────────────────────────────
def test_url_cut_by_quote_characters_is_marked():
    assert trimmed_urls("https://hanbit.example/login'phish") == {"https://hanbit.example/login"}
    assert trimmed_urls("https://hanbit.example/a>x") == {"https://hanbit.example/a"}
    assert trimmed_urls("<https://hanbit.example/a>") == set()  # 짝이 맞는 구분 부호
    assert trimmed_urls('"https://hanbit.example/a" 확인') == set()


# ── R4-03: 퍼센트 인코딩된 점 세그먼트 ────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,fixed", [
    ("https://hanbit.example/a/%2e%2e/phish", "https://hanbit.example/phish"),
    ("https://hanbit.example/a/%2E%2e/phish", "https://hanbit.example/phish"),
    ("https://hanbit.example/a/./b/../c", "https://hanbit.example/a/c"),
    ("https://hanbit.example/a/b/%2e", "https://hanbit.example/a/b/"),
    ("https://hanbit.example/?x=/%2e%2e/y", "https://hanbit.example/?x=/%2e%2e/y"),  # 질의는 건드리지 않는다
])
def test_dot_segments_are_collapsed_like_a_browser(raw, fixed):
    assert normalize_url(raw)[0] == fixed


def test_fetcher_requests_the_collapsed_path_and_the_change_is_marked_ambiguous():
    seen = []

    class One:
        def get(self, url):
            seen.append(url)
            return fc.Response(200, None, b"<html></html>")

    fc.fetch_chain("https://hanbit.example/a/%2e%2e/phish", One())
    assert seen == ["https://hanbit.example/phish"]
    assert parse_url("https://hanbit.example/a/%2e%2e/phish")["ambiguous"] is True
    assert parse_url("https://hanbit.example/a/b")["ambiguous"] is False


# ── R4-04: 전송 대상이 많아도 하나도 빠뜨리지 않는다 ─────────────────────────────────────────
def test_many_destinations_are_folded_by_domain_and_never_dropped():
    same_site = "".join(f'<button formaction="https://s{i}.hanbit.example/">x</button>' for i in range(9))
    r = _forms(f'<form action="/ok"><input type=password>{same_site}'
               '<button formaction="https://evil.test">go</button></form>')
    f = r["forms"][0]
    assert {d["registrable_domain"] for d in f["destinations"]} == {"hanbit.example", "evil.test"}
    ev = _safe_ev(page={**page(), "forms": r["forms"]})
    o = decide(**ev)
    assert o.verdict != "safe"
    assert next(s for s in o.signals if s["type"] == "cross_domain_form")["data"]["action_domain"] == "evil.test"


def test_destination_overflow_prevents_safe():
    many = "".join(f'<button formaction="https://d{i}.test/">x</button>' for i in range(30))
    r = _forms(f'<form action="/ok"><input type=password>{many}</form>')
    f = r["forms"][0]
    assert f["destinations_overflow"] is True and f["cross_domain"] is True
    trusted = {**f, "destinations": [{"host": "hanbit.example", "registrable_domain": "hanbit.example",
                                      "cross_domain": False}], "cross_domain": True, "destinations_overflow": True}
    assert decide(**_safe_ev(page={**page(), "forms": [trusted]})).verdict != "safe"


# ── R4-05: 글자로 읽히는 문맥의 form 태그 ────────────────────────────────────────────────────
@pytest.mark.parametrize("opener,closer", [("textarea", "textarea"), ("template", "template"), ("title", "title"),
                                           ("noscript", "noscript"), ("xmp", "xmp")])
def test_fake_form_in_text_context_does_not_hide_the_real_form(opener, closer):
    r = _forms(f'<{opener}><form></{closer}><form action="https://evil.test"><input type=password>'
               '<button>Go</button></form>')
    if opener == "template":  # html5lib는 template를 명세대로 읽지 못하므로 안전 판정에서 뺀다
        assert "(unmodeled)" in r["external_active_domains"]
        assert decide(**_safe_ev(page={**page(), "external_active_domains": r["external_active_domains"]})).verdict != "safe"
        return
    assert any(f["cross_domain"] and "password" in f["field_types"] for f in r["forms"])
    assert decide(**_safe_ev(page={**page(), "forms": r["forms"]})).verdict != "safe"


def test_real_nested_forms_are_still_ignored():
    r = _forms('<form action="https://evil.test"><form action="/ok"><input type=password></form></form>')
    assert len(r["forms"]) == 1 and r["forms"][0]["cross_domain"] is True


# ── R4-06: 문자셋 ──────────────────────────────────────────────────────────────────────────────
def test_only_a_real_charset_parameter_counts():
    body = "<p>ok</p>".encode("utf-16-le") + b'<script src="https://evil.test/a.js"></script>'
    r = _forms(body, ctype="text/html; xcharset=utf-16le")
    assert r["ok"] is False  # UTF-16으로 읽지 않는다: NUL이 섞여 분석 실패 → 안전 판정 불가
    r = _forms("<script src='https://evil.test/a.js'></script>".encode("utf-16-le"), ctype="text/html; charset=utf-16le")
    assert r["ok"] and r["external_active_domains"] == ["evil.test"]  # 진짜 charset 매개변수는 따른다
    assert ip._content_type_charset('text/html; a=b; Charset="EUC-KR"') == "EUC-KR"
    assert ip._content_type_charset("text/html; xcharset=utf-8") is None


def test_iso_2022_jp_body_is_decoded_like_a_browser():
    body = b'\x1b$B<!--\x1b(B<script src="https://evil.test/a.js"></script>-->'
    r = _forms(body, ctype="text/html; charset=iso-2022-jp")
    assert r["ok"] and r["external_active_domains"] == ["evil.test"]


def test_meta_charset_is_read_from_real_attributes_only():
    body = b'<meta xcharset="utf-16le"><script src="https://evil.test/a.js"></script>'
    assert _forms(body)["external_active_domains"] == ["evil.test"]
    kr = '<meta http-equiv="Content-Type" content="text/html; charset=euc-kr">'.encode() + \
        '<form action="https://evil.test"><input type=password></form>'.encode("euc-kr")
    assert _forms(kr)["forms"][0]["cross_domain"] is True
    assert ip._meta_charset(b'<meta data-charset="x" charset="euc-kr" charset="utf-8">') == "euc-kr"


# ── R4-07: srcdoc 안의 APK 링크 ───────────────────────────────────────────────────────────────
def test_apk_links_are_collected_from_nested_documents():
    r = _forms('<iframe srcdoc="&lt;a href=https://evil.test/malware.apk&gt;Install&lt;/a&gt;"></iframe>')
    assert r["apk_links"] == ["https://evil.test/malware.apk"]
    r = _forms('<base href="https://cdn.evil.test/"><a href="m.apk?x=1">Install</a>')
    assert r["apk_links"] == ["https://cdn.evil.test/m.apk?x=1"]


# ── R4-08·R4-09: 모듈 import와 링크 자동 클릭 ────────────────────────────────────────────────────
@pytest.mark.parametrize("script", [
    'import "https://evil.test/a.js";',
    'import {a} from "https://evil.test/a.js";',
    'export * from "https://evil.test/a.js";',
    'importScripts("https://evil.test/a.js")',
    'new Worker("https://evil.test/w.js")',
    'document.getElementById("go").click()',
    'go.dispatchEvent(new MouseEvent("click"))',
])
def test_module_loading_and_programmatic_activation_are_detected(script):
    assert _forms(f'<a id=go href="https://evil.test">Continue</a><script type="module">{script}</script>'
                  )["js_redirect_hint"] is True


# ── R4-10: 공격자가 만든 큰 HTML에서 처리 시간이 입력에 비례해야 한다 ──────────────────────────────────
HOSTILE = {
    "titles": lambda: "<title>" + "|".join(f"t{i}" for i in range(124_000)) + "</title>",
    "actions": lambda: '<form action="/x">' + "".join(f'<button formaction="https://d{i}.test/">x</button>'
                                                      for i in range(20_000)) + "</form>",
    "scripts": lambda: "".join(f'<script src="https://d{i}.test/a.js"></script>' for i in range(20_000)),
    "forms": lambda: "".join(f'<form action="/f{i}"><input name=a{i}></form>' for i in range(20_000)),
    "links": lambda: "".join(f'<a href="/{i}.apk">x</a>' for i in range(30_000)),
    "labels": lambda: "".join(f"<label for=a{i}>l{i}</label><input id=a{i}>" for i in range(15_000)),
    "srcdocs": lambda: '<iframe srcdoc="x"></iframe>' * 20_000,
    "handlers": lambda: "".join(f'<b onclick="v{i}=1">x</b>' for i in range(20_000)),
    "comments": lambda: "<script>" + "location/*" * 100_000 + "</script>",
    "quotes": lambda: "<script>" + '"  ' * 300_000 + "</script>",
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_inspection_time_is_bounded_on_large_hostile_pages(name):
    html = HOSTILE[name]()
    t0 = time.time()
    r = _forms(html)
    assert time.time() - t0 < 8, name
    assert r["ok"] and len(r["brand_candidates"]) <= 6 and len(r["external_active_domains"]) <= 11


def test_many_external_domains_prevent_safe_instead_of_being_dropped_silently():
    r = _forms("".join(f'<script src="https://d{i}.test/a.js"></script>' for i in range(50)))
    assert "(nested)" in r["external_active_domains"]


# ── R4-11: 늦게 도착한 정리가 진행 중인 작업을 지우면 안 된다 ────────────────────────────────────────
def test_reconciliation_never_purges_an_active_job(tmp_path):
    class Listing(FakeRunner):
        def __call__(self, args, timeout=None):
            if args[-3:-1] == ["sh", "-c"]:
                self.calls.append(args)
                return CmdResult(0, f"{FULL_ID}\n", "")
            return super().__call__(args, timeout)

    r = Listing()
    s = sb(r, tmp_path)
    s._begin_local(FULL_ID)  # 이 작업이 진행 중이다(업로드까지 마쳤다)
    assert s._reconcile_remote() is True
    assert not [c for c in r.calls if "rm" in c and "-rf" in c]
    s._pending_purge.add(FULL_ID)
    s.retry_pending()
    assert not [c for c in r.calls if "rm" in c and "-rf" in c]
    s._end_local(FULL_ID)
    assert s._reconcile_remote() is True
    assert [c for c in r.calls if "rm" in c and "-rf" in c]  # 끝난 뒤에는 남은 폴더를 지운다


# ── R4-12: 삭제한 기록이 DB 파일에 남지 않는다 ────────────────────────────────────────────────────────
TOKEN = "SECRET-TOKEN-4f1c9d"


def _dump(path):
    return path.read_bytes()


def test_purged_rows_are_overwritten_in_the_database_file(tmp_path):
    path = tmp_path / "jobs.db"
    db = DB(path)
    for i in range(4):
        db.create({"job_id": f"j_{i}", "status": "done", "stage": "done", "mode": "live", "input": TOKEN * 50,
                   "url": f"https://a.test/{TOKEN}", "result": {"note": TOKEN * 100}, "finished_at": 1.0})
    db.update("j_0", result={"note": "updated " + TOKEN * 30})  # 갱신으로 버려진 옛 값도 대상이다
    assert db.purge_expired(60) == 4
    db._conn.close()
    assert TOKEN.encode() not in _dump(path)


def test_scrub_removes_leftovers_from_before_secure_delete_was_enabled(tmp_path):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(str(path))  # secure_delete가 꺼진 옛 DB
    raw.executescript(SCHEMA)
    raw.execute("INSERT INTO jobs (job_id,status,stage,mode,input,url,created_at) VALUES ('j','done','done','live',?,?,1)",
                (TOKEN * 200, "https://a.test/"))
    raw.commit()
    raw.execute("DELETE FROM jobs")
    raw.commit()
    raw.close()
    assert TOKEN.encode() in _dump(path)  # 사전 조건: 빈 페이지에 남아 있다
    db = DB(path)
    db.scrub()
    db._conn.close()
    assert TOKEN.encode() not in _dump(path)
