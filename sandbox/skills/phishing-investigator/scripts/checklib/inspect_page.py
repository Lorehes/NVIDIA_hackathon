"""3-4. 페이지 분석: 입력란, 전송 대상, 앱 설치 유도, 브랜드 주장, 자동 이동 흔적.

HTML은 파싱만 한다(실행하지 않음). 페이지 문구는 공격자가 만든 데이터이므로
길이를 제한한 구조화 필드로만 내보내고, 그 문구의 지시를 해석하지 않는다.

브라우저가 읽는 방식과 갈리면 검사기가 못 본 것을 브라우저가 실행할 수 있다. 그래서 문자셋은 WHATWG 이름만,
중복 속성은 첫 값만, 상대 주소는 브라우저식으로(resolve_reference), 폼 소유는 `form` 속성까지 따른다.
"""
from __future__ import annotations

import codecs
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .parse_url import registrable_of, resolve_reference, to_ascii_host

FIELD_TYPES = [
    "password", "card_number", "card_cvc", "card_expiry", "bank_account", "resident_id",
    "otp", "phone", "name", "address", "other",
]

_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("card_cvc", ("cvc", "cvv", "보안코드", "카드 뒷면", "카드뒷면", "cvc2")),
    ("card_expiry", ("expiry", "expiration", "유효기간", "만료", "mm/yy", "mmyy", "cc-exp")),
    ("card_number", ("cardnumber", "card_number", "card-number", "cardno", "카드번호", "카드 번호",
                     "cc-number", "ccnum", "card number")),
    ("bank_account", ("계좌", "accountnumber", "account_no", "account-no", "bankaccount", "acctno")),
    ("resident_id", ("주민", "rrn", "resident", "ssn", "생년월일 뒤")),
    ("otp", ("otp", "인증번호", "인증 번호", "verification", "passcode", "보안카드")),
    ("password", ("password", "passwd", "비밀번호", "비번", "pwd")),
    ("phone", ("phone", "tel", "전화", "휴대폰", "핸드폰", "mobile", "연락처")),
    ("address", ("address", "addr", "주소", "우편")),
    ("name", ("name", "성함", "이름")),
]

_TRUST_RE = re.compile(r"(공식|안전|인증|보증|정식|official|verified|secure|authentic)", re.I)

# 스크립트·이벤트 핸들러 속 이동 시도와 그것을 숨기는 난독화 흔적. JavaScript는 실행하지 않으므로 도착지를 알 수 없다.
# 토큰이 붙어 있는지에 기대지 않는다: `location`이라는 낱말이 있으면(대괄호·주석·별칭으로 갈라 써도 낱말은 남는다)
# 이동 시도로 보고, 낱말을 쪼개 이어 붙이는 기법(문자열 이어 붙이기·fromCharCode·이스케이프·전역 객체의 대괄호 접근)도 같게 본다.
_ASCII_ESC = r"\\(?:x|u00)(?:4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a])"  # 영문자를 이스케이프로 쓴 표기
_JS_REDIRECT_RE = re.compile(
    r"(?:\blocation\b"
    r"|\b(?:window|self|top|parent|document|globalThis|this|frames)\s*\["
    r"|\b(?:window|self|top|parent|globalThis)\s*\.\s*open\s*\(|(?<![\w.$])open\s*\("
    r"|\bnavigate\s*\(|\bhistory\s*\.\s*(?:push|replace)State\s*\("
    r"|\beval\s*\(|\batob\s*\(|\bFunction\s*\(|\bunescape\s*\(|\bdocument\s*\.\s*write(?:ln)?\s*\("
    r"|\bimport\b|\bimportScripts\b|\bexport\s*[*{]|\bWorker\s*\(|\.\s*click\s*\(|\bdispatchEvent\s*\("
    r"|\bfromCharCode\b|\bset(?:Timeout|Interval)\s*\(\s*[\"'`]|javascript\s*:"
    r"|\.\s*(?:action|formAction)\s*=(?!=)"
    r"|[\"'`]\s*\+\s*[\"'`]|\.\s*concat\s*\(\s*[\"'`]|\.\s*join\s*\(\s*[\"'`]{2}\s*\)|\$\{\s*[\"'`]"
    r"|" + _ASCII_ESC + r"|\\u\{)", re.I)
_SKIP_INPUT_TYPES = {"hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file"}
_MAX_DOCS = 8  # iframe srcdoc를 따라 들어갈 문서 수 상한
_MAX_DEPTH = 3
_MAX_DESTINATIONS = 20  # 폼 하나에서 따로 판단할 등록 도메인 수 상한(넘으면 overflow로 표시해 안전 판정에서 뺀다)
_MAX_TITLE = 500  # 제목·브랜드 후보를 만들 때 보는 길이 상한
_MAX_ACTIONS = 5000  # 폼 하나에서 훑는 전송 대상(action·formaction) 수 상한
_RAW_TEXT = {"textarea", "title", "xmp", "iframe", "noembed", "noframes", "noscript", "template", "plaintext"}


def classify_field(attrs: dict, label_text: str = "") -> str:
    typ = (attrs.get("type") or "text").lower()
    ac = (attrs.get("autocomplete") or "").lower()
    if typ == "password":
        return "password"
    if "cc-number" in ac:
        return "card_number"
    if "cc-csc" in ac:
        return "card_cvc"
    if "cc-exp" in ac:
        return "card_expiry"
    if "one-time-code" in ac:
        return "otp"
    if typ == "tel":
        return "phone"
    hay = " ".join(
        [attrs.get("name") or "", attrs.get("id") or "", attrs.get("placeholder") or "",
         attrs.get("aria-label") or "", label_text or ""]
    ).lower()
    for ftype, words in _KEYWORDS:
        if any(w in hay for w in words):
            return ftype
    return "other"


def _strip_block_comments(text: str) -> str:
    """`/* … */`를 공백으로 바꾼 사본(선형 시간). 닫히지 않은 주석은 그 뒤를 버린다(브라우저에서도 문법 오류)."""
    out: list[str] = []
    i = 0
    while True:
        j = text.find("/*", i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        k = text.find("*/", j + 2)
        if k < 0:
            break
        out.append(" ")
        i = k + 2
    return "".join(out)


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _js_redirect_hint(texts: list[str]) -> bool:
    """원문·블록 주석을 뺀 사본·줄 주석까지 뺀 사본에 모두 적용한다. 문자열 속의 `/*`로 코드를 숨기는 수를 막으려고 원문도 본다."""
    for t in texts:
        no_block = _strip_block_comments(t)
        views = (t, no_block, _LINE_COMMENT_RE.sub(" ", no_block))
        if any(_JS_REDIRECT_RE.search(v) for v in views):
            return True
    return False


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.metas: list[dict] = []
        self.imgs: list[dict] = []
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: int | None = None  # 지금 열려 있는 form의 번호
        self.controls: list[dict] = []  # 입력란·버튼(폼 밖에 있어도 `form` 속성으로 폼에 속할 수 있다)
        self.label_for: dict[str, str] = {}
        self._label_for: str | None = None
        self._label_buf: list[str] = []
        self._in_label = False
        self._pending_wrapped_inputs: list[dict] = []
        self._in_script = False
        self._in_style = False
        self.script_text: list[str] = []
        self.text_nodes: list[str] = []
        self.base_href: str | None = None  # 첫 <base href>만 효력이 있다
        self.active_srcs: list[str] = []  # 다른 곳의 코드를 끌어오는 script·iframe·frame·embed·object 주소
        self.handler_text: list[str] = []  # onload="…" 같은 이벤트 핸들러 속성값
        self.srcdocs: list[str] = []  # iframe srcdoc(그 안의 문서도 같은 검사를 받는다)
        # <textarea>·<title>·<template> 등 안의 태그는 브라우저가 요소로 읽지 않는다(파이썬 파서는 읽는다).
        self._raw: str | None = None
        self._raw_depth = 0

    # 태그 처리
    def handle_starttag(self, tag: str, attrs_list) -> None:
        a: dict[str, str] = {}
        for k, v in attrs_list:
            a.setdefault(k, v or "")  # 브라우저는 중복 속성 중 첫 번째만 쓴다
        for k, v in a.items():
            if k.lower().startswith("on") and v:
                self.handler_text.append(v)
        if tag == "base" and self.base_href is None and a.get("href"):
            self.base_href = a["href"]
        if tag in ("script", "iframe", "frame", "embed", "object"):
            src = a.get("src") or (a.get("data") if tag == "object" else "")
            if tag == "script":  # SVG 안의 script는 href·xlink:href로 코드를 가져온다
                src = src or a.get("href") or a.get("xlink:href") or ""
            if src:
                self.active_srcs.append(src)
        if a.get("srcdoc"):
            self.srcdocs.append(a["srcdoc"])
        if "formaction" in a or "form" in a or tag in ("input", "textarea", "select", "button"):
            self.controls.append({"parent": self._form, "form": a.get("form") if "form" in a else None,
                                  "formaction": a.get("formaction") if "formaction" in a else None,
                                  "item": None})
        if tag in _RAW_TEXT:
            if self._raw is None:
                self._raw, self._raw_depth = tag, 1
            elif tag == "template" and self._raw == "template":
                self._raw_depth += 1
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "img":
            self.imgs.append(a)
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            if self._raw is not None:  # 글자로 읽히는 문맥의 form: 목적지는 살펴보되 진짜 form의 시작·끝을 흔들지 못한다
                self.forms.append({"id": a.get("id", ""), "action": a.get("action", ""), "method":
                                   (a.get("method") or "get").lower()})
            elif self._form is None:  # 브라우저는 열린 form 안의 form 시작 태그를 무시한다(안쪽 action은 효력이 없다)
                self.forms.append({"id": a.get("id", ""), "action": a.get("action", ""), "method":
                                   (a.get("method") or "get").lower()})
                self._form = len(self.forms) - 1
        elif tag == "label":
            self._in_label = True
            self._label_for = a.get("for") or None
            self._label_buf = []
            self._pending_wrapped_inputs = []
        elif tag in ("input", "textarea", "select"):
            if tag == "input" and (a.get("type") or "text").lower() in _SKIP_INPUT_TYPES:
                return
            item = dict(a)
            item["_tag"] = tag
            self.controls[-1]["item"] = item
            if self._in_label:
                self._pending_wrapped_inputs.append(item)
        elif tag == "script":
            self._in_script = True
        elif tag == "style":
            self._in_style = True

    def handle_endtag(self, tag: str) -> None:
        if self._raw is not None and tag == self._raw and tag != "plaintext":
            self._raw_depth -= 1
            if self._raw_depth <= 0:
                self._raw = None
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._raw is None:
            self._form = None
        elif tag == "label":
            text = " ".join("".join(self._label_buf).split())
            if self._label_for:
                self.label_for[self._label_for] = text
            for it in self._pending_wrapped_inputs:
                it["_label"] = text
            self._in_label = False
            self._label_for = None
        elif tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < _MAX_TITLE:
            self.title += data[:_MAX_TITLE]
        if self._in_script:
            self.script_text.append(data)
            return
        if self._in_style:
            return
        if self._in_label:
            self._label_buf.append(data)
        s = " ".join(data.split())
        if s:
            self.text_nodes.append(s)

    def form_groups(self) -> list[tuple[list[str], list[dict]]]:
        """(전송 대상 후보들, 입력란들). 컨트롤은 `form` 속성이 있으면 그 id의 폼에, 없으면 감싼 폼에 속한다.

        `form` 속성이 없는 id를 가리키는 컨트롤은 어느 폼에도 속하지 않는다(브라우저와 같다)."""
        by_id: dict[str, int] = {}
        for i, f in enumerate(self.forms):
            if f["id"] and f["id"] not in by_id:
                by_id[f["id"]] = i
        actions = [[f["action"]] for f in self.forms]
        inputs: list[list[dict]] = [[] for _ in self.forms]
        loose: list[dict] = []
        for c in self.controls:
            idx = by_id.get(c["form"]) if c["form"] is not None else c["parent"]
            if idx is None:
                if c["item"] is not None:
                    loose.append(c["item"])
                continue
            if c["formaction"] is not None:
                actions[idx].append(c["formaction"])
            if c["item"] is not None:
                inputs[idx].append(c["item"])
        groups = list(zip(actions, inputs))
        if loose:
            groups.append(([""], loose))
        return groups


def _trim(s: str, n: int) -> str:
    s = " ".join((s or "").split())
    return s[:n]


# ── 문자셋: 브라우저(WHATWG Encoding)가 받아들이는 이름만 쓴다 ─────────────────────
def _labels(codec: str, *names: str) -> dict[str, str]:
    return {n: codec for n in names}


_ENCODINGS: dict[str, str] = {
    **_labels("utf-8", "unicode-1-1-utf-8", "unicode11utf8", "unicode20utf8", "utf-8", "utf8", "x-unicode20utf8"),
    **_labels("utf-16-le", "csunicode", "iso-10646-ucs-2", "ucs-2", "unicode", "unicodefeff", "utf-16", "utf-16le"),
    **_labels("utf-16-be", "unicodefffe", "utf-16be"),
    **_labels("cp949", "cseuckr", "csksc56011987", "euc-kr", "iso-ir-149", "korean", "ks_c_5601-1987",
              "ks_c_5601-1989", "ksc5601", "ksc_5601", "windows-949"),
    **_labels("cp1252", "ansi_x3.4-1968", "ascii", "cp1252", "cp819", "csisolatin1", "ibm819", "iso-8859-1",
              "iso-ir-100", "iso8859-1", "iso88591", "iso_8859-1", "iso_8859-1:1987", "l1", "latin1", "us-ascii",
              "windows-1252", "x-cp1252", "x-user-defined"),
    **_labels("cp1251", "cp1251", "windows-1251", "x-cp1251"),
    **_labels("cp932", "csshiftjis", "ms932", "ms_kanji", "shift-jis", "shift_jis", "sjis", "windows-31j", "x-sjis"),
    **_labels("euc_jp", "cseucpkdfmtjapanese", "euc-jp", "x-euc-jp"),
    **_labels("iso2022_jp", "csiso2022jp", "iso-2022-jp"),
    **_labels("gbk", "chinese", "csgb2312", "csiso58gb231280", "gb2312", "gb_2312", "gb_2312-80", "gbk",
              "iso-ir-58", "x-gbk"),
    **_labels("gb18030", "gb18030"),
    **_labels("cp950", "big5", "big5-hkscs", "cn-big5", "csbig5", "x-x-big5"),
    **_labels("koi8-r", "cskoi8r", "koi", "koi8", "koi8-r", "koi8_r"),
    **_labels("iso8859-2", "csisolatin2", "iso-8859-2", "iso-ir-101", "iso8859-2", "iso88592", "l2", "latin2"),
}
# 브라우저에서 본문이 사라지는 "replacement" 인코딩. 마크업으로 읽을 수 없다.
_REPLACEMENT = {"csiso2022kr", "hz-gb-2312", "iso-2022-cn", "iso-2022-cn-ext", "iso-2022-kr", "replacement"}
_BOMS = [(codecs.BOM_UTF8, "utf-8"), (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be")]
_META_TAG = re.compile(rb"<meta\b([^>]*)>", re.I)
_META_ATTR = re.compile(rb"([^\s=/>\"']+)\s*(?:=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+)))?")
_CHARSET_PARAM = re.compile(rb"charset\s*=\s*[\"']?([^\s;\"']+)", re.I)


def _content_type_charset(content_type: str) -> str | None:
    """Content-Type의 매개변수 중 이름이 정확히 `charset`인 것(`xcharset=`은 매개변수가 아니다)."""
    for param in (content_type or "").split(";")[1:]:
        key, sep, val = param.partition("=")
        if sep and key.strip().lower() == "charset":
            return val.strip().strip("\"'") or None
    return None


def _meta_charset(chunk: bytes) -> str | None:
    """앞 1024바이트의 <meta>에서 `charset` 속성, 또는 http-equiv=content-type의 content 안 charset 매개변수."""
    for m in _META_TAG.finditer(chunk):
        attrs: dict[bytes, bytes] = {}
        for am in _META_ATTR.finditer(m.group(1)):
            name = am.group(1).lower()
            if name not in attrs:  # 중복 속성은 첫 값
                attrs[name] = am.group(2) or am.group(3) or am.group(4) or b""
        if b"charset" in attrs and attrs[b"charset"]:
            return attrs[b"charset"].decode("ascii", "ignore")
        if attrs.get(b"http-equiv", b"").lower() == b"content-type":
            cm = _CHARSET_PARAM.search(attrs.get(b"content", b""))
            if cm:
                return cm.group(1).decode("ascii", "ignore")
    return None


def _declared_charsets(html_bytes: bytes, content_type: str) -> list[tuple[str, str]]:
    """(출처, 이름)들. HTTP 헤더가 meta보다 먼저다. meta는 앞 1024바이트만 본다(브라우저의 사전 검사와 같다)."""
    out: list[tuple[str, str]] = []
    h = _content_type_charset(content_type)
    if h:
        out.append(("header", h))
    m = _meta_charset(html_bytes[:1024])
    if m:
        out.append(("meta", m))
    return out


def _decode(html_bytes: bytes, content_type: str = "") -> str | None:
    """브라우저와 같은 순서(BOM → HTTP 헤더 → meta 선언 → 추정)로 해석한다. 마크업으로 읽히지 않으면 None.

    브라우저가 모르는 이름(utf-7 등)은 무시되므로 여기서도 무시한다. 파이썬의 코덱 목록으로 받아들이면
    브라우저는 실행하는 마크업을 검사기는 주석으로 읽는 일이 생긴다."""
    text = None
    for bom, enc in _BOMS:
        if html_bytes.startswith(bom):
            text = html_bytes[len(bom):].decode(enc, errors="replace")
            break
    if text is None:
        for source, label in _declared_charsets(html_bytes, content_type):
            key = label.strip().lower()
            if key in _REPLACEMENT:
                return None
            codec = _ENCODINGS.get(key)
            if codec is None:
                continue
            if source == "meta" and codec.startswith("utf-16"):
                codec = "utf-8"  # meta로 선언한 UTF-16은 UTF-8로 취급한다
            text = html_bytes.decode(codec, errors="replace")
            break
    if text is None:
        try:
            text = html_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = html_bytes.decode("cp949", errors="replace")
    # 태그가 하나도 안 보이거나 NUL이 섞여 있으면 해석에 실패한 것이다(분석 결과를 믿지 않는다)
    return text if "<" in text and "\x00" not in text else None


def _resolve(base: str, ref: str) -> str:
    return resolve_reference(base, ref)


def _parse_all(text: str, page_url: str) -> tuple[list[tuple[_PageParser, str]], bool]:
    """(문서 파서와 그 문서의 기준 주소) 목록, 상한을 넘겨 다 보지 못했는가. iframe srcdoc 안의 문서까지 따라 들어간다."""
    docs: list[tuple[_PageParser, str]] = []
    todo: list[tuple[str, str, int]] = [(text, page_url, 0)]
    overflow = False
    while todo:
        t, parent_base, depth = todo.pop(0)
        if len(docs) >= _MAX_DOCS:
            overflow = True
            continue
        p = _PageParser()
        p.feed(t)
        p.close()
        base = _resolve(parent_base, p.base_href) if p.base_href else parent_base
        docs.append((p, base))
        for sd in p.srcdocs:
            if depth + 1 >= _MAX_DEPTH:
                overflow = True
            else:
                todo.append((sd, base, depth + 1))
    return docs, overflow


def _destination(base_url: str, action: str, page_url: str, page_host: str,
                 page_reg: str) -> list[tuple[str, str, bool]]:
    """전송 대상 하나를 (호스트, 등록 도메인, 교차 도메인 여부)로 푼다. 빈 action은 문서 주소로 가므로 둘 다 본다."""
    targets = [_resolve(base_url, action)] if action else [page_url, base_url]
    out: list[tuple[str, str, bool]] = []
    for target in targets:
        try:
            sp = urlsplit(target)
            host = sp.hostname or ""
        except ValueError:
            out.append(("", "(invalid)", True))
            continue
        if sp.scheme.lower() not in ("http", "https"):  # javascript:·data: 등은 목적지를 알 수 없다
            out.append(("", "(script)", True))
        elif not host:
            out.append(("", "(invalid)", True))
        else:
            a_host = to_ascii_host(host)
            a_reg = registrable_of(a_host) if a_host else page_reg
            out.append((a_host, a_reg, bool(a_reg and page_reg and a_reg != page_reg)))
    return out


def inspect_page(html_bytes: bytes, page_url: str, content_type: str = "") -> dict:
    text = _decode(html_bytes, content_type)
    if text is None:
        return {"ok": False, "error": "undecodable html"}
    docs, overflow = _parse_all(text, page_url)
    p, base_url = docs[0]

    page_host = to_ascii_host(urlsplit(page_url).hostname or "")
    page_reg = registrable_of(page_host) if page_host else ""

    # 브랜드 후보: title 조각, og:site_name, 로고 alt
    brands: list[str] = []

    def add_brand(s: str) -> None:
        s = _trim(s, 40)
        if s and len(brands) < 6 and s not in brands:
            brands.append(s)

    for part in re.split(r"[|\-–—·:]", p.title[:_MAX_TITLE], maxsplit=12):
        add_brand(part)
    for m in p.metas:
        if (m.get("property") or m.get("name") or "").lower() in ("og:site_name", "application-name"):
            add_brand(m.get("content", ""))
    for im in p.imgs:
        blob = " ".join([im.get("alt", ""), im.get("src", ""), im.get("class", ""), im.get("id", "")]).lower()
        if "logo" in blob or "로고" in blob:
            add_brand(im.get("alt", ""))
    brands = brands[:6]

    # 폼: 입력란이 없어도(hidden만 있거나 버튼뿐이어도) 전송 대상은 모두 본다
    forms_out: list[dict] = []
    for doc, doc_base in docs:
        for actions, inputs in doc.form_groups():
            by_domain: dict[tuple[str, bool], tuple[str, str, bool]] = {}
            overflow_dest = len(actions) > _MAX_ACTIONS
            for action in actions[:_MAX_ACTIONS]:
                for d in _destination(doc_base, action, page_url, page_host, page_reg):
                    key = (d[1], d[2])
                    if key in by_domain:
                        continue
                    if len(by_domain) >= _MAX_DESTINATIONS:
                        overflow_dest = True
                    else:
                        by_domain[key] = d
            dests = list(by_domain.values())
            if not inputs and not any(d[2] for d in dests) and not overflow_dest:
                continue  # 입력란도 없고 다른 곳으로 보내지도 않는 폼은 알릴 것이 없다
            first = next((d for d in dests if d[2]), dests[0])
            ftypes: list[str] = []
            for it in inputs:
                label = it.get("_label") or doc.label_for.get(it.get("id", ""), "")
                t = classify_field(it, label)
                if t not in ftypes:
                    ftypes.append(t)
            forms_out.append({
                "action_host": first[0],
                "action_registrable_domain": first[1],
                "cross_domain": any(d[2] for d in dests) or overflow_dest,
                "destinations_overflow": overflow_dest,  # 다 판단하지 못했다: 안전 판정에서 뺀다
                # 전송 대상 전체. 한 곳이 믿을 수 있는 협력 도메인이어도 나머지 대상까지 따로 판단해야 한다.
                "destinations": [{"host": h, "registrable_domain": r, "cross_domain": x} for h, r, x in dests],
                "field_types": ftypes,
            })

    apk_links: list[str] = []
    for doc, doc_base in docs:
        for href in doc.links:
            if len(apk_links) >= 5:
                break
            target = _resolve(doc_base, href)
            if urlsplit(target).path.lower().endswith(".apk"):
                apk_links.append(_trim(target, 200))

    meta_refresh = any((m.get("http-equiv") or "").lower() == "refresh" for d, _ in docs for m in d.metas)
    js_hint = (meta_refresh
               or _js_redirect_hint([t for d, _ in docs for t in d.script_text + d.handler_text])
               or any(h.strip().lower().startswith("javascript:") for d, _ in docs for h in d.links))

    # 다른 도메인의 코드·문서를 끌어오는 요소. 실행하지 않으므로 무엇을 하는지 알 수 없다(판정에서 안전 불가 사유).
    ext: list[str] = []
    ext_seen: set[str] = set()
    ext_overflow = False
    for doc, doc_base in docs:
        for src in doc.active_srcs:
            try:
                sp = urlsplit(_resolve(doc_base, src))
                host = sp.hostname or ""
            except ValueError:
                sp, host = None, ""
            if sp is None:
                dom = "(invalid)"
            elif sp.scheme.lower() not in ("http", "https", ""):
                dom = "(script)"
            else:
                dom = registrable_of(to_ascii_host(host)) if host else ""
            if dom and dom != page_reg and dom not in ext_seen:
                ext_seen.add(dom)
                if len(ext) < 10:
                    ext.append(dom)
                else:
                    ext_overflow = True
    if overflow or ext_overflow:  # 중첩 문서가 너무 많거나 깊어, 또는 도메인이 너무 많아 다 보지 못했다
        ext.append("(nested)")

    # "공식·안전·인증" 류 주장 문구: 길이 제한, 최대 3개. 검증 대상 주장일 뿐이다.
    claims: list[str] = []
    for t in p.text_nodes:
        if _TRUST_RE.search(t) and len(t) >= 6:
            c = _trim(t, 200)
            if c not in claims:
                claims.append(c)
        if len(claims) >= 3:
            break

    return {
        "ok": True,
        "title": _trim(p.title, 100),
        "brand_candidates": brands,
        "forms": forms_out,
        "apk_links": apk_links,
        "trust_claims": claims,
        "js_redirect_hint": bool(js_hint),
        "external_active_domains": ext[:11],
    }
