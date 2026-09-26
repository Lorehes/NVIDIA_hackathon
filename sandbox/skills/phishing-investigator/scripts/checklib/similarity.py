"""3-2. 공식 도메인과의 유사도: 편집 거리, 혼동 문자, 혼합 문자 체계, 서브도메인 위장.

판정은 하지 않는다. 신호를 만들 재료만 계산한다.
"""
from __future__ import annotations

import unicodedata

from .parse_url import split_host, to_unicode_host

# 시각적으로 헷갈리는 비(非)라틴 글자 → 비슷하게 생긴 라틴 글자
CONFUSABLES: dict[str, str] = {
    # 키릴
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w", "ѵ": "v", "ӏ": "l",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b",
    # 그리스
    "ο": "o", "ν": "v", "α": "a", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "υ": "u",
    "χ": "x", "ε": "e",
    # 기타
    "ɡ": "g", "ɑ": "a", "ⅼ": "l", "ｏ": "o", "０": "0", "１": "1",
}

# 라틴 안에서도 헷갈리는 조합(스켈레톤 비교용)
_ASCII_SKELETON = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l")]


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def osa_distance(a: str, b: str) -> int:
    """인접 문자 전치를 1회로 세는 편집 거리(optimal string alignment)."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def norm_similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return round(1 - osa_distance(a, b) / max(len(a), len(b)), 4)


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        return unicodedata.name(ch).split(" ")[0]
    except ValueError:
        return "UNKNOWN"


def skeleton(text: str) -> str:
    t = unicodedata.normalize("NFKC", text.lower())
    t = "".join(CONFUSABLES.get(c, c) for c in t)
    for src, dst in _ASCII_SKELETON:
        t = t.replace(src, dst)
    return t


def _pattern(actual_label: str, actual_suffix: str, off_label: str, off_suffix: str) -> str:
    if actual_label == off_label and actual_suffix != off_suffix:
        return "tld_swap"
    if actual_label.replace("-", "") == off_label.replace("-", "") and actual_label != off_label:
        return "hyphen"
    if skeleton(actual_label) == skeleton(off_label) and actual_label != off_label:
        return "confusable"
    dist = levenshtein(actual_label, off_label)
    if dist == 1:
        if len(actual_label) == len(off_label):
            return "substitution"
        return "insertion" if len(actual_label) > len(off_label) else "deletion"
    if dist == 2 and osa_distance(actual_label, off_label) == 1:
        return "transposition"
    return "none"


def compare(parsed: dict, official: list[dict]) -> dict:
    """parsed: parse_url 결과. official: [{"entity_id","domain"}, ...] (모든 KB 공식 도메인)."""
    # 유사도는 사람이 보는 글자(유니코드) 기준으로 비교한다. punycode 상태로는 혼동 문자를 알아볼 수 없다.
    actual = parsed.get("registrable_domain_unicode") or parsed.get("registrable_domain", "")
    a_label = parsed.get("domain_label_unicode") or parsed.get("domain_label", "")
    a_suffix = parsed.get("suffix", "")
    subs = [to_unicode_host(s) for s in parsed.get("subdomain_labels", [])]
    sub_text = ".".join(subs)
    host_unicode = parsed.get("host_unicode", "")

    best = None
    contains: list[dict] = []
    brand_in_domain: list[dict] = []
    seen_contains: set[tuple[str, str, str]] = set()

    a_tokens = set(a_label.replace("_", "-").split("-"))
    for rec in official:
        dom = rec["domain"].lower()
        eid = rec["entity_id"]
        o_subs, o_label, o_suffix = split_host(dom)
        if rec.get('scope') in ('host', 'url'):
            # An exact directory hostname does not establish ownership of its
            # shared parent (e.g. school-a.education.example).
            if parsed.get('host_ascii') == dom:
                cand = {'entity_id': eid, 'domain': dom, 'similarity': 1.0, 'edit_distance': 0, 'pattern': 'same'}
                if best is None or cand['similarity'] > best['similarity']:
                    best = cand
            elif dom in sub_text:
                contains.append({'entity_id': eid, 'domain': dom, 'match_kind': 'domain', 'label': dom})
            continue
        full_sim = norm_similarity(actual, dom)
        label_sim = norm_similarity(a_label, o_label)
        sim = round(max(full_sim, label_sim), 4)
        dist = levenshtein(actual, dom) if sim == full_sim else levenshtein(a_label, o_label)
        cand = {
            "entity_id": eid, "domain": dom, "similarity": sim, "edit_distance": dist,
            "pattern": _pattern(a_label, a_suffix, o_label, o_suffix) if actual != dom else "same",
        }
        if best is None or cand["similarity"] > best["similarity"]:
            best = cand

        # 서브도메인에 공식 도메인 문자열(또는 공식 라벨)이 들어 있는가
        if sub_text and actual != dom:
            if dom in sub_text:
                key = (eid, dom, "domain")
                if key not in seen_contains:
                    seen_contains.add(key)
                    contains.append({"entity_id": eid, "domain": dom, "match_kind": "domain",
                                     "label": sub_text if not sub_text.endswith(dom) else dom})
            elif len(o_label) >= 4 and o_label in {t for lab in subs for t in lab.split("-")}:
                key = (eid, dom, "label")
                if key not in seen_contains:
                    seen_contains.add(key)
                    contains.append({"entity_id": eid, "domain": dom, "match_kind": "label",
                                     "label": o_label})
        # 등록 도메인 이름에 공식 브랜드 라벨이 토큰으로 들어 있는가(hanbit-parcel.test)
        if actual != dom and len(o_label) >= 4 and o_label in a_tokens and a_label != o_label:
            brand_in_domain.append({"entity_id": eid, "domain": dom, "brand": o_label})

    # 혼동 문자·혼합 문자 체계 (호스트 전체 라벨 기준)
    confusable_chars: list[dict] = []
    mixed_script = False
    for label in host_unicode.split("."):
        # 한글+라틴 혼용은 흔하므로, 모양이 겹치는 문자 체계끼리의 혼합만 본다
        scripts = {s for s in (_script_of(c) for c in label) if s in ("LATIN", "CYRILLIC", "GREEK")}
        if len(scripts) > 1:
            mixed_script = True
        for ch in label:
            if ch in CONFUSABLES and ch not in {c["char"] for c in confusable_chars}:
                confusable_chars.append({"char": ch, "codepoint": f"U+{ord(ch):04X}",
                                         "looks_like": CONFUSABLES[ch]})

    typosquat = "none"
    if best and best["pattern"] not in ("same",):
        typosquat = best["pattern"]

    return {
        "ok": True,
        "closest_official": best,
        "subdomain_contains_official": contains,
        "brand_in_domain": brand_in_domain,
        "mixed_script": mixed_script,
        "confusable_chars": confusable_chars,
        "typosquat_pattern": typosquat,
    }
