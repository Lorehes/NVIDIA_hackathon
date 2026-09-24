// 서버의 URL 추출 규칙과 같은 규칙으로 화면에서 링크를 미리 찾는다.
//  - https?://… 를 찾고, 끝의 문장부호를 잘라 낸다.
//  - 호스트 뒤(경로·쿼리·해시)에서 처음 나오는 한글부터는 조사로 보고 자른다. (호스트 안의 한글은 IDN으로 유지)
//  - 입력 전체가 공백 없는 도메인 한 덩어리면 https:// 를 붙여 링크로 받아들인다.

export const MAX_INPUT = 2000;

export interface FoundLink {
  url: string;
  start: number;
  end: number;
}

const URL_RE = /https?:\/\/[^\s<>"'`]+/gi;
const TRAIL_RE = /[.,;:!?)\]}>'"”’」』]+$/;
const HANGUL_RE = /[ㄱ-ㆎ가-힣]/;
const BARE_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+(?::\d+)?(?:[/?#]\S*)?$/i;

function trimUrl(raw: string): string {
  let s = raw.replace(TRAIL_RE, "");
  const schemeEnd = s.indexOf("://") + 3;
  const rest = s.slice(schemeEnd);
  const pathIdx = rest.search(/[/?#]/);
  if (pathIdx >= 0) {
    const tail = rest.slice(pathIdx);
    const h = tail.search(HANGUL_RE);
    if (h >= 0) s = s.slice(0, schemeEnd + pathIdx + h);
  }
  return s.replace(TRAIL_RE, "");
}

export function findLinks(text: string): FoundLink[] {
  const out: FoundLink[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(URL_RE)) {
    const url = trimUrl(m[0]);
    if (url.length <= "https://".length || seen.has(url)) continue;
    seen.add(url);
    out.push({ url, start: m.index ?? 0, end: (m.index ?? 0) + url.length });
  }
  if (out.length === 0) {
    const t = text.trim();
    if (t && !/\s/.test(t) && BARE_RE.test(t)) {
      const start = text.indexOf(t);
      out.push({ url: "https://" + t, start, end: start + t.length });
    }
  }
  return out;
}

/** 링크 표시용: 스킴을 떼고 보여 준다. */
export function shortUrl(url: string): string {
  return url.replace(/^https?:\/\//i, "");
}
