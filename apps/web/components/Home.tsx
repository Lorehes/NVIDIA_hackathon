"use client";
import { useRouter } from "next/navigation";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { friendlyError } from "@/lib/api";
import { FALLBACK_CASES } from "@/lib/demo";
import { findLinks, MAX_INPUT, shortUrl } from "@/lib/links";
import { loadDemoCases, startInvestigation } from "@/lib/submit";
import type { DemoCase } from "@/lib/types";

const CIRCLED = ["①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨", "⑩"];

export function Home() {
  const router = useRouter();
  const [text, setText] = useState("");
  const [cases, setCases] = useState<DemoCase[]>(FALLBACK_CASES);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const taRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    let alive = true;
    loadDemoCases().then((c) => alive && setCases(c.slice(0, 5)));
    return () => {
      alive = false;
    };
  }, []);

  // 입력 칸이 글 길이에 맞게 늘어난다(겹쳐 그린 강조 표시와 높이를 맞추기 위해 스크롤을 쓰지 않는다).
  useLayoutEffect(() => {
    const el = taRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = Math.max(110, el.scrollHeight) + "px";
  }, [text]);

  const links = useMemo(() => findLinks(text), [text]);
  const tooLong = text.length > MAX_INPUT;
  const hasText = text.trim().length > 0;
  const noLink = hasText && links.length === 0;
  const canSubmit = links.length > 0 && !tooLong && !busy;

  const highlighted = useMemo(() => {
    const out: React.ReactNode[] = [];
    let pos = 0;
    links.forEach((l, i) => {
      out.push(text.slice(pos, l.start));
      out.push(<mark key={i}>{text.slice(l.start, l.end)}</mark>);
      pos = l.end;
    });
    out.push(text.slice(pos));
    return out;
  }, [links, text]);

  async function submit() {
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const accepted = await startInvestigation(text);
      router.push(`/check/${encodeURIComponent(accepted.job_id)}`);
    } catch (e) {
      setError(friendlyError(e));
      setBusy(false);
    }
  }

  function pick(c: DemoCase) {
    setText(c.input);
    setError(null);
    taRef.current?.focus();
  }

  return (
    <div className="home">
      <div className="col gap12" style={{ gap: 14 }}>
        <h1>
          <span className="only-desktop">
            이상한 문자를 받으셨나요?
            <br />
            링크를 누르기 전에 여기서 확인하세요.
          </span>
          <span className="only-mobile">
            이상한 문자,
            <br />
            누르기 전에 확인하세요
          </span>
        </h1>
        <p className="lead only-desktop">
          받은 문자를 붙여 넣으면, 저희가 대신 안전한 곳에서 열어보고 진짜인지 가짜인지 이유와 함께 알려드려요.
        </p>
      </div>

      <div>
        <div className={"paste" + (noLink || tooLong || error ? " err" : "")}>
          <div className="paste-area">
            <div className="hl" aria-hidden>
              {highlighted}
              {"\n"}
            </div>
            <textarea
              ref={taRef}
              value={text}
              onChange={(e) => {
                setText(e.target.value);
                setError(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) submit();
              }}
              placeholder="여기에 받은 문자를 붙여 넣어 주세요"
              aria-label="받은 문자 붙여 넣기"
              aria-invalid={noLink || tooLong}
              rows={3}
              spellCheck={false}
            />
          </div>
          {(noLink || tooLong || error) && (
            <div className="paste-msg" role="alert">
              {tooLong ? (
                <>글이 너무 길어요. 2,000자 안으로 줄여 주세요.</>
              ) : error ? (
                <>{error}</>
              ) : (
                <>
                  이 문자에는 링크가 없어요. 링크가 있는 문자를 넣어 주세요.
                  <br />
                  <span className="sub">전화하라는 문자라면, 문자 속 번호 말고 그 회사의 대표번호로 전화하세요.</span>
                </>
              )}
            </div>
          )}
          <div className="paste-bar">
            <span className={"paste-status" + (links.length ? "" : " muted")} aria-live="polite">
              {links.length > 0 ? (
                <>
                  <span className="dot" />
                  링크 {links.length}개를 찾았어요
                </>
              ) : (
                <>문자나 링크를 붙여 넣어 주세요</>
              )}
            </span>
            <div className="paste-actions">
              <button
                type="button"
                className="btn-clear"
                onClick={() => {
                  setText("");
                  setError(null);
                  taRef.current?.focus();
                }}
                disabled={busy || !text}
              >
                지우기
              </button>
              <button type="button" className="btn-main" onClick={submit} disabled={!canSubmit}>
                {busy ? "보내는 중…" : "확인하기"}
              </button>
            </div>
          </div>
        </div>

        {links.length > 1 && (
          <div className="card links-found" style={{ marginTop: 14 }}>
            <h2>링크를 {links.length}개 찾았어요. 첫 번째 링크부터 확인할게요.</h2>
            <div className="links-list">
              {links.slice(0, 8).map((l, i) => (
                <span key={l.url}>
                  {CIRCLED[i] ?? `${i + 1}.`} {shortUrl(l.url)}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="steps3 only-desktop">
        <div className="step3">
          <span className="num">1</span>
          <span>
            받은 문자를 <b>손가락으로 길게 눌러</b> 복사해요
          </span>
        </div>
        <div className="step3">
          <span className="num">2</span>
          <span>
            위 칸에 <b>붙여 넣어요</b> (링크만 넣어도 돼요)
          </span>
        </div>
        <div className="step3">
          <span className="num">3</span>
          <span>
            <b>확인하기</b>를 누르고 1분쯤 기다려요
          </span>
        </div>
      </div>
      <p className="small-note only-mobile" style={{ fontSize: 16, lineHeight: 1.6, color: "var(--g700)" }}>
        문자를 길게 눌러 복사한 뒤 위 칸에 붙여 넣으세요. 링크는 내 휴대폰에서 열리지 않아요.
      </p>

      <div className="examples">
        <h2>예시로 먼저 해보기</h2>
        <div className="examples-list">
          {cases.map((c) => (
            <button key={c.id} type="button" className="pill" aria-pressed={text.trim() === c.input.trim()} onClick={() => pick(c)}>
              {c.label}
            </button>
          ))}
        </div>
        <p className="small-note" style={{ marginTop: 12 }}>
          예시는 모두 가짜로 만든 회사 이름과 연습용 주소예요.
        </p>
      </div>

      <div className="reassure">
        <b>걱정 마세요.</b> 여기에 붙여 넣은 링크는 내 휴대폰에서 열리지 않아요. 바깥과 떨어진 <b>안전 공간</b>에서만
        열어봅니다.
      </div>
    </div>
  );
}
