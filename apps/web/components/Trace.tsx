"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { friendlyError, getTrace } from "@/lib/api";
import { shortUrl } from "@/lib/links";
import type {
  AddressTrace,
  AgentTrace,
  PageTrace,
  RedirectTrace,
  SandboxTrace,
  Trace,
} from "@/lib/types";
import { DevBox, Emph, Loading, toneOf, type Tone } from "./ui";

import { TABS, type TabKey } from "@/lib/tabs";

const OWNER_COLOR: Record<Tone, string> = { safe: "var(--green)", bad: "var(--red)", caution: "var(--amber)", unknown: "var(--ink)" };

export function TraceView({ jobId, tab }: { jobId: string; tab: TabKey }) {
  const [trace, setTrace] = useState<Trace | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    getTrace(jobId)
      .then((t) => alive && setTrace(t))
      .catch((e) => alive && setError(friendlyError(e)));
    return () => {
      alive = false;
    };
  }, [jobId]);

  if (error)
    return (
      <div className="center-msg" role="alert">
        <h1>조사 기록을 불러오지 못했어요</h1>
        <p>{error}</p>
        <Link href={`/check/${encodeURIComponent(jobId)}`} className="btn-outline">
          결과로 돌아가기
        </Link>
      </div>
    );
  if (!trace) return <Loading />;

  const tone = toneOf(trace.verdict);
  const enc = encodeURIComponent(jobId);
  return (
    <>
      <div className="trace-head">
        <div className="wrap">
          <Link className="back" href={`/check/${enc}`}>
            ← 결과로 돌아가기
          </Link>
          <div className="ttl">
            <h1>어떻게 조사했나요?</h1>
            <span className={`vpill ${tone}`}>
              <i />
              {trace.verdict_label}
            </span>
          </div>
          <div className="tabs" role="tablist" aria-label="조사 기록">
            {TABS.map((t) => (
              <Link
                key={t.key}
                role="tab"
                id={`tab-${t.key}`}
                aria-selected={t.key === tab}
                aria-controls="trace-panel"
                className="tab"
                href={`/check/${enc}/trace?tab=${t.key}`}
                replace
                scroll={false}
              >
                <span className="long">{t.long}</span>
                <span className="short">{t.short}</span>
              </Link>
            ))}
          </div>
        </div>
      </div>
      <div className="trace-body" role="tabpanel" id="trace-panel" aria-labelledby={`tab-${tab}`}>
        {tab === "address" && <AddressTab d={trace.address} tone={tone} />}
        {tab === "path" && <PathTab d={trace.redirects} />}
        {tab === "page" && <PageTab d={trace.page} />}
        {tab === "agent" && <AgentTab d={trace.agent} />}
        {tab === "sandbox" && <SandboxTab d={trace.sandbox} />}
      </div>
    </>
  );
}

function Missing({ text }: { text: string }) {
  return (
    <div className="note-card">
      <h3>기록이 없어요</h3>
      <p>{text}</p>
    </div>
  );
}

// ── ① 주소 ──
function AddressTab({ d, tone }: { d: AddressTrace | null; tone: Tone }) {
  if (!d) return <Missing text="주소 살펴보기 기록을 남기지 못했어요." />;
  const hasPrefix = d.subdomain_part.length > 0;
  const color = OWNER_COLOR[tone];
  const hitNames = d.tricks.filter((t) => t.hit).length;
  return (
    <>
      <div className="card card-pad" style={{ gap: 22, padding: 30 }}>
        <div className="col" style={{ gap: 6 }}>
          <h2>주소를 조각내서 봤어요</h2>
          <span className="lead">
            인터넷 주소는 <b>오른쪽 끝에 가까운 이름</b>이 진짜 주인이에요. 앞에 붙은 글자는 누구나 마음대로 바꿀 수 있어요.
          </span>
        </div>
        <div className="anatomy" aria-label="주소를 나눈 모습">
          <span className="b">{d.scheme}://</span>
          {hasPrefix ? <span className="pre">{d.subdomain_part}</span> : <span />}
          <span className={"own" + (hasPrefix ? "" : " solo")} style={{ background: color, color: tone === "caution" ? "var(--ink)" : "#fff" }}>
            {d.registrable_domain}
          </span>
          <span className="b">{d.path}</span>
          <span className="cap g">시작 표시</span>
          {hasPrefix ? (
            <span className="cap">
              <b>앞에 붙인 글자</b>
              <br />
              진짜처럼 보이려고 넣었어요
            </span>
          ) : (
            <span />
          )}
          <span className="cap" style={{ color: tone === "bad" ? "var(--red-ink)" : undefined }}>
            <b>진짜 사이트 이름</b>
            <br />이 사이트의 진짜 주인
          </span>
          <span className="cap g">사이트 안의 위치</span>
        </div>
        <div className="explain-box">
          <Emph text={d.summary_sentence} />
        </div>
      </div>

      <div className="grid-2">
        <div className="card card-pad" style={{ gap: 6 }}>
          <span className="card-title" style={{ marginBottom: 10 }}>
            이런 속임수가 있는지 확인했어요
          </span>
          {d.tricks.map((t) => (
            <div className="trick" key={t.key}>
              <div className="col" style={{ gap: 4 }}>
                <span className="q">{t.question}</span>
                <span className="h">{t.hit && t.detail ? t.detail : t.hint}</span>
              </div>
              <span className={"ans" + (t.hit ? " hit" : "")}>{t.answer}</span>
            </div>
          ))}
        </div>
        <div className="col gap22">
          <div className="card card-pad" style={{ gap: 16 }}>
            <span className="card-title">진짜 주소와 얼마나 닮았나요?</span>
            {d.similarity.map((s) => (
              <div className="sim" key={s.entity_id + s.domain}>
                <div className="r">
                  <span>
                    <b>{s.name}</b> <span className="dom">{s.domain}</span>
                  </span>
                  <b style={{ fontWeight: s.similarity >= 0.5 ? 700 : 400, color: s.similarity >= 0.5 ? undefined : "var(--g600)" }}>{s.label}</b>
                </div>
                <div className="track" aria-hidden>
                  <i className={s.similarity >= 0.8 ? "hi" : s.similarity >= 0.5 ? "" : "lo"} style={{ width: `${Math.round(s.similarity * 100)}%` }} />
                </div>
                {s.note && <span className="nt">{s.note}</span>}
              </div>
            ))}
            {d.similarity.length === 0 && <span className="lead">비교할 진짜 주소가 없어요.</span>}
            {hitNames === 0 && d.similarity.length > 0 && (
              <span className="nt" style={{ fontSize: 15, color: "var(--g600)", lineHeight: 1.55 }}>
                철자를 비슷하게 만든 흔적은 찾지 못했어요.
              </span>
            )}
          </div>
          <div className="note-card">
            <h3>비교에 쓴 진짜 주소는 어디서 왔나요?</h3>
            <p>{d.kb_note}</p>
          </div>
        </div>
      </div>
      <DevBox title="개발자용 기록 보기 (원본 데이터)" json={{ host_ascii: d.host_ascii, host_unicode: d.host_unicode, registrable_domain: d.registrable_domain, ...d.dev }} />
    </>
  );
}

// ── ② 넘어간 길 ──
function PathTab({ d }: { d: RedirectTrace | null }) {
  if (!d) return <Missing text="넘어간 길 기록을 남기지 못했어요." />;
  const statuses = d.chain.map((h) => h.status ?? "-").join(" · ");
  const blocked = d.chain.filter((h) => h.blocked).map((h) => h.status ?? 403);
  return (
    <>
      <div className="stat3">
        <div className="card stat">
          <span className="k">다른 곳으로 넘어간 횟수</span>
          <span className="v">{d.redirect_count}번</span>
        </div>
        <div className="card stat">
          <span className="k">들어가지 않고 막은 곳</span>
          <span className={"v" + (d.blocked_count ? " red" : "")}>{d.blocked_count}곳</span>
        </div>
        <div className="card stat">
          <span className="k">마지막으로 본 곳</span>
          <span className="v mono">{d.last_seen_domain ?? "—"}</span>
        </div>
      </div>

      <div className="card card-pad" style={{ padding: 30, gap: 22 }}>
        <div className="col" style={{ gap: 6 }}>
          <h2>링크를 열었을 때 어디로 갔나요?</h2>
          <span className="lead">가짜 사이트는 여러 번 다른 곳으로 넘겨서 진짜 주인을 숨기기도 해요.</span>
        </div>
        <div className="timeline">
          {d.chain.map((h, i) => {
            const last = i === d.chain.length - 1;
            const cls = h.blocked || h.error ? "bad" : "";
            const title = h.blocked ? "넘어가려던 곳" : h.error ? "열지 못한 곳" : i === 0 ? "문자 속 링크를 열었어요" : "그다음 열어본 곳";
            const redirected = !h.blocked && !h.error && (h.status ?? 0) >= 300 && (h.status ?? 0) < 400;
            return (
              <div key={h.url + i} style={{ display: "contents" }}>
                <div className="tl-ico">
                  <span className={"c " + cls} aria-hidden>
                    {h.blocked ? "✕" : i + 1}
                  </span>
                  {!last && <span className="line" />}
                </div>
                <div className="tl-body">
                  <div className="h">
                    <b>{title}</b>
                    {h.blocked ? (
                      <span className="chip chip-red">막음</span>
                    ) : h.error ? (
                      <span className="chip chip-amber">열리지 않음</span>
                    ) : (
                      <span className="chip chip-green">열어봄</span>
                    )}
                  </div>
                  <span className="u">{shortUrl(h.url)}</span>
                  {h.blocked ? (
                    <span className="n bad">
                      처음 링크와 <b>다른 주인의 사이트</b>예요. 허락하지 않은 곳이라 안전 공간이 들어가지 않았어요.
                      {/pay|card|bank|secure/i.test(h.host) && <> 이름에 결제·보안 같은 말이 들어간 것도 눈여겨보세요.</>}
                    </span>
                  ) : h.error ? (
                    <span className="n">이 사이트가 응답하지 않았어요.</span>
                  ) : redirected ? (
                    <span className="n">이 사이트가 &quot;다른 곳으로 가세요&quot;라고 우리를 넘기려 했어요.</span>
                  ) : last ? (
                    <span className="n">여기가 마지막이에요. 다른 곳으로 넘어가지 않았어요.</span>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="grid-2e">
        <div className="note-card">
          <h3>자물쇠 표시(https)가 있으면 안전한가요?</h3>
          <p>
            아니에요. 자물쇠는 &quot;주고받는 내용이 암호로 바뀐다&quot;는 뜻일 뿐, <b>진짜 회사</b>라는 뜻이 아니에요. 가짜 사이트도
            자물쇠를 달 수 있어요.
          </p>
        </div>
        <div className="note-card">
          <h3>왜 끝까지 따라가지 않았나요?</h3>
          <p>모르는 곳에 들어가는 건 조사하는 쪽도 위험해요. 그래서 허락한 주소 한 곳만 열고, 나머지는 막고 기록만 남겨요.</p>
        </div>
      </div>
      <DevBox
        title={`개발자용 기록 보기 (응답 코드 ${statuses}${blocked.length ? ` · 차단 ${blocked.join(",")}` : ""})`}
        json={{ chain: d.chain, ...d.dev }}
      />
    </>
  );
}

// ── ③ 페이지 ──
function PageTab({ d }: { d: PageTrace | null }) {
  if (!d || !d.available)
    return (
      <div className="card card-pad">
        <h2>페이지 안을 보지 못했어요</h2>
        <span className="lead">
          링크가 열리지 않았거나 조사가 중간에 멈춰서, 페이지가 무엇을 적으라고 하는지는 알 수 없어요. 그래서 이 부분으로는 판단하지
          않았어요.
        </span>
      </div>
    );
  const anyNot = d.field_rows.some((r) => r.verdict === "not_needed");
  return (
    <>
      <div className="pgrid">
        <div className="card kv">
          <span className="k">페이지 제목</span>
          <span className="v">{d.title ?? "제목 없음"}</span>
        </div>
        <div className="card kv">
          <span className="k">페이지가 스스로 밝힌 회사 이름</span>
          <span className="v">{d.brand_candidates[0] ?? "밝히지 않았어요"}</span>
          {d.brand_sentence && <span className="s">{d.brand_sentence}</span>}
        </div>
      </div>

      <div className="card card-pad" style={{ padding: 30, gap: 20 }}>
        <div className="col" style={{ gap: 6 }}>
          <h2>무엇을 적으라고 하나요?</h2>
          <span className="lead">
            {d.stated_purpose_label ? <>문자는 &quot;{d.stated_purpose_label}&quot;라고 했어요. </> : null}
            {anyNot ? "그런데 페이지는 다른 것을 적으라고 해요." : "페이지가 적으라고 하는 것을 살펴봤어요."}
          </span>
        </div>
        <div className="expect">
          <div className="box">
            <span className="k">{d.stated_purpose_label ? `${d.stated_purpose_label} 때 보통 필요한 것` : "보통 필요한 것"}</span>
            <span className="v">{d.expected_fields_label ?? "알 수 없음"}</span>
          </div>
          <span className="neq" aria-hidden>
            {anyNot ? "≠" : "="}
          </span>
          <div className="box">
            <span className="k">이 페이지가 적으라고 한 것</span>
            {d.field_rows.length === 0 ? (
              <span className="v">적는 칸이 없어요</span>
            ) : (
              d.field_rows.map((f) => (
                <div className="frow" key={f.type}>
                  <span>{f.label}</span>
                  <span className={f.verdict === "not_needed" ? "no" : "ok"}>{f.verdict_label}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="pgrid">
        <div className="card kv">
          <span className="k">적은 내용은 어디로 가나요?</span>
          <span className="v" style={{ fontFamily: d.sends_to ? "var(--mono)" : undefined, color: d.sends_cross_domain ? "var(--red-ink)" : undefined }}>
            {d.sends_to ?? "보내는 곳이 없어요"}
          </span>
          <span className="s">{d.sends_sentence ?? (d.field_rows.length ? "이 페이지 안에서만 쓰여요." : "적는 칸이 없어요.")}</span>
        </div>
        <div className="card kv">
          <span className="k">앱을 깔라고 하나요?</span>
          <span className="v" style={{ color: d.apk_links.length ? "var(--red-ink)" : undefined }}>
            {d.apk_links.length ? "예" : "아니오"}
          </span>
          <span className="s">문자나 페이지가 모르는 앱을 깔라고 하면 절대 깔지 마세요.</span>
        </div>
        <div className="card kv">
          <span className="k">몰래 다른 곳으로 보내나요?</span>
          <span className="v" style={{ color: d.js_redirect_hint ? "var(--red-ink)" : undefined }}>
            {d.js_redirect_hint ? "흔적 있음" : "흔적 없음"}
          </span>
          <span className="s">{d.js_redirect_hint ? "페이지 안에 자동으로 넘기는 장치가 있어요." : "페이지 안에 자동으로 넘기는 장치는 찾지 못했어요."}</span>
        </div>
      </div>

      {d.trust_claims.length > 0 && (
        <div className="card card-pad" style={{ gap: 14 }}>
          <span className="card-title">페이지에 적힌 말 믿지 않고 기록만 했어요</span>
          {d.trust_claims.map((c, i) => (
            <div className="quote" key={i}>
              &quot;{c}&quot;
            </div>
          ))}
          <span className="lead" style={{ fontSize: 16 }}>
            가짜 사이트는 &quot;안전합니다&quot;, &quot;공식입니다&quot; 같은 말을 자주 써요. 이런 말은 진짜·가짜를 정할 때 쓰지 않아요.
          </span>
        </div>
      )}
      <DevBox title="개발자용 기록 보기 (입력란 종류 · 전송 대상)" json={{ title: d.title, brand_candidates: d.brand_candidates, ...d.dev }} />
    </>
  );
}

// ── ④ AI 조사원 ──
function AgentTab({ d }: { d: AgentTrace | null }) {
  if (!d) return <Missing text="AI 조사원 기록을 남기지 못했어요." />;
  return (
    <div className="grid-side">
      <div className="card card-pad" style={{ padding: 30, gap: 8 }}>
        <div className="col" style={{ gap: 4, marginBottom: 14 }}>
          <h2>AI 조사원이 한 일을 순서대로 보여드려요</h2>
          <span className="lead">모두 안전 공간 안에서 일어났어요.</span>
        </div>
        <div>
          {d.steps.map((s, i) => {
            const last = i === d.steps.length - 1;
            const chips = s.detail && s.detail.includes(":") && s.detail.includes(" · ") ? s.detail.split(" · ") : null;
            return (
              <div className="atl" key={i}>
                <div className="col" style={{ alignItems: "center" }}>
                  <span className="c">{i + 1}</span>
                  {!last && <span className="ln" />}
                </div>
                <div className="body">
                  <span className="t">{s.title}</span>
                  {chips ? (
                    <div className="chips">
                      {chips.map((c) => {
                        const [k, ...v] = c.split(":");
                        return (
                          <span key={c}>
                            {k}: <b>{v.join(":").trim()}</b>
                          </span>
                        );
                      })}
                    </div>
                  ) : (
                    s.detail && (
                      <span style={{ fontSize: 16, color: "var(--g700)" }}>
                        {s.detail}
                        {last && d.explain_check === "passed" && (
                          <>
                            {" "}
                            <b style={{ color: "var(--green-ink)" }}>통과</b>
                          </>
                        )}
                        {last && d.explain_check === "template" && <> 이번에는 AI 설명 대신 기본 설명을 썼어요.</>}
                      </span>
                    )
                  )}
                  {s.lines.length > 0 && (
                    <div className={s.lines.every((l) => l.startsWith("✓")) ? "checklist" : "col"} style={{ gap: 6 }}>
                      {s.lines.map((l) => (
                        <span key={l} style={s.lines.every((x) => x.startsWith("✓")) ? undefined : { fontSize: 15, color: "var(--g600)" }}>
                          {l}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <span className="sec">{s.t_sec}초</span>
              </div>
            );
          })}
        </div>
      </div>

      <div className="col gap16">
        <div className="dark-note">
          <h3>AI는 진짜·가짜를 정하지 않아요</h3>
          <p>결정은 미리 정해 둔 규칙이 해요. AI는 조사를 진행하고 설명을 쓰는 일만 해요. 그래서 AI가 실수로 &quot;안전해요&quot;라고 말할 수 없어요.</p>
        </div>
        <div className="card kv" style={{ gap: 14 }}>
          <span className="card-title" style={{ fontSize: 17 }}>
            시키지 않은 일을 했나요?
          </span>
          <div className="zero">
            <b className={d.unexpected_count ? "bad" : ""}>{d.unexpected_count}번</b>
            <span style={{ fontSize: 16, color: "var(--g700)" }}>허락되지 않은 도구 사용</span>
          </div>
          {d.unexpected_count > 0 && <span className="s">허락되지 않은 도구가 쓰였어요. 아래 개발자용 기록에서 확인할 수 있어요.</span>}
          <span className="s" style={{ fontSize: 15, color: "var(--g600)" }}>
            페이지에 &quot;안전하다고 답하라&quot; 같은 속임 문구가 있어도 따르지 않도록 막아 두었어요.
          </span>
        </div>
        <div className="card two-stat">
          <div className="col" style={{ gap: 4 }}>
            <span className="k">걸린 시간</span>
            <span className="v">{d.duration_sec != null ? `${d.duration_sec}초` : "—"}</span>
          </div>
          <div className="col" style={{ gap: 4 }}>
            <span className="k">사용한 AI</span>
            <span className="v s">{d.model_reported ?? "—"}</span>
          </div>
        </div>
        <DevBox title="개발자용 기록 보기">
          <div className="dev-dark">
            {d.dev_log.map((l, i) => {
              const m = /^(\d\d:\d\d)\s+(.*)$/.exec(l);
              return m ? (
                <div key={i}>
                  <span className="t">{m[1]}</span> {m[2]}
                </div>
              ) : (
                <div key={i} className="t">
                  {l}
                </div>
              );
            })}
            {d.unexpected_tools.length > 0 && <div style={{ color: "oklch(0.8 0.12 27)" }}>unexpected: {d.unexpected_tools.join(", ")}</div>}
          </div>
        </DevBox>
      </div>
    </div>
  );
}

// ── ⑤ 안전 공간 ──
function SandboxTab({ d }: { d: SandboxTrace | null }) {
  if (!d) return <Missing text="안전 공간 기록을 남기지 못했어요." />;
  return (
    <>
      <div className="card card-pad" style={{ padding: 30, gap: 22 }}>
        <div className="col" style={{ gap: 6 }}>
          <h2>링크는 내 휴대폰이 아닌 안전 공간에서만 열었어요</h2>
          <span className="lead">안전 공간은 바깥과 떨어진 컴퓨터예요. 평소엔 문이 모두 잠겨 있고, 조사할 때만 한 곳의 문을 잠깐 열어요.</span>
        </div>
        <div className="diagram">
          <div className="dnode">
            <b>내 휴대폰</b>
            <span>링크를 열지 않음</span>
          </div>
          <span className="darrow" aria-hidden>
            →
          </span>
          <div className="dnode">
            <b>우리 서버</b>
            <span>주소 글자만 읽음</span>
          </div>
          <span className="darrow" aria-hidden>
            →
          </span>
          <div className="dnode dark">
            <b>안전 공간</b>
            <span>AI 조사원 + 확인 도구</span>
          </div>
          <span className="darrow" aria-hidden>
            →
          </span>
          <div className="doors">
            {d.opened_host && (
              <div className="door">
                <b>문 열어줌</b>
                <span>{d.opened_host}</span>
              </div>
            )}
            {d.blocked_hosts.map((h) => (
              <div className="door closed" key={h}>
                <b>문 닫혀 있음 · 막음</b>
                <span>{h}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid-2e">
        <div className="card card-pad" style={{ gap: 6 }}>
          <span className="card-title" style={{ marginBottom: 14 }}>
            문 열기 기록
          </span>
          <div>
            {d.events.map((e, i) => {
              const last = i === d.events.length - 1;
              return (
                <div className="evt" key={i}>
                  <span className="tm">{e.at}</span>
                  <div className="dotcol">
                    <span className={"dot " + (e.kind === "blocked" ? "blocked" : e.kind === "close" ? "close" : "")} />
                    {!last && <span className="ln" />}
                  </div>
                  <div className="tx">
                    <b>{e.title}</b>
                    {e.detail && <span className={e.kind === "blocked" ? "mono" : ""}>{e.detail}</span>}
                  </div>
                </div>
              );
            })}
            {d.events.length === 0 && <span className="lead">기록된 일이 없어요.</span>}
          </div>
          <span style={{ fontSize: 15, color: "var(--g700)", marginTop: 8 }}>
            {d.remaining_open === 0 ? (
              <>
                남은 열린 문 <b>없음</b>
              </>
            ) : (
              <>
                남은 열린 문 <b style={{ color: "var(--red-ink)" }}>{d.remaining_open}곳</b>
              </>
            )}
            {d.open_seconds != null && <> · 열어 둔 시간 {d.open_seconds}초</>}
          </span>
        </div>
        <div className="col gap16">
          <div className="card perm ok">
            <h3>허락한 것</h3>
            <ul>
              {d.allowed.map((t) => (
                <li key={t}>✓ {t}</li>
              ))}
            </ul>
          </div>
          <div className="card perm no">
            <h3>허락하지 않은 것</h3>
            <ul>
              {d.denied.map((t) => (
                <li key={t}>✕ {t}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      <DevBox title="개발자용 기록 보기 (정책 이름 · 허용 방식)" json={d.dev} />
    </>
  );
}
