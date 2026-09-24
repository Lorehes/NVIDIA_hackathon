"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Fragment, useState } from "react";
import { friendlyError } from "@/lib/api";
import { recallInput } from "@/lib/demo";
import { shortUrl } from "@/lib/links";
import { startInvestigation } from "@/lib/submit";
import type { ComparisonRow, InvestigationResult, JobView } from "@/lib/types";
import { List, toneOf, TONE_ICON, type Tone } from "./ui";
import { STEP_TITLE } from "./Progress";

const HERO_CLASS: Record<Tone, string> = { safe: "hero-safe", bad: "hero-bad", caution: "hero-caution", unknown: "hero-unknown" };
const OWNER_COLOR: Record<Tone, string> = { safe: "green", bad: "red", caution: "amber", unknown: "dark" };

function entityName(r: InvestigationResult): string {
  const sig = r.signals.find((s) => s.type === "entity_not_in_kb");
  const n = sig?.data?.name;
  if (typeof n === "string" && n) return n;
  return r.claimed_entity?.name ?? "이 회사";
}

/** 다시 확인하기: 처음 붙여 넣은 글(없으면 링크)로 새 조사를 시작한다. */
function useRestart(result: InvestigationResult) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function restart() {
    setBusy(true);
    setError(null);
    try {
      const accepted = await startInvestigation(recallInput(result.job_id) ?? result.url);
      router.replace(`/check/${encodeURIComponent(accepted.job_id)}`);
    } catch (e) {
      setError(friendlyError(e));
      setBusy(false);
    }
  }
  return { restart, busy, error };
}

export function ResultView({ job, result }: { job: JobView; result: InvestigationResult }) {
  const tone = toneOf(result.verdict);
  const unknown = tone === "unknown";
  const ex = result.explanation;
  const { restart, busy, error } = useRestart(result);
  const more = result.more_urls.length ? result.more_urls : job.more_urls;

  return (
    <>
      <Link href="/" className="back-bar">
        ← 다른 문자 확인
      </Link>
      <section className={`hero ${HERO_CLASS[tone]}${unknown ? " flex" : ""}`} aria-labelledby="result-h">
        <div className="wrap">
          <div className="col" style={{ gap: 16 }}>
            <span className={`badge badge-${tone}`}>
              <i aria-hidden>{TONE_ICON[tone]}</i>
              {result.verdict_label}
            </span>
            <h2 id="result-h">
              {ex.headline}
              {!unknown && ex.warning && (
                <>
                  <br />
                  {ex.warning}
                </>
              )}
            </h2>
            {unknown ? (
              <span className="sub">
                {result.incomplete_reason ?? ex.detail} {ex.warning && <b>{ex.warning}</b>}
              </span>
            ) : (
              ex.detail && <span className="sub">{ex.detail}</span>
            )}
          </div>
          {unknown && (
            <div className="col" style={{ gap: 8, flex: "none" }}>
              <button className="btn-main" onClick={restart} disabled={busy} style={{ padding: "16px 28px" }}>
                {busy ? "보내는 중…" : "다시 확인하기"}
              </button>
              {error && (
                <span role="alert" style={{ color: "var(--red-ink)", fontWeight: 600, fontSize: 15 }}>
                  {error}
                </span>
              )}
            </div>
          )}
        </div>
      </section>

      <div className="result-grid">
        <div className="col gap22">
          {more.length > 0 && (
            <div className="card more-urls">
              <b>문자에 링크가 {more.length + 1}개 있었어요. 첫 번째 링크만 확인했어요.</b>
              {more.map((u) => (
                <span className="l" key={u}>
                  {shortUrl(u)}
                </span>
              ))}
            </div>
          )}
          {unknown ? <UnknownBody job={job} result={result} /> : <KnownBody result={result} tone={tone} />}
        </div>
        <SideColumn result={result} tone={tone} />
      </div>
    </>
  );
}

// ── 안전·조심·가짜 ──
function KnownBody({ result, tone }: { result: InvestigationResult; tone: Tone }) {
  const ex = result.explanation;
  const cards: { key: string; node: React.ReactNode }[] = [];
  if (ex.confirmed_facts.length)
    cards.push({
      key: "facts",
      node: (
        <div className="info-card">
          <h3>확실한 것</h3>
          <List items={ex.confirmed_facts} />
        </div>
      ),
    });
  if (ex.suspicion_evidence.length)
    cards.push({
      key: "why",
      node: (
        <div className={"info-card " + (tone === "bad" ? "why" : "why-caution")}>
          <h3>{tone === "bad" ? "가짜라고 보는 이유" : "조심해야 하는 이유"}</h3>
          <List items={ex.suspicion_evidence} />
        </div>
      ),
    });
  if (ex.unverified.length)
    cards.push({
      key: "unv",
      node: (
        <div className="info-card unverified">
          <h3>확인하지 못한 것</h3>
          <List items={ex.unverified} />
        </div>
      ),
    });

  return (
    <>
      <OwnerCard result={result} tone={tone} />
      {result.comparison.length > 0 && <ComparisonCard rows={result.comparison} />}
      {cards.length > 0 && (
        <div className="info3" style={{ ["--n" as string]: cards.length }}>
          {cards.map((c) => (
            <div key={c.key} style={{ display: "contents" }}>
              {c.node}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function OwnerCard({ result, tone }: { result: InvestigationResult; tone: Tone }) {
  const p = result.url_parts;
  if (!p) return null;
  const color = OWNER_COLOR[tone];
  const name = entityName(result);
  const hasPrefix = p.subdomain_part.length > 0;
  const partner = p.matches_partner && p.partner_domain;

  return (
    <div className="card card-pad">
      <span className="card-title">이 링크의 진짜 주인은 누구일까요?</span>
      <div className="owner-row">
        {hasPrefix && (
          <div className="seg">
            <span className="blk prefix">{p.subdomain_part}</span>
            <span className="cap">
              앞에 붙인 글자
              <br />
              누구나 아무렇게나 붙일 수 있어요
            </span>
          </div>
        )}
        <div className="seg">
          <span className={`blk owner ${color}${hasPrefix ? "" : " solo"}`}>{p.registrable_domain}</span>
          <span className={`cap strong ${color}`}>
            진짜 사이트 이름
            {tone === "bad" && hasPrefix && (
              <>
                <br />이 부분이 진짜 주인이에요
              </>
            )}
          </span>
        </div>
        {p.path && p.path !== "/" && (
          <div className="seg">
            <span className="blk path">{p.path}</span>
            {!hasPrefix && <span className="cap grey">사이트 안의 위치</span>}
          </div>
        )}
      </div>

      <div className="compare2">
        {p.official_domain ? (
          <>
            <div className="cbox">
              <span>{name} 진짜 주소</span>
              <b>{p.official_domain}</b>
            </div>
            {partner ? (
              <>
                <div className="cbox">
                  <span>{name} 협력 회사</span>
                  <b>{p.partner_domain}</b>
                </div>
                <div className="cbox green" style={{ gridColumn: "1 / -1" }}>
                  <span>이 링크</span>
                  <b>{p.registrable_domain} 협력 회사 목록에 있어요 ✓</b>
                </div>
              </>
            ) : (
              <div className={"cbox " + (p.matches_official ? "green" : "red")}>
                <span>이 링크의 진짜 주인</span>
                <b>
                  {p.registrable_domain} {p.matches_official ? "✓ 같아요" : "✗ 달라요"}
                </b>
              </div>
            )}
          </>
        ) : (
          <>
            <div className="cbox">
              <span>{name} 진짜 주소</span>
              <b className="plain">목록에 없어서 비교할 수 없어요</b>
            </div>
            <div className={"cbox " + (tone === "caution" ? "amber" : "")}>
              <span>이 링크의 진짜 주인</span>
              <b>{p.registrable_domain}</b>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function ComparisonCard({ rows }: { rows: ComparisonRow[] }) {
  return (
    <div className="card table-card">
      <h3>문자가 한 말 vs 실제로 확인한 것</h3>
      <div className="cmp">
        <div className="head" />
        <div className="head">문자가 한 말</div>
        <div className="head">실제로 확인한 것</div>
        <div className="head" />
        {rows.map((r) => (
          <Fragment key={r.key}>
            <div>{r.label}</div>
            <div>{r.said}</div>
            <div className={"found " + (r.status === "unknown" ? "unknown" : "")}>{r.found}</div>
            <div className={"stt " + r.status}>{r.status_label}</div>
          </Fragment>
        ))}
      </div>
      <div className="cmp-m">
        {rows.map((r) => (
          <div className="r" key={r.key}>
            <span className="l">
              <span>{r.label}</span>
              <span className={"stt " + r.status} style={statusColor(r.status)}>
                {r.status_label}
              </span>
            </span>
            <span className="said">문자: {r.said}</span>
            <span className="found">{r.found}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function statusColor(s: ComparisonRow["status"]): React.CSSProperties {
  const c = { bad: "var(--red-ink2)", ok: "var(--green-ink)", warn: "var(--amber-ink)", unknown: "var(--g600)" }[s];
  return { color: c, fontWeight: 700 };
}

function SideColumn({ result, tone }: { result: InvestigationResult; tone: Tone }) {
  const ex = result.explanation;
  const unknown = tone === "unknown";
  const partner = !!result.url_parts?.matches_partner;
  return (
    <div className="col gap16">
      <div className="action-card">
        <span className="k">이렇게 하세요</span>
        <span className="big">{ex.recommended_action}</span>
        {ex.action_bullets.length > 0 && <List items={ex.action_bullets} />}
      </div>

      {unknown ? (
        <div className="card risk-card">
          <h3>&quot;알 수 없어요&quot;가 나오는 경우</h3>
          <div className="col gap8" style={{ fontSize: 16, lineHeight: 1.55, color: "var(--ink2)" }}>
            <span>· 조사가 중간에 멈췄을 때</span>
            <span>· 사이트가 열리지 않을 때</span>
            <span>· 비교할 진짜 주소가 없고, 위험한 점도 없을 때</span>
          </div>
        </div>
      ) : (
        <div className="card risk-card">
          <h3>위험한 점 한눈에 보기</h3>
          {result.risks.length === 0 ? (
            <span className="risk-none">위험한 점을 찾지 못했어요</span>
          ) : (
            <div className="risk-list">
              {result.risks.map((r) => (
                <div key={r.label}>
                  <span>{r.label}</span>
                  <span className={`lvl ${r.level}`}>{r.level_label}</span>
                </div>
              ))}
            </div>
          )}
          {result.risks_note && <span className="foot-note" style={{ borderTop: 0, paddingTop: 0 }}>{result.risks_note}</span>}
          {partner ? (
            <span className="foot-note">
              <b>알아두세요</b> 회사들은 결제나 본인 확인을 다른 전문 회사에 맡기기도 해요. 저희는 회사가 직접 밝힌 협력 회사
              목록과 비교해요. 진짜·가짜 결정은 정해진 규칙으로 하고, 설명 글만 AI가 썼어요.
            </span>
          ) : (
            <span className="foot-note">진짜·가짜 결정은 정해진 규칙으로 하고, 설명 글만 AI가 썼어요.</span>
          )}
        </div>
      )}

      <Link
        className="card link-card"
        href={unknown ? `/check/${encodeURIComponent(result.job_id)}/trace?tab=address` : `/check/${encodeURIComponent(result.job_id)}/trace`}
      >
        <span>{unknown ? "주소 살펴보기 결과만 보기" : "어떻게 조사했는지 보기"}</span>
        <span aria-hidden>→</span>
      </Link>
    </div>
  );
}

// ── 알 수 없어요 ──
function diffMarks(official: string, actual: string): React.ReactNode {
  if (official.length !== actual.length) return actual;
  return (
    <>
      {actual.split("").map((ch, i) => (ch !== official[i] ? <u key={i}>{ch}</u> : <span key={i}>{ch}</span>))}
    </>
  );
}

function UnknownBody({ job, result }: { job: JobView; result: InvestigationResult }) {
  const p = result.url_parts;
  const steps = job.steps.filter((s) => s.key !== "summary");
  const showVs = !!(p?.official_domain && p.registrable_domain && p.official_domain !== p.registrable_domain);
  return (
    <>
      <div className="card card-pad" style={{ gap: 6 }}>
        <span className="card-title" style={{ marginBottom: 12 }}>
          어디까지 확인했나요?
        </span>
        <div className="checked-list">
          {steps.map((s) => (
            <div key={s.key} className={"checked " + s.status}>
              <span className="ico">{s.status === "done" ? "✓" : s.status === "stopped" ? "!" : ""}</span>
              <div className="col" style={{ gap: 3 }}>
                <span className="t">{STEP_TITLE[s.key]}</span>
                {s.status !== "waiting" && s.detail && <span className="d">{s.detail}</span>}
              </div>
              <span className="st">
                {s.status === "done" ? "끝" : s.status === "stopped" ? "멈춤" : "못 함"}
              </span>
            </div>
          ))}
        </div>
      </div>

      {(result.partial_findings.length > 0 || showVs) && (
        <div className="card card-pad" style={{ gap: 16 }}>
          <div className="row" style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <span className="card-title">멈추기 전에 발견한 것</span>
            <span className="chip chip-amber">참고만 하세요</span>
          </div>
          {showVs && p && (
            <div className="vs">
              <span className="box">
                {p.official_domain} <small>진짜</small>
              </span>
              <span className="v">vs</span>
              <span className="box warn">
                {diffMarks(p.official_domain!, p.registrable_domain)} <small>이 링크</small>
              </span>
            </div>
          )}
          {result.partial_findings.map((t, i) => (
            <span key={i} style={{ fontSize: 17, lineHeight: 1.6, color: "var(--ink2)" }}>
              {t}
            </span>
          ))}
        </div>
      )}
    </>
  );
}

/** 오류로 끝난(failed) 작업 */
export function FailedView({ job }: { job: JobView }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function retry() {
    setBusy(true);
    setError(null);
    try {
      const a = await startInvestigation(recallInput(job.job_id) ?? job.url);
      router.replace(`/check/${encodeURIComponent(a.job_id)}`);
    } catch (e) {
      setError(friendlyError(e));
      setBusy(false);
    }
  }
  return (
    <section className="hero hero-unknown">
      <div className="wrap">
        <span className="badge badge-unknown">
          <i aria-hidden>?</i>알 수 없어요
        </span>
        <h2>지금은 확인을 끝내지 못했어요.</h2>
        <span className="sub">
          {job.error ?? "조사 중에 문제가 생겼어요."} <b>안전하다는 뜻이 아니니</b> 아직 링크를 누르지 마세요.
        </span>
        <div className="col" style={{ gap: 8, alignSelf: "flex-start" }}>
          <button className="btn-main" onClick={retry} disabled={busy}>
            {busy ? "보내는 중…" : "다시 확인하기"}
          </button>
          {error && (
            <span role="alert" style={{ color: "var(--red-ink)", fontWeight: 600 }}>
              {error}
            </span>
          )}
        </div>
      </div>
    </section>
  );
}
