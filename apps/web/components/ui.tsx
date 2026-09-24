import type { ReactNode } from "react";
import type { Verdict } from "@/lib/types";

export type Tone = "safe" | "bad" | "caution" | "unknown";

export function toneOf(v: Verdict): Tone {
  return v === "safe" ? "safe" : v === "suspected_impersonation" ? "bad" : v === "caution" ? "caution" : "unknown";
}

export const TONE_ICON: Record<Tone, string> = { safe: "✓", bad: "!", caution: "!", unknown: "?" };

/** "…" 로 감싼 부분을 굵게 보여 준다(쉬운 말 문장 강조). */
export function Emph({ text }: { text: string }) {
  const parts = text.split(/("[^"]+")/g);
  return (
    <>
      {parts.map((p, i) => (p.startsWith('"') && p.endsWith('"') ? <b key={i}>{p}</b> : <span key={i}>{p}</span>))}
    </>
  );
}

export function List({ items, className }: { items: string[]; className?: string }) {
  return (
    <ul className={className}>
      {items.map((t, i) => (
        <li key={i}>· {t}</li>
      ))}
    </ul>
  );
}

/** 개발자용 기록(접힘). 기술 이름은 여기에만 둔다. */
export function DevBox({ title, children, json }: { title: string; children?: ReactNode; json?: unknown }) {
  return (
    <details className="dev">
      <summary>
        <span>{title}</span>
        <span className="caret" aria-hidden>
          ▾
        </span>
      </summary>
      {children}
      {json !== undefined && <pre>{JSON.stringify(json, null, 2)}</pre>}
    </details>
  );
}

export function Loading({ text = "불러오는 중이에요…" }: { text?: string }) {
  return (
    <div className="center-msg" role="status" aria-live="polite">
      <p>{text}</p>
    </div>
  );
}
