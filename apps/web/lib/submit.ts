"use client";
import { getDemoCases, postInvestigation } from "./api";
import { FALLBACK_CASES, getDemo, rememberInput } from "./demo";
import type { DemoCase, InvestigationAccepted } from "./types";

let casesCache: DemoCase[] | null = null;

/** 데모 사례 5개. 서버가 못 주면 화면에 내장한 값을 쓴다. */
export async function loadDemoCases(): Promise<DemoCase[]> {
  if (casesCache) return casesCache;
  try {
    const list = await getDemoCases();
    casesCache = list.length ? list : FALLBACK_CASES;
  } catch {
    casesCache = FALLBACK_CASES;
  }
  return casesCache;
}

/** 시연 모드에서는 서버가 저장된 입력을 찾는다. 없는 입력을 실시간 조사로 전환하지 않는다. */
export async function startInvestigation(text: string): Promise<InvestigationAccepted> {
  const mode = getDemo() ? "replay" : "live";
  const accepted = await postInvestigation({ input: text, mode });
  rememberInput(accepted.job_id, text);
  return accepted;
}
