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

/** 조사 요청을 보낸다. 시연 모드이고 붙여 넣은 글이 데모 사례와 같으면 저장된 결과(replay)를 요청한다. */
export async function startInvestigation(text: string): Promise<InvestigationAccepted> {
  let mode: "live" | "replay" = "live";
  let case_id: string | null = null;
  if (getDemo()) {
    const cases = await loadDemoCases();
    const hit = cases.find((c) => c.input.trim() === text.trim() && c.available_replay);
    if (hit) {
      mode = "replay";
      case_id = hit.id;
    }
  }
  const accepted = await postInvestigation({ input: text, mode, case_id });
  rememberInput(accepted.job_id, text);
  return accepted;
}
