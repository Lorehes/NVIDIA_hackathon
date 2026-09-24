"use client";
// 시연 모드(발표용): ?demo=1 로 켜고, sessionStorage에 기억한다. ?demo=0 이나 배너의 "끄기"로 끈다.
import type { DemoCase } from "./types";

const KEY = "demo-mode";
const EVT = "demo-mode-change";

export function getDemo(): boolean {
  try {
    return sessionStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function setDemo(on: boolean): void {
  try {
    if (on) sessionStorage.setItem(KEY, "1");
    else sessionStorage.removeItem(KEY);
  } catch {
    /* 저장소를 못 쓰는 브라우저에서는 이번 화면에서만 유지 */
  }
  window.dispatchEvent(new Event(EVT));
}

export function subscribeDemo(cb: () => void): () => void {
  window.addEventListener(EVT, cb);
  return () => window.removeEventListener(EVT, cb);
}

/** 주소창의 ?demo= 값을 읽어 반영한다. */
export function syncDemoFromUrl(): void {
  const p = new URLSearchParams(window.location.search).get("demo");
  if (p === "1") setDemo(true);
  else if (p === "0") setDemo(false);
}

// 예시 버튼 5개. /api/demo-cases 가 실패하면 이 값을 쓴다(백엔드 데모 입력과 같은 값).
export const FALLBACK_CASES: DemoCase[] = [
  {
    "id": "official",
    "label": "진짜 택배 사이트",
    "input": "[한빛택배] 고객님의 택배가 배송 중입니다. 배송 조회: https://hanbit.example/track/12345",
    "expected_verdict": "safe",
    "available_replay": true
  },
  {
    "id": "lookalike",
    "label": "한 글자 바꾼 가짜 주소",
    "input": "[한빛택배] 배송지 확인이 필요합니다. 로그인 후 확인: https://hanblt.example/login",
    "expected_verdict": "suspected_impersonation",
    "available_replay": true
  },
  {
    "id": "disguise",
    "label": "진짜 주소를 앞에 붙인 가짜",
    "input": "[한빛택배] 주소 불일치로 배송 보류. 수정: https://hanbit.example.account-check.test/login",
    "expected_verdict": "suspected_impersonation",
    "available_replay": true
  },
  {
    "id": "clone",
    "label": "화면을 베낀 가짜",
    "input": "[한빛택배] 배송지 오류로 반송 예정입니다. 주소 수정: https://hanbit-parcel.test/address",
    "expected_verdict": "suspected_impersonation",
    "available_replay": true
  },
  {
    "id": "partner",
    "label": "택배사가 쓰는 결제 사이트",
    "input": "[한빛택배] 착불 요금 3,500원 결제 안내: https://pay-partner.example/checkout",
    "expected_verdict": "safe",
    "available_replay": true
  }
];

const LAST_INPUT_KEY = "last-input:";

export function rememberInput(jobId: string, text: string): void {
  try {
    sessionStorage.setItem(LAST_INPUT_KEY + jobId, text);
  } catch {
    /* 무시 */
  }
}

export function recallInput(jobId: string): string | null {
  try {
    return sessionStorage.getItem(LAST_INPUT_KEY + jobId);
  } catch {
    return null;
  }
}
