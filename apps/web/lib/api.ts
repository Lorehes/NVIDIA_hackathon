// 브라우저 → Next 서버(/api/*) 호출. FastAPI에는 브라우저가 직접 접속하지 않는다.
import type {
  ApiErrorBody,
  DemoCase,
  InvestigationAccepted,
  InvestigationRequest,
  JobView,
  Trace,
} from "./types";

export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { cache: "no-store", ...init });
  } catch {
    throw new ApiError("network", "인터넷 연결을 확인해 주세요.", 0);
  }
  if (!res.ok) {
    let body: Partial<ApiErrorBody> = {};
    try {
      body = await res.json();
    } catch {
      /* 본문이 JSON이 아님 */
    }
    throw new ApiError(body.error?.code ?? "unknown", body.error?.message ?? "잠시 뒤에 다시 해 주세요.", res.status);
  }
  return (await res.json()) as T;
}

export function postInvestigation(req: InvestigationRequest): Promise<InvestigationAccepted> {
  return call("/api/investigations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
}

export const getJob = (id: string) => call<JobView>(`/api/investigations/${encodeURIComponent(id)}`);
export const getTrace = (id: string) => call<Trace>(`/api/investigations/${encodeURIComponent(id)}/trace`);
export const getDemoCases = () => call<DemoCase[]>("/api/demo-cases");

/** 오류 코드를 쉬운 말로 바꾼다. */
export function friendlyError(e: unknown): string {
  if (e instanceof ApiError) {
    switch (e.code) {
      case "no_url_found":
        return "이 문자에는 링크가 없어요. 링크가 있는 문자를 넣어 주세요.";
      case "input_too_long":
        return "글이 너무 길어요. 2,000자 안으로 줄여 주세요.";
      case "queue_full":
        return "지금 확인하려는 사람이 많아요. 잠시 뒤에 다시 눌러 주세요.";
      case "not_found":
        return "이 확인 기록을 찾지 못했어요. 처음부터 다시 확인해 주세요.";
      case "backend_unreachable":
        return "확인 서버에 연결하지 못했어요. 잠시 뒤에 다시 해 주세요.";
      default:
        return e.message || "잠시 뒤에 다시 해 주세요.";
    }
  }
  return "잠시 뒤에 다시 해 주세요.";
}
