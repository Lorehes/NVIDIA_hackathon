// 서버 전용: 브라우저 요청을 FastAPI(루프백)로 전달한다. 토큰·키는 이 경계 안쪽에만 있다.
import { NextResponse } from "next/server";

const API_BASE = (process.env.API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

export const isMock = () => process.env.API_MOCK === "1";

export function errorResponse(status: number, code: string, message: string) {
  return NextResponse.json({ error: { code, message } }, { status });
}

/** FastAPI 응답을 그대로(상태 코드 포함) 돌려준다. 연결 실패는 502로 바꾼다. */
export async function forward(path: string, init?: RequestInit): Promise<Response> {
  try {
    const res = await fetch(API_BASE + path, {
      ...init,
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
    });
    const text = await res.text();
    return new NextResponse(text, {
      status: res.status,
      headers: { "Content-Type": res.headers.get("content-type") ?? "application/json" },
    });
  } catch {
    return errorResponse(502, "backend_unreachable", "확인 서버에 연결하지 못했어요.");
  }
}
