// 서버 전용: 브라우저 요청을 FastAPI(루프백)로 전달한다. 토큰·키는 이 경계 안쪽에만 있다.
import { randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { cookies, headers } from "next/headers";
import { NextResponse } from "next/server";

const API_BASE = (process.env.API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

export const isMock = () => process.env.API_MOCK === "1";

export function errorResponse(status: number, code: string, message: string) {
  return NextResponse.json({ error: { code, message } }, { status });
}

// 익명 세션: 브라우저는 httpOnly 쿠키만 갖고, FastAPI에는 이 서버가 헤더로 전달한다.
// 조사 결과는 만든 세션에서만 열린다(다른 브라우저·링크 공유로는 열리지 않는다).
const SESSION_COOKIE = "sid";
const SESSION_TTL_S = 60 * 60 * 24;

async function getSession(): Promise<{ sid: string; fresh: boolean }> {
  const existing = (await cookies()).get(SESSION_COOKIE)?.value;
  if (existing && /^[A-Za-z0-9_-]{32,128}$/.test(existing)) return { sid: existing, fresh: false };
  return { sid: randomBytes(24).toString("base64url"), fresh: true };
}

/**
 * 클라이언트 주소. 요청 제한에만 쓴다.
 * 헤더는 클라이언트가 마음대로 보낼 수 있으므로, 앞단(nginx 등)이 이 헤더를 덮어쓰고 이 서버로 직접 들어오는 길을 막았다고
 * 운영자가 확인해 TRUST_PROXY_HEADERS=1로 켠 경우에만 믿는다. 그렇지 않으면 주소를 넘기지 않고, API는 모든 요청을
 * 하나의 낮은 합계 한도로 제한한다(쿠키·헤더를 바꿔 가며 한도를 피할 수 없다).
 */
async function clientIp(): Promise<string> {
  if (process.env.TRUST_PROXY_HEADERS !== "1") return "";
  const h = await headers();
  const forwarded = h.get("x-forwarded-for")?.split(",").map((v) => v.trim()).filter(Boolean).pop(); // 앞단이 덧붙인 마지막 값
  const ip = (h.get("x-real-ip") ?? forwarded ?? "").trim();
  return isIP(ip) ? ip : "";
}

/** FastAPI 응답을 그대로(상태 코드 포함) 돌려준다. 연결 실패는 502로 바꾼다. */
export async function forward(path: string, init?: RequestInit): Promise<Response> {
  try {
    const { sid, fresh } = await getSession();
    const ip = await clientIp();
    const res = await fetch(API_BASE + path, {
      ...init,
      headers: { ...(init?.headers as Record<string, string> | undefined), "X-Session-Id": sid, ...(ip ? { "X-Client-Ip": ip } : {}) },
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
    });
    const text = await res.text();
    const out = new NextResponse(text, {
      status: res.status,
      headers: { "Content-Type": res.headers.get("content-type") ?? "application/json" },
    });
    if (fresh) {
      out.cookies.set(SESSION_COOKIE, sid, {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production" && process.env.COOKIE_SECURE !== "0", // HTTP로만 시연할 때는 COOKIE_SECURE=0
        path: "/",
        maxAge: SESSION_TTL_S,
      });
    }
    return out;
  } catch {
    return errorResponse(502, "backend_unreachable", "확인 서버에 연결하지 못했어요.");
  }
}
