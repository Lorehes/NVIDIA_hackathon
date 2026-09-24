import { NextResponse } from "next/server";
import { findLinks, MAX_INPUT } from "@/lib/links";
import { pickScenario } from "@/mocks/data";
import { errorResponse, forward, isMock } from "@/lib/server/proxy";

export const dynamic = "force-dynamic";

const MAX_BODY_BYTES = 32 * 1024;

/** 본문을 읽는 도중에 바이트 수를 세고, 한도를 넘으면 읽기를 멈춘다(Content-Length가 없거나 거짓이어도 통한다). */
async function readBounded(req: Request, limit: number): Promise<string | null> {
  const reader = req.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function POST(req: Request) {
  // 크기를 먼저 막는다: 선언된 길이를 보고, 실제로 읽는 동안에도 센다(FastAPI도 같은 한도를 다시 검사한다)
  const declared = Number(req.headers.get("content-length") ?? 0);
  if (declared > MAX_BODY_BYTES) return errorResponse(413, "body_too_large", "글이 너무 길어요.");
  const raw = await readBounded(req, MAX_BODY_BYTES);
  if (raw === null) return errorResponse(413, "body_too_large", "글이 너무 길어요.");
  let body: { input?: unknown; mode?: unknown; case_id?: unknown };
  try {
    body = JSON.parse(raw);
  } catch {
    return errorResponse(400, "bad_request", "요청을 읽지 못했어요.");
  }
  if (!body || typeof body !== "object") return errorResponse(400, "bad_request", "요청을 읽지 못했어요.");
  const input = typeof body.input === "string" ? body.input : "";
  const mode = body.mode === "replay" ? "replay" : "live";
  const case_id = typeof body.case_id === "string" ? body.case_id : null;
  if (!input.trim()) return errorResponse(400, "no_url_found", "이 문자에는 링크가 없어요.");
  if (input.length > MAX_INPUT) return errorResponse(400, "input_too_long", "글이 너무 길어요.");

  if (isMock()) {
    const links = findLinks(input);
    if (links.length === 0) return errorResponse(400, "no_url_found", "이 문자에는 링크가 없어요.");
    const scenario = pickScenario(input);
    return NextResponse.json(
      {
        job_id: `mock_${scenario}_${Date.now()}`,
        status: "queued",
        position: 0,
        url: links[0].url,
        more_urls: links.slice(1).map((l) => l.url),
      },
      { status: 202 },
    );
  }
  return forward("/api/investigations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input, mode, case_id }),
  });
}
