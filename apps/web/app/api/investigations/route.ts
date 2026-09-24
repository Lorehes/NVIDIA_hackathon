import { NextResponse } from "next/server";
import { findLinks, MAX_INPUT } from "@/lib/links";
import { pickScenario } from "@/mocks/data";
import { errorResponse, forward, isMock } from "@/lib/server/proxy";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  let body: { input?: unknown; mode?: unknown; case_id?: unknown };
  try {
    body = await req.json();
  } catch {
    return errorResponse(400, "bad_request", "요청을 읽지 못했어요.");
  }
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
