import { NextResponse } from "next/server";
import { forward, isMock } from "@/lib/server/proxy";

export const dynamic = "force-dynamic";

export async function GET() {
  if (isMock()) {
    return NextResponse.json({ ok: true, sandbox_mode: "mock", queue_length: 0, running: false, sandbox: {}, inference: {} });
  }
  return forward("/api/health");
}
