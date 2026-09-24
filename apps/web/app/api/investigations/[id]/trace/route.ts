import { NextResponse } from "next/server";
import { mockTrace } from "@/mocks/data";
import { errorResponse, forward, isMock } from "@/lib/server/proxy";

export const dynamic = "force-dynamic";

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (isMock()) {
    const t = mockTrace(id);
    return t ? NextResponse.json(t) : errorResponse(404, "not_found", "찾지 못했어요.");
  }
  return forward(`/api/investigations/${encodeURIComponent(id)}/trace`);
}
