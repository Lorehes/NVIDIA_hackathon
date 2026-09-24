import { NextResponse } from "next/server";
import { MOCK_CASES } from "@/mocks/data";
import { forward, isMock } from "@/lib/server/proxy";

export const dynamic = "force-dynamic";

export async function GET() {
  if (isMock()) return NextResponse.json(MOCK_CASES);
  return forward("/api/demo-cases");
}
