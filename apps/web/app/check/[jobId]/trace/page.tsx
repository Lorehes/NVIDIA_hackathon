import { TraceView } from "@/components/Trace";
import { parseTab } from "@/lib/tabs";

export default async function Page({
  params,
  searchParams,
}: {
  params: Promise<{ jobId: string }>;
  searchParams: Promise<{ tab?: string }>;
}) {
  const { jobId } = await params;
  const { tab } = await searchParams;
  return <TraceView jobId={jobId} tab={parseTab(tab)} />;
}
