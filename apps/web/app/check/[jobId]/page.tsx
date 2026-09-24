import { Check } from "@/components/Check";

export default async function Page({ params }: { params: Promise<{ jobId: string }> }) {
  const { jobId } = await params;
  return <Check jobId={jobId} />;
}
