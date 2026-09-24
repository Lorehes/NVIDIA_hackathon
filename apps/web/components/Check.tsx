"use client";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { ApiError, friendlyError, getJob } from "@/lib/api";
import { setDemo } from "@/lib/demo";
import type { JobView } from "@/lib/types";
import { ProgressView } from "./Progress";
import { FailedView, ResultView } from "./Result";
import { Loading } from "./ui";

const POLL_MS = 2000;

export function Check({ jobId }: { jobId: string }) {
  const [job, setJob] = useState<JobView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const fetchedAt = useRef(Date.now());

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;

    async function tick() {
      try {
        const j = await getJob(jobId);
        if (!alive) return;
        failures = 0;
        fetchedAt.current = Date.now();
        setJob(j);
        setError(null);
        if (j.mode === "replay") setDemo(true);
        if (j.status === "queued" || j.status === "running") timer = setTimeout(tick, POLL_MS);
      } catch (e) {
        if (!alive) return;
        if (e instanceof ApiError && e.code === "not_found") {
          setError(friendlyError(e));
          return;
        }
        failures += 1;
        if (failures >= 5) {
          setError(friendlyError(e));
          return;
        }
        timer = setTimeout(tick, POLL_MS);
      }
    }
    tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [jobId]);

  // 서버 응답 사이에도 "지난 시간"이 1초마다 올라가도록 한다.
  const active = job && (job.status === "queued" || job.status === "running");
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [active]);

  if (error)
    return (
      <div className="center-msg" role="alert">
        <h1>확인 기록을 불러오지 못했어요</h1>
        <p>{error}</p>
        <Link href="/" className="btn-main">
          처음으로 가기
        </Link>
      </div>
    );
  if (!job) return <Loading />;

  if (job.status === "done" && job.result) return <ResultView job={job} result={job.result} />;
  if (job.status === "failed" || (job.status === "done" && !job.result)) return <FailedView job={job} />;

  const elapsed = job.status === "queued" ? 0 : job.elapsed_ms + Math.max(0, now - fetchedAt.current);
  return <ProgressView job={job} elapsedMs={elapsed} />;
}
