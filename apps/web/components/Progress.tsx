"use client";
import type { JobView, StepKey, StepState } from "@/lib/types";

export const STEP_TITLE: Record<StepKey, string> = {
  claim: "누가 보낸 척하는지 확인",
  address: "주소 살펴보기",
  sandbox: "안전 공간에서 열어보기",
  page: "페이지 속 내용 살펴보기",
  summary: "결과 정리",
};

const WAITING_HINT: Record<StepKey, string> = {
  claim: "누가 보낸 척하는 문자인지 봐요",
  address: "주소를 조각내서 살펴봐요",
  sandbox: "사이트의 허용된 주소를 안전 공간에서 열어봐요",
  page: "무엇을 적으라고 하는지 봐요",
  summary: "쉽게 설명을 써요",
};

const STATUS_TEXT: Record<StepState["status"], string> = {
  done: "끝",
  running: "하는 중",
  waiting: "기다리는 중",
  stopped: "멈춤",
};

function Icon({ status }: { status: StepState["status"] }) {
  if (status === "done") return <span className="ico">✓</span>;
  if (status === "stopped") return <span className="ico">!</span>;
  return <span className="ico" />;
}

export function StepList({ steps }: { steps: StepState[] }) {
  return (
    <ol className="steps" aria-label="확인 순서">
      {steps.map((s) => (
        <li key={s.key} className={"step " + s.status}>
          <Icon status={s.status} />
          <div className="col" style={{ gap: 4 }}>
            <span className="t">{STEP_TITLE[s.key]}</span>
            <span className="d">{s.detail ?? WAITING_HINT[s.key]}</span>
          </div>
          <span className="st">{STATUS_TEXT[s.status]}</span>
        </li>
      ))}
    </ol>
  );
}

export function ProgressView({ job, elapsedMs }: { job: JobView; elapsedMs: number }) {
  const queued = job.status === "queued";
  const sec = Math.floor(elapsedMs / 1000);
  const pct = Math.min(96, Math.round((elapsedMs / 90000) * 100));
  const sandboxRunning = job.steps.find((s) => s.key === "sandbox")?.status === "running" || job.open_hosts.length > 0;

  return (
    <div className="progress-grid">
      <div className="col gap22">
        <div className="col gap8">
          <h1>{queued ? "순서를 기다리고 있어요" : "확인하고 있어요"}</h1>
          <span className="progress-sub">
            {queued ? "안전을 위해 한 번에 한 건씩 확인해요." : "확인하는 동안 이 화면을 열어 두세요. 1분 이상 걸릴 수 있어요."}
          </span>
        </div>
        {queued && (
          <div className="card queue-card" role="status">
            <span className="queue-num" aria-label={`내 앞에 ${job.position}건`}>
              {Math.max(1, job.position)}
            </span>
            <div className="col" style={{ gap: 4 }}>
              <span className="t">앞 사람의 확인이 끝나면 바로 시작해요</span>
              <span className="d">앞선 조사가 끝나면 시작해요. 대기 시간이 추가될 수 있어요.</span>
            </div>
          </div>
        )}
        <div aria-live="polite">
          <StepList steps={job.steps} />
        </div>
      </div>

      <div className="side">
        <div className="card timer">
          <div className="row">
            <b>지난 시간</b>
            <span className="big">{sec}초</span>
          </div>
          <div className="bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label="진행 정도">
            <i style={{ width: `${pct}%` }} />
          </div>
          <span className="hint">진행 상황에 따라 1분 이상 걸릴 수 있어요</span>
        </div>
        {sandboxRunning ? (
          <div className="vault">
            <div className="h">
              <i />
              <span>안전 공간에서 여는 중</span>
            </div>
            <p>
              이 사이트의 <b>허용된 주소만</b> 문을 열어 두었어요. 확인이 끝나면 문을 바로 닫아요.
            </p>
            <div className="blocked">
              <span>막은 곳</span>
              <b>{job.blocked_count}곳</b>
            </div>
          </div>
        ) : (
          <div className="note-card">
            <p>링크는 안전 공간에서만 열고, 조사할 사이트의 허용된 주소만 문을 열었다가 닫아요.</p>
          </div>
        )}
      </div>
    </div>
  );
}
