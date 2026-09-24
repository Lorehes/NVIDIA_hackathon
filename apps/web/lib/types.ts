// apps/api/app/models.py 를 1:1로 옮긴 타입. 백엔드 스키마가 바뀌면 이 파일도 함께 바꾼다.

export type Verdict = "safe" | "caution" | "suspected_impersonation" | "unknown";
export type Strength = "positive" | "strong" | "mid" | "info";
export type JobStatus = "queued" | "running" | "done" | "failed";
export type Purpose =
  | "delivery"
  | "payment"
  | "account_security"
  | "government_notice"
  | "prize_event"
  | "other";
export type StepKey = "claim" | "address" | "sandbox" | "page" | "summary";
export type StepStatus = "waiting" | "running" | "done" | "stopped";
export type Mode = "live" | "replay";

// ── 요청 ──
export interface InvestigationRequest {
  input: string;
  mode?: Mode;
  case_id?: string | null;
}

export interface InvestigationAccepted {
  job_id: string;
  status: JobStatus;
  position: number;
  url: string;
  more_urls: string[];
}

// ── 결과 ──
export interface ClaimedEntity {
  id: string;
  name: string;
  source: "exact" | "alias" | "embedding" | "agent" | "address" | "none";
}

export interface Signal {
  type: string;
  strength: Strength;
  data: Record<string, unknown>;
}

export interface Explanation {
  headline: string;
  warning: string | null;
  detail: string | null;
  confirmed_facts: string[];
  suspicion_evidence: string[];
  unverified: string[];
  recommended_action: string;
  action_bullets: string[];
  source: "agent" | "template";
}

export interface UrlParts {
  url: string;
  scheme: string;
  subdomain_part: string;
  registrable_domain: string;
  path: string;
  official_domain: string | null;
  matches_official: boolean | null;
  matches_partner: boolean;
  partner_domain: string | null;
}

export interface ComparisonRow {
  key: "address" | "fields" | "promise" | "destination" | "redirect" | "sender";
  label: string;
  said: string;
  found: string;
  status: "ok" | "bad" | "warn" | "unknown";
  status_label: string;
}

export interface RiskItem {
  label: string;
  level: "high" | "mid" | "info";
  level_label: string;
}

export interface RedirectHop {
  url: string;
  host: string;
  registrable_domain: string;
  status: number | null;
  blocked: boolean;
  error: string | null;
  at: string | null;
}

export interface AgentSummary {
  tool_calls: string[];
  unexpected_tools: string[];
  duration_ms: number | null;
  model_reported: string | null;
  kind: "openshell" | "local-sim" | "replay";
}

export interface InvestigationResult {
  job_id: string;
  mode: Mode;
  input_kind: "message" | "url";
  verdict: Verdict;
  verdict_label: string;
  claimed_entity: ClaimedEntity | null;
  stated_purpose: Purpose | null;
  stated_purpose_label: string | null;
  url: string;
  actual_registrable_domain: string | null;
  url_parts: UrlParts | null;
  signals: Signal[];
  explanation: Explanation;
  comparison: ComparisonRow[];
  risks: RiskItem[];
  risks_note: string | null;
  redirect_chain: RedirectHop[];
  partial_findings: string[];
  incomplete_reason: string | null;
  more_urls: string[];
  agent: AgentSummary;
}

// ── 진행 상태 ──
export interface StepState {
  key: StepKey;
  title: string;
  status: StepStatus;
  detail: string | null;
}

export interface JobView {
  job_id: string;
  status: JobStatus;
  stage: string;
  stages: string[];
  steps: StepState[];
  position: number;
  mode: Mode;
  elapsed_ms: number;
  open_hosts: string[];
  blocked_count: number;
  url: string;
  more_urls: string[];
  result: InvestigationResult | null;
  error: string | null;
  timings_ms: Record<string, number>;
}

// ── 상세 기록 ──
export interface TrickCheck {
  key: "subdomain_disguise" | "lookalike" | "confusable" | "ip_host" | "userinfo";
  question: string;
  hint: string;
  hit: boolean;
  answer: string;
  detail: string | null;
}

export interface SimilarityRow {
  entity_id: string;
  name: string;
  domain: string;
  similarity: number;
  label: string;
  note: string | null;
}

export interface AddressTrace {
  url: string;
  scheme: string;
  host_unicode: string;
  host_ascii: string;
  subdomain_part: string;
  registrable_domain: string;
  path: string;
  tricks: TrickCheck[];
  similarity: SimilarityRow[];
  summary_sentence: string;
  kb_note: string;
  dev: Record<string, unknown>;
}

export interface RedirectTrace {
  chain: RedirectHop[];
  redirect_count: number;
  blocked_count: number;
  last_seen_domain: string | null;
  blocked_hosts: string[];
  dev: Record<string, unknown>;
}

export interface FieldRow {
  type: string;
  label: string;
  verdict: "needed" | "not_needed" | "ok";
  verdict_label: string;
}

export interface PageTrace {
  available: boolean;
  title: string | null;
  brand_candidates: string[];
  brand_sentence: string | null;
  stated_purpose_label: string | null;
  expected_fields_label: string | null;
  field_rows: FieldRow[];
  sends_to: string | null;
  sends_cross_domain: boolean;
  sends_sentence: string | null;
  apk_links: string[];
  js_redirect_hint: boolean;
  trust_claims: string[];
  dev: Record<string, unknown>;
}

export interface AgentStepTrace {
  t_sec: number;
  title: string;
  detail: string | null;
  lines: string[];
}

export interface AgentTrace {
  steps: AgentStepTrace[];
  unexpected_count: number;
  unexpected_tools: string[];
  duration_ms: number | null;
  duration_sec: number | null;
  model_reported: string | null;
  explain_check: "passed" | "template" | "skipped";
  dev_log: string[];
  dev: Record<string, unknown>;
}

export interface SandboxEvent {
  at: string;
  kind: "open" | "blocked" | "close";
  title: string;
  detail: string | null;
}

export interface SandboxTrace {
  opened_host: string | null;
  blocked_hosts: string[];
  events: SandboxEvent[];
  open_seconds: number | null;
  remaining_open: number;
  allowed: string[];
  denied: string[];
  dev: Record<string, unknown>;
}

export interface Trace {
  job_id: string;
  verdict: Verdict;
  verdict_label: string;
  address: AddressTrace | null;
  redirects: RedirectTrace | null;
  page: PageTrace | null;
  agent: AgentTrace | null;
  sandbox: SandboxTrace | null;
}

// ── 기타 ──
export interface DemoCase {
  id: string;
  label: string;
  input: string;
  expected_verdict: Verdict;
  available_replay: boolean;
}

export interface Health {
  ok: boolean;
  sandbox_mode: string;
  queue_length: number;
  running: boolean;
  sandbox: Record<string, unknown>;
  inference: Record<string, unknown>;
}

export interface ApiErrorBody {
  error: { code: string; message: string };
}
