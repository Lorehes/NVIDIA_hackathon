// API_MOCK=1 일 때 라우트 핸들러가 돌려주는 예시 데이터. 백엔드 없이 화면을 확인하기 위한 것이다.
import type {
  DemoCase,
  InvestigationResult,
  JobView,
  StepState,
  Trace,
} from "@/lib/types";

export type Scenario = "suspected" | "safe" | "partner" | "caution" | "unknown";

const NO_SENDER = "문자를 보낸 전화번호가 진짜인지";

const agentBase = {
  tool_calls: ["read", "exec", "exec"],
  unexpected_tools: [] as string[],
  duration_ms: 14210,
  model_reported: "NVIDIA Nemotron",
  kind: "replay" as const,
};

function result(s: Scenario, jobId: string): InvestigationResult {
  switch (s) {
    case "suspected":
      return {
        job_id: jobId,
        mode: "live",
        input_kind: "message",
        verdict: "suspected_impersonation",
        verdict_label: "가짜로 의심돼요",
        claimed_entity: { id: "hanbit", name: "한빛택배", source: "exact" },
        stated_purpose: "delivery",
        stated_purpose_label: "택배 안내",
        url: "https://hanbit.example.account-check.test/login",
        actual_registrable_domain: "account-check.test",
        url_parts: {
          url: "https://hanbit.example.account-check.test/login",
          scheme: "https",
          subdomain_part: "hanbit.example.",
          registrable_domain: "account-check.test",
          path: "/login",
          official_domain: "hanbit.example",
          matches_official: false,
          matches_partner: false,
          partner_domain: null,
        },
        signals: [
          { type: "subdomain_disguise", strength: "strong", data: { label: "hanbit.example" } },
          { type: "purpose_mismatch", strength: "strong", data: { fields: ["card_number", "card_cvc"] } },
          { type: "credential_form", strength: "mid", data: {} },
          { type: "cross_domain_form", strength: "mid", data: { action_host: "collect-pay.test" } },
          { type: "redirect_blocked", strength: "info", data: { host: "collect-pay.test" } },
        ],
        explanation: {
          headline: "한빛택배를 흉내 낸 가짜 사이트 같아요.",
          warning: "링크를 누르지 마세요.",
          detail: "한빛택배의 진짜 주소가 아니고, 택배 일에는 필요 없는 카드 번호를 적으라고 해요.",
          confirmed_facts: [
            "진짜 사이트 이름은 account-check.test예요.",
            "카드 번호, 카드 뒷면 숫자를 적는 칸이 있어요.",
            "다른 사이트로 넘어가려 해서 막았어요.",
          ],
          suspicion_evidence: [
            "주소 앞에 한빛택배 주소를 붙여서 진짜처럼 보이게 했어요.",
            "택배 주소를 고치는 데 카드 번호는 필요 없어요.",
          ],
          unverified: [NO_SENDER, "페이지가 나중에 스스로 바뀌는 내용"],
          recommended_action: "한빛택배 공식 앱을 직접 열어서 배송 상태를 확인하세요.",
          action_bullets: [
            "문자 속 링크는 누르지 마세요.",
            "이미 카드 번호를 적었다면 카드 회사에 바로 전화하세요.",
            "문자는 지워도 괜찮아요.",
          ],
          source: "agent",
        },
        comparison: [
          { key: "address", label: "주소", said: "한빛택배 사이트예요", found: "다른 사람의 사이트예요", status: "bad", status_label: "달라요" },
          { key: "fields", label: "적는 칸", said: "배송 주소를 고쳐 주세요", found: "카드 번호를 적으라고 해요", status: "bad", status_label: "달라요" },
          { key: "promise", label: "회사 약속", said: "한빛택배는 문자로 카드 번호를 묻지 않아요", found: "카드 번호를 물어요", status: "bad", status_label: "약속과 달라요" },
          { key: "sender", label: "보낸 번호", said: "한빛택배가 보냈어요", found: "확인할 방법이 없어요", status: "unknown", status_label: "모름" },
        ],
        risks: [
          { label: "진짜 주소를 앞에 붙임", level: "high", level_label: "많이 위험" },
          { label: "필요 없는 카드 정보 요구", level: "high", level_label: "많이 위험" },
          { label: "개인 정보 적는 칸", level: "mid", level_label: "조금 위험" },
          { label: "다른 곳으로 넘어가려 함", level: "info", level_label: "참고" },
        ],
        risks_note: null,
        redirect_chain: [
          { url: "https://hanbit.example.account-check.test/login", host: "hanbit.example.account-check.test", registrable_domain: "account-check.test", status: 302, blocked: false, error: null, at: "2026-09-24T14:31:53Z" },
          { url: "https://collect-pay.test/card", host: "collect-pay.test", registrable_domain: "collect-pay.test", status: 403, blocked: true, error: null, at: "2026-09-24T14:31:58Z" },
        ],
        partial_findings: [],
        incomplete_reason: null,
        more_urls: [],
        agent: agentBase,
      };
    case "safe":
      return {
        job_id: jobId,
        mode: "live",
        input_kind: "message",
        verdict: "safe",
        verdict_label: "안전해요",
        claimed_entity: { id: "hanbit", name: "한빛택배", source: "exact" },
        stated_purpose: "delivery",
        stated_purpose_label: "택배 안내",
        url: "https://hanbit.example/track/12345",
        actual_registrable_domain: "hanbit.example",
        url_parts: {
          url: "https://hanbit.example/track/12345",
          scheme: "https",
          subdomain_part: "",
          registrable_domain: "hanbit.example",
          path: "/track/12345",
          official_domain: "hanbit.example",
          matches_official: true,
          matches_partner: false,
          partner_domain: null,
        },
        signals: [{ type: "official_match", strength: "positive", data: {} }],
        explanation: {
          headline: "한빛택배의 진짜 사이트예요.",
          warning: null,
          detail: "주소의 주인이 한빛택배 진짜 주소와 같고, 이상한 것을 적으라고 하지 않아요.",
          confirmed_facts: [
            "진짜 사이트 이름은 hanbit.example이에요.",
            "한빛택배 진짜 주소 목록에 있는 주소예요.",
            "카드 번호나 비밀번호를 묻지 않아요.",
          ],
          suspicion_evidence: [],
          unverified: [NO_SENDER, "페이지가 나중에 스스로 바뀌는 내용"],
          recommended_action: "링크를 열어도 괜찮아요.",
          action_bullets: [
            "그래도 카드 번호나 비밀번호를 적으라고 하면 멈추고 다시 확인하세요.",
            "불안하면 한빛택배 앱에서 직접 확인해도 돼요.",
          ],
          source: "template",
        },
        comparison: [
          { key: "address", label: "주소", said: "한빛택배 사이트예요", found: "한빛택배 사이트가 맞아요", status: "ok", status_label: "같아요" },
          { key: "fields", label: "적는 칸", said: "배송 조회", found: "적는 칸 없음 (조회만)", status: "ok", status_label: "맞아요" },
          { key: "redirect", label: "넘어간 곳", said: "—", found: "다른 곳으로 넘어가지 않았어요", status: "ok", status_label: "괜찮아요" },
          { key: "sender", label: "보낸 번호", said: "한빛택배가 보냈어요", found: "확인할 방법이 없어요", status: "unknown", status_label: "모름" },
        ],
        risks: [],
        risks_note: null,
        redirect_chain: [
          { url: "https://hanbit.example/track/12345", host: "hanbit.example", registrable_domain: "hanbit.example", status: 200, blocked: false, error: null, at: null },
        ],
        partial_findings: [],
        incomplete_reason: null,
        more_urls: [],
        agent: agentBase,
      };
    case "partner":
      return {
        job_id: jobId,
        mode: "live",
        input_kind: "message",
        verdict: "safe",
        verdict_label: "안전해요 · 협력 회사",
        claimed_entity: { id: "hanbit", name: "한빛택배", source: "exact" },
        stated_purpose: "payment",
        stated_purpose_label: "결제 안내",
        url: "https://pay-partner.example/checkout",
        actual_registrable_domain: "pay-partner.example",
        url_parts: {
          url: "https://pay-partner.example/checkout",
          scheme: "https",
          subdomain_part: "",
          registrable_domain: "pay-partner.example",
          path: "/checkout",
          official_domain: "hanbit.example",
          matches_official: false,
          matches_partner: true,
          partner_domain: "pay-partner.example",
        },
        signals: [
          { type: "partner_match", strength: "positive", data: {} },
          { type: "credential_form", strength: "mid", data: {} },
        ],
        explanation: {
          headline: "한빛택배가 함께 쓰는 결제 사이트예요.",
          warning: null,
          detail: "주소는 한빛택배와 다르지만, 한빛택배가 공식으로 쓰는 결제 회사예요. 주소가 다르다는 것만으로 가짜는 아니에요.",
          confirmed_facts: [
            "진짜 사이트 이름은 pay-partner.example이에요.",
            "한빛택배 공식 홈페이지에 협력 회사로 적혀 있어요.",
            "결제에 필요한 것만 적으라고 해요.",
          ],
          suspicion_evidence: [],
          unverified: [NO_SENDER, "결제 금액이 맞는지"],
          recommended_action: "결제하기 전에 금액과 회사 이름을 한 번 더 보세요.",
          action_bullets: ["받을 택배가 없다면 결제하지 마세요.", "한빛택배 앱에서 결제해도 돼요."],
          source: "template",
        },
        comparison: [
          { key: "address", label: "주소", said: "한빛택배 결제 페이지예요", found: "한빛택배의 공식 결제 회사예요", status: "ok", status_label: "맞아요" },
          { key: "fields", label: "적는 칸", said: "착불 요금 결제", found: "카드 번호, 유효기간, 이름", status: "ok", status_label: "결제에 필요" },
          { key: "destination", label: "적은 내용", said: "—", found: "같은 결제 회사로 보내져요", status: "ok", status_label: "괜찮아요" },
          { key: "sender", label: "보낸 번호", said: "한빛택배가 보냈어요", found: "확인할 방법이 없어요", status: "unknown", status_label: "모름" },
        ],
        risks: [],
        risks_note: null,
        redirect_chain: [
          { url: "https://pay-partner.example/checkout", host: "pay-partner.example", registrable_domain: "pay-partner.example", status: 200, blocked: false, error: null, at: null },
        ],
        partial_findings: [],
        incomplete_reason: null,
        more_urls: [],
        agent: agentBase,
      };
    case "caution":
      return {
        job_id: jobId,
        mode: "live",
        input_kind: "message",
        verdict: "caution",
        verdict_label: "조심하세요",
        claimed_entity: null,
        stated_purpose: "account_security",
        stated_purpose_label: "회원 정보 확인",
        url: "https://member-check.test/login",
        actual_registrable_domain: "member-check.test",
        url_parts: {
          url: "https://member-check.test/login",
          scheme: "https",
          subdomain_part: "",
          registrable_domain: "member-check.test",
          path: "/login",
          official_domain: null,
          matches_official: null,
          matches_partner: false,
          partner_domain: null,
        },
        signals: [
          { type: "entity_not_in_kb", strength: "info", data: { name: "별빛마켓" } },
          { type: "credential_form", strength: "mid", data: {} },
          { type: "cross_domain_form", strength: "mid", data: { action_host: "data-send.test" } },
        ],
        explanation: {
          headline: "어느 회사인지 알 수 없지만, 위험한 점이 있어요.",
          warning: null,
          detail: "\"별빛마켓\"의 진짜 주소는 저희 목록에 없어요. 그런데 비밀번호를 적게 하고, 그 내용을 다른 사이트로 보내요.",
          confirmed_facts: ["진짜 사이트 이름은 member-check.test예요.", "비밀번호와 인증번호를 적는 칸이 있어요."],
          suspicion_evidence: ["적은 비밀번호가 이 페이지와 다른 사이트로 가요.", "휴대폰 인증번호는 남에게 알려주면 안 돼요."],
          unverified: ["별빛마켓의 진짜 주소", NO_SENDER],
          recommended_action: "링크 대신, 별빛마켓 앱이나 대표 전화번호로 직접 물어보세요.",
          action_bullets: ["문자 속 전화번호로 전화하지 마세요.", "비밀번호, 인증번호는 적지 마세요."],
          source: "template",
        },
        comparison: [
          { key: "address", label: "주소", said: "별빛마켓 회원 확인이에요", found: "진짜 주소를 몰라 비교 못 함", status: "unknown", status_label: "모름" },
          { key: "fields", label: "적는 칸", said: "회원 정보 확인", found: "아이디, 비밀번호, 인증번호", status: "warn", status_label: "조심" },
          { key: "destination", label: "적은 내용", said: "—", found: "다른 사이트(data-send.test)로 보내져요", status: "warn", status_label: "조심" },
          { key: "sender", label: "보낸 번호", said: "별빛마켓이 보냈어요", found: "확인할 방법이 없어요", status: "unknown", status_label: "모름" },
        ],
        risks: [
          { label: "비밀번호 적는 칸", level: "mid", level_label: "조금 위험" },
          { label: "다른 사이트로 보냄", level: "mid", level_label: "조금 위험" },
          { label: "목록에 없는 회사", level: "info", level_label: "참고" },
        ],
        risks_note: "회사를 알 수 없어서 \"가짜\"라고 단정하지 않았어요.",
        redirect_chain: [
          { url: "https://member-check.test/login", host: "member-check.test", registrable_domain: "member-check.test", status: 200, blocked: false, error: null, at: null },
        ],
        partial_findings: [],
        incomplete_reason: null,
        more_urls: [],
        agent: agentBase,
      };
    case "unknown":
      return {
        job_id: jobId,
        mode: "live",
        input_kind: "message",
        verdict: "unknown",
        verdict_label: "알 수 없어요",
        claimed_entity: { id: "hanbit", name: "한빛택배", source: "exact" },
        stated_purpose: "delivery",
        stated_purpose_label: "택배 안내",
        url: "https://hanblt.example/login",
        actual_registrable_domain: "hanblt.example",
        url_parts: {
          url: "https://hanblt.example/login",
          scheme: "https",
          subdomain_part: "",
          registrable_domain: "hanblt.example",
          path: "/login",
          official_domain: "hanbit.example",
          matches_official: false,
          matches_partner: false,
          partner_domain: null,
        },
        signals: [{ type: "lookalike_domain", strength: "strong", data: { similarity: 0.83 } }],
        explanation: {
          headline: "지금은 확인을 끝내지 못했어요.",
          warning: "안전하다는 뜻이 아니니 아직 링크를 누르지 마세요.",
          detail: "AI가 너무 바빠서 조사가 멈췄어요.",
          confirmed_facts: [],
          suspicion_evidence: [],
          unverified: ["페이지 속 내용", NO_SENDER],
          recommended_action: "1~2분 뒤에 다시 확인해 보세요.",
          action_bullets: ["그 전까지 링크를 누르지 마세요.", "급하다면 한빛택배 앱에서 직접 확인하세요."],
          source: "template",
        },
        comparison: [],
        risks: [],
        risks_note: null,
        redirect_chain: [],
        partial_findings: [
          "진짜 주소 hanbit.example과 한 글자(i → l)만 다른 hanblt.example이에요. 가짜 사이트가 자주 쓰는 방법이에요. 페이지 안을 보지 못해서 최종 결과는 내리지 않았어요.",
        ],
        incomplete_reason: "AI가 너무 바빠서 조사가 멈췄어요.",
        more_urls: [],
        agent: { ...agentBase, duration_ms: null },
      };
  }
}

function trace(s: Scenario, jobId: string): Trace {
  const r = result(s, jobId);
  const base = { job_id: jobId, verdict: r.verdict, verdict_label: r.verdict_label };
  const address = {
    url: r.url,
    scheme: "https",
    host_unicode: (r.url_parts?.subdomain_part ?? "") + (r.url_parts?.registrable_domain ?? ""),
    host_ascii: (r.url_parts?.subdomain_part ?? "") + (r.url_parts?.registrable_domain ?? ""),
    subdomain_part: r.url_parts?.subdomain_part ?? "",
    registrable_domain: r.url_parts?.registrable_domain ?? "",
    path: r.url_parts?.path ?? "/",
    tricks: [
      {
        key: "subdomain_disguise" as const,
        question: "진짜 주소를 앞에 끼워 넣었나요?",
        hint: "hanbit.example처럼 진짜 주소를 앞에 붙이는 방법",
        hit: s === "suspected",
        answer: s === "suspected" ? "예" : "아니오",
        detail: s === "suspected" ? "hanbit.example을 앞에 붙였어요" : null,
      },
      {
        key: "lookalike" as const,
        question: "진짜 주소와 한두 글자만 다른가요?",
        hint: "예: hanbit → hanblt",
        hit: s === "unknown",
        answer: s === "unknown" ? "예" : "아니오",
        detail: s === "unknown" ? "한 글자(i → l)만 달라요" : null,
      },
      { key: "confusable" as const, question: "헷갈리는 글자를 섞었나요?", hint: "예: 영어 o 대신 숫자 0, 모양이 같은 외국 글자", hit: false, answer: "아니오", detail: null },
      { key: "ip_host" as const, question: "이름 없이 숫자로만 된 주소인가요?", hint: "예: 123.45.67.89", hit: false, answer: "아니오", detail: null },
      { key: "userinfo" as const, question: "주소 중간에 @ 표시가 있나요?", hint: "@ 앞의 글자는 무시되고 뒤쪽으로 가요", hit: false, answer: "아니오", detail: null },
    ],
    similarity: [
      { entity_id: "hanbit", name: "한빛택배", domain: "hanbit.example", similarity: s === "unknown" ? 0.93 : s === "suspected" ? 0.32 : s === "caution" ? 0.21 : 1, label: s === "unknown" ? "많이 닮음" : s === "suspected" ? "조금 닮음" : s === "caution" ? "거의 안 닮음" : "같은 주소", note: s === "unknown" ? "한 글자(i → l)만 달라요" : null },
      { entity_id: "haneul", name: "하늘은행", domain: "haneul.example", similarity: 0.21, label: "거의 안 닮음", note: null },
    ],
    summary_sentence:
      s === "suspected"
        ? "쉽게 말해, \"한빛택배 옆집\"이라고 문패를 단 다른 사람의 집과 같아요. 문패에 한빛택배라고 써 있어도 집주인은 account-check.test예요."
        : s === "unknown"
          ? "진짜 주소와 한 글자만 다른, 철자를 비슷하게 만든 주소예요."
          : "주소의 주인 이름이 그대로 보여요.",
    kb_note: "각 회사 공식 홈페이지에서 직접 확인한 주소만 모아 두었어요. 목록에 없는 회사는 \"알 수 없어요\"로 알려드려요.",
    dev: { registrable_domain: r.actual_registrable_domain, closest_official: "hanbit.example" },
  };
  const redirects = {
    chain: r.redirect_chain,
    redirect_count: Math.max(0, r.redirect_chain.length - 1),
    blocked_count: r.redirect_chain.filter((h) => h.blocked).length,
    last_seen_domain: r.redirect_chain.filter((h) => !h.blocked).slice(-1)[0]?.registrable_domain ?? null,
    blocked_hosts: r.redirect_chain.filter((h) => h.blocked).map((h) => h.host),
    dev: { statuses: r.redirect_chain.map((h) => h.status) },
  };
  const page =
    s === "unknown"
      ? { available: false, title: null, brand_candidates: [], brand_sentence: null, stated_purpose_label: null, expected_fields_label: null, field_rows: [], sends_to: null, sends_cross_domain: false, sends_sentence: null, apk_links: [], js_redirect_hint: false, trust_claims: [], dev: {} }
      : s === "suspected"
        ? {
            available: true,
            title: "한빛택배 | 배송지 확인",
            brand_candidates: ["한빛택배 HANBIT"],
            brand_sentence: "페이지는 자기가 한빛택배라고 말하지만, 앞에서 본 것처럼 주소의 주인은 한빛택배가 아니에요.",
            stated_purpose_label: "택배 안내",
            expected_fields_label: "이름 · 전화번호 · 받을 주소",
            field_rows: [
              { type: "card_number", label: "카드 번호", verdict: "not_needed" as const, verdict_label: "필요 없음" },
              { type: "card_cvc", label: "카드 뒷면 숫자 3자리", verdict: "not_needed" as const, verdict_label: "필요 없음" },
              { type: "card_expiry", label: "카드 유효기간", verdict: "not_needed" as const, verdict_label: "필요 없음" },
              { type: "name", label: "이름", verdict: "ok" as const, verdict_label: "괜찮음" },
            ],
            sends_to: "collect-pay.test",
            sends_cross_domain: true,
            sends_sentence: "이 페이지와 다른 사이트로 보내져요. 적는 순간 모르는 사람에게 가요.",
            apk_links: [],
            js_redirect_hint: false,
            trust_claims: ["본 페이지는 한빛택배 공식 인증 페이지입니다."],
            dev: { field_types: ["card_number", "card_cvc", "card_expiry", "name"], form_action_host: "collect-pay.test" },
          }
        : {
            available: true,
            title: s === "safe" ? "한빛택배 | 배송 조회" : s === "partner" ? "착불 요금 결제 | 페이파트너" : "별빛마켓 | 회원 확인",
            brand_candidates: [],
            brand_sentence: null,
            stated_purpose_label: r.stated_purpose_label,
            expected_fields_label: s === "safe" ? "적는 칸 없음" : s === "partner" ? "카드 번호 · 유효기간 · 이름" : "알 수 없음",
            field_rows:
              s === "safe"
                ? []
                : s === "partner"
                  ? [
                      { type: "card_number", label: "카드 번호", verdict: "needed" as const, verdict_label: "결제에 필요" },
                      { type: "card_expiry", label: "카드 유효기간", verdict: "needed" as const, verdict_label: "결제에 필요" },
                      { type: "name", label: "이름", verdict: "ok" as const, verdict_label: "괜찮음" },
                    ]
                  : [
                      { type: "password", label: "비밀번호", verdict: "not_needed" as const, verdict_label: "조심" },
                      { type: "otp", label: "휴대폰 인증번호", verdict: "not_needed" as const, verdict_label: "조심" },
                    ],
            sends_to: s === "caution" ? "data-send.test" : null,
            sends_cross_domain: s === "caution",
            sends_sentence: s === "caution" ? "이 페이지와 다른 사이트로 보내져요." : null,
            apk_links: [],
            js_redirect_hint: false,
            trust_claims: [],
            dev: {},
          };
  const agent = {
    steps: [
      { t_sec: 0, title: "문자를 읽었어요", detail: "붙여 넣은 문자와, 비교할 회사 후보 목록을 받았어요.", lines: [] },
      { t_sec: 3, title: "누가 보낸 척하는지 골랐어요", detail: r.claimed_entity ? `회사: ${r.claimed_entity.name} · 목적: ${r.stated_purpose_label ?? "-"}` : "회사: 목록에 없음", lines: ["이유: 문자 맨 앞에 회사 이름이 적혀 있어요."] },
      { t_sec: 5, title: "정해진 확인 도구를 차례로 돌렸어요", detail: null, lines: ["✓ 주소 조각내기", "✓ 진짜 주소와 닮았는지 비교", "✓ 안전 공간에서 열어보기", "✓ 페이지 속 적는 칸 살펴보기"] },
      { t_sec: 31, title: "결과를 쉬운 말로 설명했어요", detail: "쓴 설명에 확인하지 않은 내용이 섞이지 않았는지 한 번 더 검사했어요.", lines: [] },
    ],
    unexpected_count: 0,
    unexpected_tools: [],
    duration_ms: 41000,
    duration_sec: 41,
    model_reported: "NVIDIA Nemotron",
    explain_check: "passed" as const,
    dev_log: ["00:01  read input.json", "00:03  exec record_claim.py", "00:05  exec run_checks.py", `session ${jobId}-inv · 14,210ms`],
    dev: {},
  };
  const sandbox = {
    opened_host: r.url_parts ? r.url_parts.subdomain_part + r.url_parts.registrable_domain : null,
    blocked_hosts: redirects.blocked_hosts,
    events: [
      { at: "14:31:52", kind: "open" as const, title: "문을 열었어요", detail: "조사할 링크 한 곳만" },
      ...(redirects.blocked_hosts.length
        ? [{ at: "14:31:58", kind: "blocked" as const, title: "다른 곳 들어가기를 막았어요", detail: redirects.blocked_hosts[0] }]
        : []),
      { at: "14:32:18", kind: "close" as const, title: "문을 다시 닫았어요", detail: "열어 둔 시간 26초 · 남은 열린 문 없음" },
    ],
    open_seconds: 26,
    remaining_open: 0,
    allowed: ["조사할 링크 한 곳 들어가기", "페이지를 보기만 하기", "정해진 확인 도구만 쓰기"],
    denied: ["다른 사이트 들어가기", "정보를 적어서 보내기", "프로그램·앱 설치하기", "페이지 속 프로그램 실행하기"],
    dev: { policy: `job-${jobId}`, methods: ["GET"], ports: [443, 80], binaries: ["python3"] },
  };
  return { ...base, address, redirects, page, agent, sandbox };
}

// ── 진행 순서(약 11초) ──
const TITLE: Record<string, string> = {
  claim: "누가 보낸 척하는지",
  address: "주소 살펴보기",
  sandbox: "안전 공간에서 열어보기",
  page: "페이지 속 내용",
  summary: "결과 정리",
};

function steps(s: Scenario, t: number): StepState[] {
  // 각 단계의 [시작, 끝] (초)
  const win: Record<string, [number, number]> =
    s === "unknown"
      ? { claim: [0, 2], address: [2, 4], sandbox: [4, 8], page: [8, 9], summary: [8, 9] }
      : { claim: [0, 2], address: [2, 4], sandbox: [4, 7], page: [7, 9], summary: [9, 11] };
  const details: Record<string, string> = {
    claim: "한빛택배가 보낸 척하는 택배 안내 문자예요",
    address: `진짜 사이트 이름은 ${result(s, "x").actual_registrable_domain}예요`,
    sandbox: s === "suspected" ? "다른 사이트로 넘어가려고 해서 막았어요" : "링크 한 곳을 열어봤어요",
    page: "무엇을 적으라고 하는지 봐요",
    summary: "쉽게 설명을 써요",
  };
  return (["claim", "address", "sandbox", "page", "summary"] as const).map((key) => {
    const [a, b] = win[key];
    let status: StepState["status"] = t >= b ? "done" : t >= a ? "running" : "waiting";
    if (s === "unknown" && key === "sandbox" && t >= b) status = "stopped";
    if (s === "unknown" && (key === "page" || key === "summary") && t >= b) status = "waiting";
    const detail =
      status === "waiting" && key !== "page" && key !== "summary"
        ? null
        : status === "stopped"
          ? "1분 안에 답이 오지 않아 멈췄어요"
          : details[key];
    return { key, title: TITLE[key], status, detail };
  });
}

const STAGES = ["parse", "kb_lookup", "policy_open", "agent_investigate", "policy_close", "verdict", "explain", "done"];

export function mockJob(id: string, now = Date.now()): JobView | null {
  const m = /^mock_(suspected|safe|partner|caution|unknown|queued)_(\d+)$/.exec(id);
  if (!m) return null;
  const queued = m[1] === "queued";
  const s: Scenario = queued ? "suspected" : (m[1] as Scenario);
  let t = (now - Number(m[2])) / 1000;
  const base = {
    job_id: id,
    stages: STAGES,
    mode: "live" as const,
    url: result(s, id).url,
    more_urls: [] as string[],
    timings_ms: {},
  };
  if (queued && t < 6) {
    return {
      ...base, status: "queued", stage: "queued", steps: steps(s, -1), position: 2,
      elapsed_ms: 0, open_hosts: [], blocked_count: 0, result: null, error: null,
    };
  }
  if (queued) t -= 6;
  const doneAt = s === "unknown" ? 9 : 11;
  const stepList = steps(s, t);
  const sandboxOpen = stepList[2].status === "running";
  if (t >= doneAt) {
    return {
      ...base, status: "done", stage: "done", steps: stepList, position: 0,
      elapsed_ms: doneAt * 1000, open_hosts: [], blocked_count: s === "suspected" ? 1 : 0,
      result: result(s, id), error: null,
    };
  }
  return {
    ...base, status: "running", stage: sandboxOpen ? "agent_investigate" : "kb_lookup", steps: stepList, position: 0,
    elapsed_ms: Math.max(0, Math.round(t * 1000)),
    open_hosts: sandboxOpen ? [result(s, id).url_parts?.subdomain_part + result(s, id).actual_registrable_domain!] : [],
    blocked_count: s === "suspected" && t >= 6 ? 1 : 0,
    result: null, error: null,
  };
}

export function mockTrace(id: string): Trace | null {
  const m = /^mock_(suspected|safe|partner|caution|unknown|queued)_(\d+)$/.exec(id);
  if (!m) return null;
  return trace(m[1] === "queued" ? "suspected" : (m[1] as Scenario), id);
}

export function pickScenario(input: string): Scenario | "queued" {
  if (input.includes("queue-demo")) return "queued";
  if (/hanbit\.example\.account-check/.test(input)) return "suspected";
  if (/pay-partner\.example/.test(input)) return "partner";
  if (/member-check\.test|별빛마켓/.test(input)) return "caution";
  if (/hanblt\.example/.test(input)) return "unknown";
  if (/hanbit\.example/.test(input)) return "safe";
  return "suspected";
}

export const MOCK_CASES: DemoCase[] = [
  {
    "id": "official",
    "label": "진짜 택배 사이트",
    "input": "[한빛택배] 고객님의 택배가 배송 중입니다. 배송 조회: https://hanbit.example/track/12345",
    "expected_verdict": "safe",
    "available_replay": true
  },
  {
    "id": "lookalike",
    "label": "한 글자 바꾼 가짜 주소",
    "input": "[한빛택배] 배송지 확인이 필요합니다. 로그인 후 확인: https://hanblt.example/login",
    "expected_verdict": "suspected_impersonation",
    "available_replay": true
  },
  {
    "id": "disguise",
    "label": "진짜 주소를 앞에 붙인 가짜",
    "input": "[한빛택배] 주소 불일치로 배송 보류. 수정: https://hanbit.example.account-check.test/login",
    "expected_verdict": "suspected_impersonation",
    "available_replay": true
  },
  {
    "id": "clone",
    "label": "화면을 베낀 가짜",
    "input": "[한빛택배] 배송지 오류로 반송 예정입니다. 주소 수정: https://hanbit-parcel.test/address",
    "expected_verdict": "suspected_impersonation",
    "available_replay": true
  },
  {
    "id": "partner",
    "label": "택배사가 쓰는 결제 사이트",
    "input": "[한빛택배] 착불 요금 3,500원 결제 안내: https://pay-partner.example/checkout",
    "expected_verdict": "safe",
    "available_replay": true
  }
];
