export type TabKey = "address" | "path" | "page" | "agent" | "sandbox";

export const TABS: { key: TabKey; long: string; short: string }[] = [
  { key: "address", long: "① 주소 살펴보기", short: "① 주소" },
  { key: "path", long: "② 넘어간 길", short: "② 넘어간 길" },
  { key: "page", long: "③ 페이지 속 내용", short: "③ 페이지" },
  { key: "agent", long: "④ AI 조사원이 한 일", short: "④ AI" },
  { key: "sandbox", long: "⑤ 안전 공간 기록", short: "⑤ 안전" },
];

export function parseTab(v: string | undefined): TabKey {
  return TABS.some((t) => t.key === v) ? (v as TabKey) : "address";
}
