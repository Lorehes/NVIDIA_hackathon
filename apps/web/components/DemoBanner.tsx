"use client";
import { useEffect, useSyncExternalStore } from "react";
import { getDemo, setDemo, subscribeDemo, syncDemoFromUrl } from "@/lib/demo";

export function DemoBanner() {
  const on = useSyncExternalStore(subscribeDemo, getDemo, () => false);
  useEffect(() => {
    syncDemoFromUrl();
  }, []);
  if (!on) return null;
  return (
    <div className="demo-banner" role="status">
      <span>시연 모드 · 미리 저장해 둔 결과를 보여주고 있어요</span>
      <button
        onClick={() => {
          setDemo(false);
          const u = new URL(window.location.href);
          if (u.searchParams.has("demo")) {
            u.searchParams.delete("demo");
            window.history.replaceState(null, "", u.toString());
          }
        }}
      >
        끄기
      </button>
    </div>
  );
}
