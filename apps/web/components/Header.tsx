"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

export function Header() {
  const path = usePathname() ?? "/";
  const [open, setOpen] = useState(false);
  const isHow = path.startsWith("/how");
  const isHome = path === "/";

  useEffect(() => setOpen(false), [path]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open]);

  return (
    <>
      <header className="header">
        <Link href="/" className="brand" aria-label="문자 링크 확인 처음으로">
          <span className="brand-mark" aria-hidden />
          <span>문자 링크 확인</span>
        </Link>
        <nav className="nav" aria-label="주 메뉴">
          {isHome || isHow ? (
            <>
              {isHow && <Link href="/">확인하기</Link>}
              <Link href="/how" aria-current={isHow ? "page" : undefined}>
                이용 방법
              </Link>
            </>
          ) : (
            <Link href="/" className="btn-outline hdr">
              다른 문자 확인하기
            </Link>
          )}
        </nav>
        <button className="hamburger" aria-label="메뉴 열기" aria-expanded={open} onClick={() => setOpen(true)}>
          ☰
        </button>
      </header>
      {open && (
        <div className="menu-overlay" role="dialog" aria-modal="true" aria-label="메뉴">
          <div className="menu-top">
            <span className="brand">
              <span className="brand-mark" aria-hidden />
              문자 링크 확인
            </span>
            <button className="hamburger" style={{ display: "grid" }} aria-label="메뉴 닫기" onClick={() => setOpen(false)}>
              ✕
            </button>
          </div>
          <div className="menu-list">
            <Link href="/">확인하기</Link>
            <Link href="/how">이용 방법</Link>
          </div>
          <div className="menu-emergency">
            <b style={{ fontSize: 17 }}>이미 눌렀다면</b>
            <span className="hint">급할 땐 바로 전화하세요</span>
            <div className="row">
              <span>사기 신고</span>
              <b>112</b>
            </div>
            <div className="row">
              <span>상담</span>
              <b>118</b>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
