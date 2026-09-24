import type { Metadata, Viewport } from "next";
import "./globals.css";
import { Header } from "@/components/Header";
import { DemoBanner } from "@/components/DemoBanner";

export const metadata: Metadata = {
  title: "문자 링크 확인",
  description: "받은 문자의 링크를 누르기 전에, 안전한 곳에서 대신 열어보고 진짜인지 가짜인지 이유와 함께 알려드려요.",
};

export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko">
      <head>
        <link rel="preconnect" href="https://cdn.jsdelivr.net" crossOrigin="" />
        <link
          rel="stylesheet"
          href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css"
        />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap"
        />
      </head>
      <body>
        <Header />
        <DemoBanner />
        <main>{children}</main>
      </body>
    </html>
  );
}
