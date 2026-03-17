import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Defense by Hack - Vulnerability Analyzer",
  description: "AI-powered web application vulnerability analysis and attack simulation",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ko">
      <body className="bg-slate-950 text-slate-200 min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
