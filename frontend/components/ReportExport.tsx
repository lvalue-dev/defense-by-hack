"use client";

import { useState } from "react";
import { Vulnerability } from "@/types/vulnerability";

interface ReportExportProps {
  code: string;
  language: string;
  vulnerabilities: Vulnerability[];
}

export default function ReportExport({ code, language, vulnerabilities }: ReportExportProps) {
  const [isExporting, setIsExporting] = useState(false);

  const exportJSON = () => {
    fetch("/api/py/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, language, vulnerabilities, format: "json" }),
    })
      .then((r) => r.json())
      .then((data) => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `security-report-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      });
  };

  const exportHTML = async () => {
    setIsExporting(true);
    try {
      const response = await fetch("/api/py/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, language, vulnerabilities, format: "html" }),
      });
      const html = await response.text();
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `security-report-${Date.now()}.html`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setIsExporting(false);
    }
  };

  if (vulnerabilities.length === 0) return null;

  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-slate-400">리포트 내보내기:</span>
      <button
        onClick={exportJSON}
        className="text-xs px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded transition-colors flex items-center gap-1.5"
      >
        <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
        </svg>
        JSON
      </button>
      <button
        onClick={exportHTML}
        disabled={isExporting}
        className="text-xs px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 rounded transition-colors flex items-center gap-1.5"
      >
        <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
        </svg>
        {isExporting ? "생성 중..." : "HTML"}
      </button>
    </div>
  );
}
