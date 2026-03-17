"use client";

import { useState, useEffect } from "react";
import { Vulnerability, CodeFix } from "@/types/vulnerability";

interface CodeFixPanelProps {
  vulnerability: Vulnerability | null;
  code: string;
}

export default function CodeFixPanel({ vulnerability, code }: CodeFixPanelProps) {
  const [fix, setFix] = useState<CodeFix | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!vulnerability) {
      setFix(null);
      setError(null);
      return;
    }

    setIsLoading(true);
    setFix(null);
    setError(null);

    fetch("/api/py/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        vulnerability_id: vulnerability.id,
        vulnerability_type: vulnerability.type,
        description: vulnerability.description,
        affected_lines: vulnerability.affected_lines,
      }),
    })
      .then((r) => {
        if (!r.ok) throw new Error(`Server error: ${r.status}`);
        return r.json();
      })
      .then((data) => setFix(data))
      .catch((e) => setError(e.message))
      .finally(() => setIsLoading(false));
  }, [vulnerability, code]);

  if (!vulnerability) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 text-center px-6">
        <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center">
          <svg xmlns="http://www.w3.org/2000/svg" className="w-8 h-8 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
          </svg>
        </div>
        <div>
          <p className="text-slate-300 font-medium">취약점을 선택하세요</p>
          <p className="text-slate-500 text-sm mt-1">왼쪽 목록에서 취약점을 클릭하면 코드 수정 방법을 확인할 수 있습니다</p>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <div className="w-8 h-8 border-2 border-cyan-600/30 border-t-cyan-400 rounded-full animate-spin" />
        <p className="text-slate-400 text-sm">수정 방법을 생성하고 있습니다...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 px-6">
        <p className="text-red-400 font-medium">오류가 발생했습니다</p>
        <p className="text-slate-400 text-sm">{error}</p>
      </div>
    );
  }

  if (!fix) return null;

  return (
    <div className="flex flex-col h-full overflow-y-auto">
      {/* Header */}
      <div className="px-4 py-3 bg-slate-800/50 border-b border-slate-700 flex-shrink-0">
        <p className="text-sm font-semibold text-slate-200">{vulnerability.title} — 코드 수정</p>
      </div>

      <div className="flex-1 p-4 space-y-4 overflow-y-auto">
        {/* Explanation */}
        <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
          <h3 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-2">설명</h3>
          <p className="text-sm text-slate-300">{fix.explanation}</p>
        </div>

        {/* Before / After Diff */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-xs font-semibold text-red-400">취약한 코드</span>
            </div>
            <div className="bg-red-950/20 border border-red-800/30 rounded-lg overflow-auto">
              <pre className="text-xs text-slate-300 font-mono p-4 whitespace-pre-wrap">{fix.vulnerable_code}</pre>
            </div>
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-xs font-semibold text-green-400">수정된 코드</span>
            </div>
            <div className="bg-green-950/20 border border-green-800/30 rounded-lg overflow-auto">
              <pre className="text-xs text-slate-300 font-mono p-4 whitespace-pre-wrap">{fix.fixed_code}</pre>
            </div>
          </div>
        </div>

        {/* Additional Notes */}
        {fix.additional_notes && (
          <div className="bg-amber-950/20 border border-amber-800/30 rounded-lg p-4">
            <h3 className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-2">추가 보안 권고사항</h3>
            <p className="text-sm text-slate-300">{fix.additional_notes}</p>
          </div>
        )}
      </div>
    </div>
  );
}
