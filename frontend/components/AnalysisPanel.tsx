"use client";

import { Vulnerability, SEVERITY_CONFIG, Severity } from "@/types/vulnerability";
import VulnerabilityCard from "./VulnerabilityCard";

interface AnalysisPanelProps {
  isStreaming: boolean;
  isComplete: boolean;
  error: string | null;
  vulnerabilities: Vulnerability[];
  rawChunks: string;
  selectedVuln: Vulnerability | null;
  onSelectVuln: (v: Vulnerability) => void;
}

function SeverityBadge({ severity, count }: { severity: Severity; count: number }) {
  const cfg = SEVERITY_CONFIG[severity];
  if (count === 0) return null;
  return (
    <div className={`flex items-center gap-1.5 px-2 py-1 rounded-md ${cfg.bg}`}>
      <span className={`text-xs font-bold ${cfg.color}`}>{cfg.label}</span>
      <span className={`text-xs font-mono font-semibold ${cfg.color}`}>{count}</span>
    </div>
  );
}

export default function AnalysisPanel({
  isStreaming,
  isComplete,
  error,
  vulnerabilities,
  rawChunks,
  selectedVuln,
  onSelectVuln,
}: AnalysisPanelProps) {
  const severityCounts = (["critical", "high", "medium", "low", "info"] as Severity[]).reduce(
    (acc, s) => ({ ...acc, [s]: vulnerabilities.filter((v) => v.severity === s).length }),
    {} as Record<Severity, number>
  );

  // Empty state
  if (!isStreaming && !isComplete && !error) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 text-center px-6">
        <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center">
          <svg xmlns="http://www.w3.org/2000/svg" className="w-8 h-8 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div>
          <p className="text-slate-300 font-medium">코드를 입력하고 분석을 시작하세요</p>
          <p className="text-slate-500 text-sm mt-1">왼쪽 에디터에서 코드를 붙여넣은 후 &quot;취약점 분석 시작&quot; 버튼을 클릭하세요</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 px-6">
        <div className="w-16 h-16 rounded-full bg-red-950/50 flex items-center justify-center">
          <svg xmlns="http://www.w3.org/2000/svg" className="w-8 h-8 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>
        <div className="text-center">
          <p className="text-red-400 font-medium">분석 오류</p>
          <p className="text-slate-400 text-sm mt-1">{error}</p>
        </div>
      </div>
    );
  }

  // Streaming state - show raw chunks
  if (isStreaming && vulnerabilities.length === 0) {
    return (
      <div className="p-4 h-full flex flex-col gap-4">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span className="text-sm text-cyan-400 font-medium">Claude AI가 코드를 분석하고 있습니다...</span>
        </div>
        <div className="flex-1 bg-slate-900 rounded-lg p-4 overflow-auto">
          <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap">
            {rawChunks || "분석 중..."}
          </pre>
        </div>
      </div>
    );
  }

  // Results
  return (
    <div className="flex flex-col h-full">
      {/* Summary Header */}
      <div className="px-4 py-3 bg-slate-800/50 border-b border-slate-700">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-semibold text-slate-200">
            {isStreaming ? (
              <span className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                분석 중...
              </span>
            ) : (
              `취약점 ${vulnerabilities.length}개 발견`
            )}
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => (
            <SeverityBadge key={s} severity={s} count={severityCounts[s]} />
          ))}
        </div>
      </div>

      {/* Vulnerability List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {vulnerabilities.length === 0 && isComplete ? (
          <div className="text-center py-12 text-slate-500">
            <svg xmlns="http://www.w3.org/2000/svg" className="w-12 h-12 mx-auto mb-3 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="font-medium text-green-400">취약점이 발견되지 않았습니다</p>
            <p className="text-sm mt-1">코드가 보안 검사를 통과했습니다</p>
          </div>
        ) : (
          vulnerabilities.map((v) => (
            <VulnerabilityCard
              key={v.id}
              vulnerability={v}
              isSelected={selectedVuln?.id === v.id}
              onClick={onSelectVuln}
            />
          ))
        )}
      </div>
    </div>
  );
}
