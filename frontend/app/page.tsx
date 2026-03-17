"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import { Vulnerability } from "@/types/vulnerability";
import { useSSEStream } from "@/hooks/useSSEStream";
import AnalysisPanel from "@/components/AnalysisPanel";
import CodeFixPanel from "@/components/CodeFixPanel";
import SimulationPanel from "@/components/SimulationPanel";
import ReportExport from "@/components/ReportExport";

// CodeMirror must be loaded client-side only
const CodeEditor = dynamic(() => import("@/components/CodeEditor"), { ssr: false });

type RightTab = "analysis" | "fix" | "simulation";

export default function Home() {
  const [currentCode, setCurrentCode] = useState("");
  const [currentLanguage, setCurrentLanguage] = useState("javascript");
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [rightTab, setRightTab] = useState<RightTab>("analysis");

  const { isStreaming, isComplete, error, rawChunks, vulnerabilities, startAnalysis, reset } =
    useSSEStream();

  const handleAnalyze = (code: string, language: string) => {
    setCurrentCode(code);
    setCurrentLanguage(language);
    setSelectedVuln(null);
    setRightTab("analysis");
    reset();
    startAnalysis(code, language);
  };

  const handleSelectVuln = (v: Vulnerability) => {
    setSelectedVuln(v);
    setRightTab("fix");
  };

  const RIGHT_TABS: { id: RightTab; label: string; icon: React.ReactNode }[] = [
    {
      id: "analysis",
      label: "취약점 분석",
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
    },
    {
      id: "fix",
      label: "코드 수정",
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      ),
    },
    {
      id: "simulation",
      label: "공격 시뮬레이션",
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      ),
    },
  ];

  return (
    <div className="flex flex-col h-screen bg-slate-950">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-3 bg-slate-900 border-b border-slate-800 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-600/20 border border-cyan-600/40 flex items-center justify-center">
            <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-100 leading-none">Defense by Hack</h1>
            <p className="text-xs text-slate-500 leading-none mt-0.5">AI 취약점 분석 &amp; 공격 시뮬레이터</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {isComplete && (
            <ReportExport
              code={currentCode}
              language={currentLanguage}
              vulnerabilities={vulnerabilities}
            />
          )}
          <div className="flex items-center gap-2 text-xs text-slate-500 bg-slate-800 px-3 py-1.5 rounded-full">
            <div className={`w-2 h-2 rounded-full ${isStreaming ? "bg-cyan-400 animate-pulse" : "bg-green-500"}`} />
            {isStreaming ? "분석 중" : "준비됨"}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left Panel: Code Editor */}
        <div className="w-2/5 flex flex-col border-r border-slate-800 bg-slate-900">
          <div className="px-4 py-2 border-b border-slate-800 flex-shrink-0">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">코드 입력</h2>
          </div>
          <div className="flex-1 overflow-hidden">
            <CodeEditor onAnalyze={handleAnalyze} isStreaming={isStreaming} />
          </div>
        </div>

        {/* Right Panel: Tabs */}
        <div className="flex-1 flex flex-col bg-slate-900 overflow-hidden">
          {/* Tab Bar */}
          <div className="flex border-b border-slate-800 flex-shrink-0 bg-slate-900">
            {RIGHT_TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setRightTab(tab.id)}
                className={`flex items-center gap-2 px-5 py-3 text-xs font-medium border-b-2 transition-all ${
                  rightTab === tab.id
                    ? "border-cyan-500 text-cyan-400"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                {tab.icon}
                {tab.label}
                {tab.id === "analysis" && vulnerabilities.length > 0 && (
                  <span className="ml-1 bg-cyan-600 text-white text-xs px-1.5 py-0.5 rounded-full leading-none">
                    {vulnerabilities.length}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <div className="flex-1 overflow-hidden">
            {rightTab === "analysis" && (
              <AnalysisPanel
                isStreaming={isStreaming}
                isComplete={isComplete}
                error={error}
                vulnerabilities={vulnerabilities}
                rawChunks={rawChunks}
                selectedVuln={selectedVuln}
                onSelectVuln={(v) => handleSelectVuln(v)}
              />
            )}
            {rightTab === "fix" && (
              <CodeFixPanel vulnerability={selectedVuln} code={currentCode} />
            )}
            {rightTab === "simulation" && (
              <SimulationPanel vulnerability={selectedVuln} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
