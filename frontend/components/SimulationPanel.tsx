"use client";

import { useState, useEffect } from "react";
import { Vulnerability, Simulation } from "@/types/vulnerability";

interface SimulationPanelProps {
  vulnerability: Vulnerability | null;
}

type SimTab = "attack" | "steps" | "impact" | "prevention";

export default function SimulationPanel({ vulnerability }: SimulationPanelProps) {
  const [simulation, setSimulation] = useState<Simulation | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<SimTab>("attack");
  const [activeStep, setActiveStep] = useState(0);

  useEffect(() => {
    if (!vulnerability) {
      setSimulation(null);
      setError(null);
      return;
    }

    setIsLoading(true);
    setSimulation(null);
    setError(null);
    setActiveStep(0);
    setActiveTab("attack");

    fetch("/api/py/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        vulnerability_type: vulnerability.type,
        vulnerability_title: vulnerability.title,
        code_snippet: vulnerability.code_snippet,
        description: vulnerability.description,
      }),
    })
      .then((r) => {
        if (!r.ok) throw new Error(`Server error: ${r.status}`);
        return r.json();
      })
      .then((data) => setSimulation(data))
      .catch((e) => setError(e.message))
      .finally(() => setIsLoading(false));
  }, [vulnerability]);

  if (!vulnerability) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 text-center px-6">
        <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center">
          <svg xmlns="http://www.w3.org/2000/svg" className="w-8 h-8 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        </div>
        <div>
          <p className="text-slate-300 font-medium">시뮬레이션 대상 선택</p>
          <p className="text-slate-500 text-sm mt-1">취약점 목록에서 항목을 선택하면 공격 시뮬레이션을 확인할 수 있습니다</p>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <div className="w-8 h-8 border-2 border-orange-600/30 border-t-orange-400 rounded-full animate-spin" />
        <p className="text-slate-400 text-sm">공격 시뮬레이션을 생성하고 있습니다...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 px-6">
        <p className="text-red-400 font-medium">시뮬레이션 오류</p>
        <p className="text-slate-400 text-sm">{error}</p>
      </div>
    );
  }

  if (!simulation) return null;

  const TABS: { id: SimTab; label: string }[] = [
    { id: "attack", label: "공격 벡터" },
    { id: "steps", label: "단계별 시뮬레이션" },
    { id: "impact", label: "영향 분석" },
    { id: "prevention", label: "방어 방법" },
  ];

  return (
    <div className="flex flex-col h-full">
      {/* Warning Banner */}
      <div className="px-4 py-2 bg-orange-950/30 border-b border-orange-800/30 flex-shrink-0">
        <p className="text-xs text-orange-400 flex items-center gap-2">
          <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          교육 목적 시뮬레이션 — 실제 시스템 공격에 사용하지 마세요
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-700 flex-shrink-0">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-xs font-medium transition-colors ${
              activeTab === tab.id
                ? "text-orange-400 border-b-2 border-orange-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {activeTab === "attack" && (
          <div className="space-y-4">
            <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
              <h3 className="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-2">공격 벡터</h3>
              <p className="text-sm text-slate-300">{simulation.attack_vector}</p>
            </div>
            {simulation.prerequisites.length > 0 && (
              <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">사전 조건</h3>
                <ul className="space-y-1">
                  {simulation.prerequisites.map((p, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                      <span className="text-orange-400 mt-0.5">•</span>
                      {p}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {simulation.real_world_example && (
              <div className="bg-amber-950/20 border border-amber-800/30 rounded-lg p-4">
                <h3 className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-2">실제 사례</h3>
                <p className="text-sm text-slate-300">{simulation.real_world_example}</p>
              </div>
            )}
          </div>
        )}

        {activeTab === "steps" && (
          <div className="space-y-4">
            {/* Step selector */}
            <div className="flex gap-2 flex-wrap">
              {simulation.steps.map((s, i) => (
                <button
                  key={i}
                  onClick={() => setActiveStep(i)}
                  className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                    activeStep === i
                      ? "bg-orange-600 text-white"
                      : "bg-slate-700 text-slate-300 hover:bg-slate-600"
                  }`}
                >
                  Step {s.step}
                </button>
              ))}
            </div>

            {simulation.steps[activeStep] && (() => {
              const step = simulation.steps[activeStep];
              return (
                <div className="space-y-3 animate-slide-in">
                  <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                    <h3 className="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-2">
                      Step {step.step}: 공격자 행동
                    </h3>
                    <p className="text-sm text-slate-300">{step.action}</p>
                  </div>
                  {step.payload && (
                    <div className="bg-red-950/20 border border-red-800/30 rounded-lg p-4">
                      <h3 className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2">페이로드</h3>
                      <pre className="text-xs text-red-300 font-mono whitespace-pre-wrap">{step.payload}</pre>
                    </div>
                  )}
                  <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">결과</h3>
                    <p className="text-sm text-slate-300">{step.result}</p>
                  </div>
                  <div className="flex gap-2 justify-end">
                    <button
                      onClick={() => setActiveStep(Math.max(0, activeStep - 1))}
                      disabled={activeStep === 0}
                      className="px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 disabled:opacity-40 rounded transition-colors"
                    >
                      이전
                    </button>
                    <button
                      onClick={() => setActiveStep(Math.min(simulation.steps.length - 1, activeStep + 1))}
                      disabled={activeStep === simulation.steps.length - 1}
                      className="px-3 py-1 text-xs bg-orange-700 hover:bg-orange-600 disabled:opacity-40 rounded transition-colors"
                    >
                      다음 단계
                    </button>
                  </div>
                </div>
              );
            })()}
          </div>
        )}

        {activeTab === "impact" && (
          <div className="space-y-4">
            <div className="bg-red-950/20 border border-red-800/30 rounded-lg p-4">
              <h3 className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2">공격 영향</h3>
              <p className="text-sm text-slate-300">{simulation.impact}</p>
            </div>
            {simulation.detection_methods.length > 0 && (
              <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">탐지 방법</h3>
                <ul className="space-y-2">
                  {simulation.detection_methods.map((m, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                      </svg>
                      {m}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {activeTab === "prevention" && (
          <div className="bg-green-950/20 border border-green-800/30 rounded-lg p-4">
            <h3 className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-3">방어 방법</h3>
            <ul className="space-y-3">
              {simulation.prevention_tips.map((tip, i) => (
                <li key={i} className="flex items-start gap-3">
                  <div className="w-5 h-5 rounded-full bg-green-700/50 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <span className="text-xs text-green-300 font-bold">{i + 1}</span>
                  </div>
                  <p className="text-sm text-slate-300">{tip}</p>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
