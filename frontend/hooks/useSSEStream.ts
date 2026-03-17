import { useState, useCallback, useRef } from "react";
import { Vulnerability } from "@/types/vulnerability";

interface SSEState {
  isStreaming: boolean;
  isComplete: boolean;
  error: string | null;
  rawChunks: string;
  vulnerabilities: Vulnerability[];
}

export function useSSEStream() {
  const [state, setState] = useState<SSEState>({
    isStreaming: false,
    isComplete: false,
    error: null,
    rawChunks: "",
    vulnerabilities: [],
  });

  const abortRef = useRef<AbortController | null>(null);

  const startAnalysis = useCallback(async (code: string, language: string) => {
    // Cancel any existing stream
    if (abortRef.current) {
      abortRef.current.abort();
    }

    abortRef.current = new AbortController();

    setState({
      isStreaming: true,
      isComplete: false,
      error: null,
      rawChunks: "",
      vulnerabilities: [],
    });

    try {
      const response = await fetch("/api/py/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, language }),
        signal: abortRef.current.signal,
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) throw new Error("No response body");

      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            const data = line.slice(6).trim();

            if (data === "[DONE]") {
              setState((prev) => ({ ...prev, isStreaming: false, isComplete: true }));
              continue;
            }

            try {
              const parsed = JSON.parse(data);

              if (parsed.type === "chunk") {
                setState((prev) => ({
                  ...prev,
                  rawChunks: prev.rawChunks + parsed.text,
                }));
              } else if (parsed.type === "complete") {
                setState((prev) => ({
                  ...prev,
                  vulnerabilities: parsed.vulnerabilities ?? [],
                  isStreaming: false,
                  isComplete: true,
                }));
              } else if (parsed.type === "error") {
                setState((prev) => ({
                  ...prev,
                  error: parsed.message,
                  isStreaming: false,
                }));
              }
            } catch {
              // Ignore JSON parse errors on incomplete chunks
            }
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") return;
      setState((prev) => ({
        ...prev,
        isStreaming: false,
        error: err instanceof Error ? err.message : "Unknown error",
      }));
    }
  }, []);

  const reset = useCallback(() => {
    if (abortRef.current) abortRef.current.abort();
    setState({
      isStreaming: false,
      isComplete: false,
      error: null,
      rawChunks: "",
      vulnerabilities: [],
    });
  }, []);

  return { ...state, startAnalysis, reset };
}
