"use client";

interface ScanResult {
  scan_id: string;
  status: string;
  health_score?: {
    overall: number;
    grade: string;
    severity_counts: Record<string, number>;
  };
  finding_count: number;
  error?: string;
}

const gradeColor: Record<string, string> = {
  A: "text-green-400", B: "text-blue-400", C: "text-yellow-400",
  D: "text-orange-400", F: "text-red-400",
};

const sevColor: Record<string, string> = {
  critical: "bg-severity-critical/10 text-severity-critical",
  high: "bg-severity-high/10 text-severity-high",
  medium: "bg-severity-medium/10 text-severity-medium",
  low: "bg-severity-low/10 text-severity-low",
};

export default function ResultsPanel({ result }: { result: ScanResult }) {
  const hs = result.health_score;

  if (result.status === "failed") {
    return (
      <div className="mt-8 p-6 bg-red-500/5 border border-red-500/20 rounded-xl">
        <h2 className="text-lg font-bold text-red-400 mb-2">Scan Failed</h2>
        <p className="text-gray-400 text-sm font-mono">{result.error || "Unknown error"}</p>
      </div>
    );
  }

  return (
    <div className="mt-8 p-6 bg-dark-card border border-dark-border rounded-xl">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold text-white">Audit Results</h2>
        <span className="text-xs text-gray-500 font-mono">{result.scan_id}</span>
      </div>

      {hs && (
        <div className="flex items-center gap-8 mb-6">
          {/* Score gauge */}
          <div className="text-center">
            <div className={`text-5xl font-extrabold ${gradeColor[hs.grade] || "text-white"}`}>
              {hs.overall}
            </div>
            <div className="text-sm text-gray-500 mt-1">Grade {hs.grade}</div>
          </div>

          {/* Severity badges */}
          <div className="flex gap-2 flex-wrap">
            {(["critical", "high", "medium", "low"] as const).map((sev) => {
              const count = hs.severity_counts[sev] || 0;
              if (count === 0) return null;
              return (
                <span
                  key={sev}
                  className={`px-3 py-1 rounded-full text-xs font-mono font-bold ${sevColor[sev]}`}
                >
                  {count} {sev}
                </span>
              );
            })}
          </div>
        </div>
      )}

      <div className="text-sm text-gray-400">
        {result.finding_count} findings detected.
        {result.status === "completed" && (
          <span className="ml-2 text-green-400">Scan complete.</span>
        )}
      </div>
    </div>
  );
}
