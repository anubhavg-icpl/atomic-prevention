"use client";

// Single run: score, verdict counts, a stacked verdict bar (plain SVG-free divs, token fills),
// and the per-test table. Every verdict is a dot plus word via the one canonical resolver.
import { useCallback, useEffect, useState } from "react";
import { Clock, HardDrives } from "@phosphor-icons/react";
import { fetchRunResults, type RunDetail } from "@/lib/api";
import { formatDate } from "@/lib/attack";
import { canonicalVerdict, preventionScore } from "@/lib/status";
import { ErrorState, Skeleton } from "./page-parts";
import ScoreRing from "./score-ring";
import Stat from "./stat";
import StatusDot from "./status-dot";

const BAR = { ok: "bg-status-ok", error: "bg-status-error", degraded: "bg-status-degraded", idle: "bg-status-idle" };

export default function ResultDashboard({ runId }: { runId: string }) {
  const [run, setRun] = useState<RunDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setError("");
    setRun(null);
    try {
      setRun(await fetchRunResults(runId));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    }
  }, [runId]);

  useEffect(() => { load(); }, [load]);

  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!run) return <Skeleton rows={3} />;

  const { summary } = run;
  const all = summary.blocked + summary.allowed + summary.error;

  return (
    <div className="space-y-6">
      <p className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm text-muted-foreground">
        <span className="flex items-center gap-2"><HardDrives size={16} aria-hidden />{run.hostname || "Unknown host"}</span>
        <span className="flex items-center gap-2"><Clock size={16} aria-hidden />{formatDate(run.started_at, true)}</span>
      </p>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="surface flex items-center gap-4 p-4">
          <ScoreRing score={preventionScore(summary)} size={80} />
          <p className="text-label font-medium">Prevention score</p>
        </div>
        <Stat label="Blocked" value={summary.blocked} />
        <Stat label="Allowed" value={summary.allowed} sub="Controls did not stop these" />
        <Stat label="Errors" value={summary.error} sub="Could not be judged" />
      </div>

      {all > 0 && (
        <section className="surface p-4" aria-labelledby="mix-h">
          <h2 id="mix-h" className="text-lg font-semibold">Verdict mix</h2>
          <div className="mt-3 flex h-3 overflow-hidden rounded-sm bg-muted" role="img" aria-label={`${summary.blocked} blocked, ${summary.allowed} allowed, ${summary.error} errors`}>
            {(["blocked", "allowed", "error"] as const).map((v) => summary[v] > 0 && (
              <div key={v} className={BAR[canonicalVerdict(v).tone]} style={{ width: `${(summary[v] / all) * 100}%` }} />
            ))}
          </div>
        </section>
      )}

      <section className="surface overflow-hidden" aria-labelledby="tests-h">
        <div className="border-b border-border p-4"><h2 id="tests-h" className="text-lg font-semibold">Test results</h2></div>
        {run.results.length === 0 ? (
          <p className="p-6 text-sm text-muted-foreground">This run has no recorded tests.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-card text-label text-muted-foreground">
                <tr className="border-b border-border">
                  <th className="px-4 py-2 font-medium">Verdict</th>
                  <th className="px-4 py-2 font-medium">Test</th>
                  <th className="px-4 py-2 text-right font-medium">Exit code</th>
                  <th className="px-4 py-2 text-right font-medium">Duration</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {run.results.map((r) => {
                  const v = canonicalVerdict(r.verdict);
                  return (
                    <tr key={r.id} className="hover:bg-muted/50">
                      <td className="px-4 py-2.5"><StatusDot tone={v.tone} label={v.label} /></td>
                      <td className="max-w-[40ch] px-4 py-2.5">
                        <span className="block truncate font-mono text-data" title={r.test_id}>{r.test_id}</span>
                        {r.error_message && <span className="block truncate text-xs text-muted-foreground" title={r.error_message}>{r.error_message}</span>}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-data tabular-nums">{r.exit_code ?? "None"}</td>
                      <td className="px-4 py-2.5 text-right font-mono text-data tabular-nums">{r.execution_time_ms} ms</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
