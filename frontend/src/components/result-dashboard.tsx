"use client";

// Single run: prevention and detection scores, the full verdict mix, and expandable
// evidence for every command. Evidence is displayed, never executed.
import { Fragment, useCallback, useEffect, useState } from "react";
import { Clock, Desktop, HardDrives } from "@phosphor-icons/react";
import Button from "./button";
import { EvidenceGrid, EvidenceLogs, EvidenceText } from "./evidence-logs";
import { ErrorState, Skeleton } from "./page-parts";
import ScoreRing from "./score-ring";
import Stat from "./stat";
import StatusDot from "./status-dot";
import { fetchRunResults, type RunDetail, type TestVerdict } from "@/lib/api";
import { formatDate } from "@/lib/attack";
import { canonicalVerdict, preventionScore, visibilityScore } from "@/lib/status";

const VERDICT_ORDER: TestVerdict[] = ["blocked", "detected", "allowed", "error"];
const BAR: Record<TestVerdict, string> = {
  blocked: "bg-status-ok",
  detected: "bg-status-info",
  allowed: "bg-status-error",
  error: "bg-status-degraded",
};

export default function ResultDashboard({ runId }: { runId: string }) {
  const [run, setRun] = useState<RunDetail | null>(null);
  const [error, setError] = useState("");
  const [openResult, setOpenResult] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError("");
    setRun(null);
    setOpenResult(null);
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
  const detected = summary.detected ?? 0;
  const all = summary.blocked + detected + summary.allowed + summary.error;

  return (
    <div className="space-y-6">
      <p className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm text-muted-foreground">
        <span className="flex items-center gap-2"><HardDrives size={16} aria-hidden />{run.hostname || "Unknown host"}</span>
        <span className="flex items-center gap-2"><Clock size={16} aria-hidden />{formatDate(run.started_at, true)}</span>
        {(run.platform || run.os_version) && (
          <span className="flex items-center gap-2">
            <Desktop size={16} aria-hidden />
            {[run.platform, run.os_version].filter(Boolean).join(" · ")}
          </span>
        )}
        {(run.agent_name || run.agent_version) && (
          <span>{[run.agent_name, run.agent_version].filter(Boolean).join(" ")}</span>
        )}
      </p>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-6">
        <div className="surface flex items-center gap-3 p-4">
          <ScoreRing score={preventionScore(summary)} size={68} />
          <p className="text-label font-medium">Prevention score</p>
        </div>
        <div className="surface flex items-center gap-3 p-4">
          <ScoreRing score={visibilityScore(summary)} size={68} label="Visibility score" />
          <p className="text-label font-medium">Visibility score</p>
        </div>
        <Stat label="Blocked" value={summary.blocked} />
        <Stat label="Detected" value={detected} sub="Telemetry without prevention" />
        <Stat label="Allowed" value={summary.allowed} sub="Controls did not stop these" />
        <Stat label="Errors" value={summary.error} sub="Could not be judged" />
      </div>

      {all > 0 && (
        <section className="surface p-4" aria-labelledby="mix-h">
          <h2 id="mix-h" className="text-lg font-semibold">Verdict mix</h2>
          <div
            className="mt-3 flex h-3 overflow-hidden rounded-sm bg-muted"
            role="img"
            aria-label={`${summary.blocked} blocked, ${detected} detected, ${summary.allowed} allowed, ${summary.error} errors`}
          >
            {VERDICT_ORDER.map((verdict) => {
              const count = verdict === "detected" ? detected : summary[verdict];
              return count > 0 ? (
                <div key={verdict} className={BAR[verdict]} style={{ width: `${(count / all) * 100}%` }} />
              ) : null;
            })}
          </div>
        </section>
      )}

      {run.performance && Object.keys(run.performance).length > 0 && (
        <section className="surface p-4" aria-labelledby="benchmark-h">
          <h2 id="benchmark-h" className="text-lg font-semibold">Sensor benchmark</h2>
          <p className="mt-1 text-sm text-muted-foreground">Bounded CPU, memory, load, and host memory samples collected while the playbook ran.</p>
          <div className="mt-3">
            <EvidenceLogs title="Benchmark telemetry" logs={[run.performance]} emptyMessage="No benchmark telemetry was captured." />
          </div>
        </section>
      )}

      <section className="surface overflow-hidden" aria-labelledby="tests-h">
        <div className="border-b border-border p-4">
          <h2 id="tests-h" className="text-lg font-semibold">Test results and evidence</h2>
          <p className="mt-1 text-sm text-muted-foreground">Expand a result to inspect the command, output, agent logs, and UEC sensor logs.</p>
        </div>
        {run.results.length === 0 ? (
          <p className="p-6 text-sm text-muted-foreground">This run has no recorded tests.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-card text-label text-muted-foreground">
                <tr className="border-b border-border">
                  <th scope="col" className="px-4 py-2 font-medium">Verdict</th>
                  <th scope="col" className="px-4 py-2 font-medium">Test</th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">Exit code</th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">Duration</th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {run.results.map((result) => {
                  const verdict = canonicalVerdict(result.verdict);
                  const evidenceId = `${result.id}-evidence`;
                  const isOpen = openResult === result.id;
                  const testName = result.test_name || result.test_id;

                  return (
                    <Fragment key={result.id}>
                      <tr className="hover:bg-muted/50">
                        <td className="px-4 py-2.5">
                          <StatusDot tone={verdict.tone} label={verdict.label} token={verdict.token} />
                        </td>
                        <td className="max-w-[40ch] px-4 py-2.5">
                          <span className="block truncate font-medium" title={testName}>{testName}</span>
                          <span className="block truncate text-xs text-muted-foreground" title={result.technique_id || result.test_id}>
                            {[result.technique_id, result.executor].filter(Boolean).join(" · ") || result.test_id}
                          </span>
                          {result.error_message && (
                            <span className="block truncate text-xs text-muted-foreground" title={result.error_message}>
                              {result.error_message}
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2.5 text-right font-mono text-data tabular-nums">{result.exit_code ?? "None"}</td>
                        <td className="px-4 py-2.5 text-right font-mono text-data tabular-nums">{result.execution_time_ms} ms</td>
                        <td className="px-4 py-2.5 text-right">
                          <Button
                            size="sm"
                            aria-expanded={isOpen}
                            aria-controls={evidenceId}
                            onClick={() => setOpenResult(isOpen ? null : result.id)}
                          >
                            {isOpen ? "Hide evidence" : "Show evidence"}
                          </Button>
                        </td>
                      </tr>
                      <tr id={evidenceId} hidden={!isOpen} className="bg-muted/40">
                        <td colSpan={5} className="px-4 py-4">
                          {isOpen && (
                            <EvidenceGrid>
                              <EvidenceText title="Command" value={result.command} emptyMessage="No command was recorded for this test." />
                              <EvidenceText title="Standard output" value={result.stdout} />
                              <EvidenceText title="Standard error" value={result.stderr} />
                              <EvidenceLogs title="Agent logs" logs={result.agent_logs} />
                              <EvidenceLogs title="UEC matches" logs={result.uec_matches} emptyMessage="No authoritative UEC finding matched this test." />
                              <EvidenceLogs title="UEC sensor logs" logs={run.sensor_logs} emptyMessage="No UEC sensor logs were captured for this run." />
                              <EvidenceLogs title="Run debug logs" logs={run.debug_logs} emptyMessage="No debug logs were captured for this run." />
                              <section aria-label="Execution metadata">
                                <h4 className="text-label font-semibold">Execution metadata</h4>
                                <dl className="mt-2 space-y-2 text-sm">
                                  <div className="flex justify-between gap-3">
                                    <dt className="text-muted-foreground">Executed at</dt>
                                    <dd className="text-right">{formatDate(result.executed_at ?? run.started_at, true)}</dd>
                                  </div>
                                  <div className="flex justify-between gap-3">
                                    <dt className="text-muted-foreground">Completed at</dt>
                                    <dd className="text-right">{formatDate(result.completed_at ?? run.completed_at, true)}</dd>
                                  </div>
                                  <div className="flex justify-between gap-3">
                                    <dt className="text-muted-foreground">UEC match</dt>
                                    <dd className="text-right font-mono text-data">{result.uec_match_status ?? "not evaluated"}</dd>
                                  </div>
                                  <div className="flex justify-between gap-3">
                                    <dt className="text-muted-foreground">Result identifier</dt>
                                    <dd className="text-right font-mono text-data">{result.id}</dd>
                                  </div>
                                  <div className="flex justify-between gap-3">
                                    <dt className="text-muted-foreground">Test identifier</dt>
                                    <dd className="text-right font-mono text-data">{result.test_id}</dd>
                                  </div>
                                  {result.source && (
                                    <div className="flex justify-between gap-3">
                                      <dt className="text-muted-foreground">Source</dt>
                                      <dd className="text-right">{result.source}</dd>
                                    </div>
                                  )}
                                </dl>
                              </section>
                            </EvidenceGrid>
                          )}
                        </td>
                      </tr>
                    </Fragment>
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
