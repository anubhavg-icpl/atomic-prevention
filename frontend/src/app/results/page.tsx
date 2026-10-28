"use client";

import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ArrowLeft, CaretRight, ChartBar, UploadSimple } from "@phosphor-icons/react";
import Button from "@/components/button";
import ResultDashboard from "@/components/result-dashboard";
import ScoreRing from "@/components/score-ring";
import { Empty, ErrorState, PageHeader, Skeleton } from "@/components/page-parts";
import { fetchPlaybookRuns, fetchPlaybooks, uploadResultsFile, type PlaybookRunSummary, type PlaybookSummary } from "@/lib/api";
import { formatDate } from "@/lib/attack";
import { preventionScore } from "@/lib/status";

function ResultsInner() {
  const params = useSearchParams();
  const [playbooks, setPlaybooks] = useState<PlaybookSummary[]>([]);
  const [selected, setSelected] = useState(params.get("playbook") || "");
  const [runs, setRuns] = useState<PlaybookRunSummary[]>([]);
  const [runId, setRunId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [runsLoading, setRunsLoading] = useState(false);
  const [error, setError] = useState("");
  const [uploading, setUploading] = useState(false);
  const [upload, setUpload] = useState<{ ok: boolean; text: string } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const loadPlaybooks = useCallback(async () => {
    setError("");
    try {
      setPlaybooks((await fetchPlaybooks()).playbooks);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { document.title = "Results · Atomic Prevention"; loadPlaybooks(); }, [loadPlaybooks]);

  useEffect(() => {
    if (!selected) return;
    setRunsLoading(true);
    setRunId(null);
    fetchPlaybookRuns(selected).then((d) => setRuns(d.runs)).catch(() => setRuns([])).finally(() => setRunsLoading(false));
  }, [selected]);

  const onFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setUpload(null);
    try {
      const r = await uploadResultsFile(file);
      setUpload({ ok: true, text: `Uploaded run ${r.run_id.slice(0, 8)}: ${r.summary.blocked} blocked, ${r.summary.allowed} allowed.` });
      await loadPlaybooks();
    } catch (err) {
      setUpload({ ok: false, text: err instanceof Error ? err.message : "Upload failed" });
    } finally {
      setUploading(false);
      e.target.value = "";
    }
  };

  if (runId) {
    return (
      <>
        <Button icon={ArrowLeft} variant="ghost" onClick={() => setRunId(null)}>Back to runs</Button>
        <PageHeader title={`Run ${runId.slice(0, 8)}`} description="Per-test verdicts from one execution of the playbook." />
        <ResultDashboard runId={runId} />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Results"
        description="Prevention scores and verdicts from playbook runs."
        actions={
          <>
            <input ref={fileRef} type="file" accept=".json,application/json" className="sr-only" tabIndex={-1} aria-label="Results file" onChange={onFile} />
            <Button icon={UploadSimple} loading={uploading} onClick={() => fileRef.current?.click()}>Upload results file</Button>
          </>
        }
      />
      {upload && <p role="status" className={`text-sm ${upload.ok ? "text-status-ok-text" : "text-status-error-text"}`}>{upload.text}</p>}

      {error ? (
        <ErrorState message={error} onRetry={loadPlaybooks} />
      ) : loading ? (
        <Skeleton rows={3} />
      ) : (
        <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-3">
          <section className="surface overflow-hidden lg:col-span-1" aria-labelledby="pb-h">
            <div className="border-b border-border p-4"><h2 id="pb-h" className="text-lg font-semibold">Playbooks</h2></div>
            {playbooks.length === 0 ? (
              <p className="p-6 text-sm text-muted-foreground">No playbooks yet.</p>
            ) : (
              <ul className="max-h-[60vh] divide-y divide-border overflow-y-auto">
                {playbooks.map((p) => (
                  <li key={p.id}>
                    <button onClick={() => setSelected(p.id)} aria-pressed={selected === p.id} className={`flex w-full items-center gap-3 p-4 text-left hover:bg-muted ${selected === p.id ? "bg-primary/15" : ""}`}>
                      <span className="min-w-0 flex-1">
                        <span className={`block truncate text-sm ${selected === p.id ? "font-semibold text-primary-accent" : "font-medium"}`}>{p.name}</span>
                        <span className="block text-xs text-muted-foreground">{p.test_count} tests</span>
                      </span>
                      <CaretRight size={16} className="text-muted-foreground" aria-hidden />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <div className="lg:col-span-2">
            {!selected ? (
              <Empty icon={ChartBar} title="Select a playbook" hint="Choose a playbook on the left to see its runs." />
            ) : runsLoading ? (
              <Skeleton rows={3} />
            ) : runs.length === 0 ? (
              <Empty icon={ChartBar} title="No runs for this playbook" hint="Export the playbook, run it with an agent, then upload the results file or let the agent post them." />
            ) : (
              <ul className="space-y-3">
                {runs.map((r) => (
                  <li key={r.id}>
                    <button onClick={() => setRunId(r.id)} className="surface flex w-full items-center gap-4 p-4 text-left hover:bg-muted">
                      <ScoreRing score={preventionScore(r.summary)} size={56} />
                      <span className="min-w-0 flex-1">
                        <span className="block font-mono text-data">Run {r.id.slice(0, 8)}</span>
                        <span className="block text-xs text-muted-foreground">{r.hostname || "Unknown host"} · {formatDate(r.started_at, true)}</span>
                      </span>
                      <span className="text-label tabular-nums text-muted-foreground">
                        {r.summary.blocked} blocked · {r.summary.detected ?? 0} detected · {r.summary.allowed} allowed{r.summary.error > 0 ? ` · ${r.summary.error} errors` : ""}
                      </span>
                      <CaretRight size={16} className="text-muted-foreground" aria-hidden />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export default function ResultsPage() {
  return (
    <Suspense fallback={<Skeleton rows={3} />}>
      <ResultsInner />
    </Suspense>
  );
}
