"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ArrowLeft, CaretRight, ClipboardText } from "@phosphor-icons/react";
import Button from "@/components/button";
import { Empty, ErrorState, PageHeader, Skeleton } from "@/components/page-parts";
import QaWorkbench from "@/components/qa-workbench";
import ResultDashboard from "@/components/result-dashboard";
import ScoreRing from "@/components/score-ring";
import StatusDot from "@/components/status-dot";
import {
  fetchIntegrationStatus,
  fetchPlaybookRuns,
  fetchPlaybooks,
  type IntegrationStatus,
  type PlaybookRunSummary,
  type PlaybookSummary,
} from "@/lib/api";
import { formatDate } from "@/lib/attack";
import { preventionScore } from "@/lib/status";

function hostLabel(url: string) {
  try {
    return new URL(url).host;
  } catch {
    return url || "Not configured";
  }
}

function IntegrationPanel({
  integration,
  error,
  onRetry,
}: {
  integration: IntegrationStatus | null;
  error: string;
  onRetry: () => void;
}) {
  return (
    <section className="surface p-4" aria-labelledby="integrations-h">
      <h2 id="integrations-h" className="text-lg font-semibold">Integration status</h2>
      {error ? (
        <div className="mt-3">
          <ErrorState message={error} onRetry={onRetry} />
        </div>
      ) : !integration ? (
        <div className="mt-3"><Skeleton rows={3} /></div>
      ) : (
        <dl className="mt-3 space-y-4">
          <div>
            <dt className="text-label font-medium">Claude</dt>
            <dd className="mt-1 flex flex-wrap items-center gap-2 text-sm">
              <StatusDot tone={integration.claude.configured ? "ok" : "idle"} label={integration.claude.configured ? "Configured" : "Not configured"} />
              <span className="text-muted-foreground">{integration.claude.model}</span>
            </dd>
          </div>
          <div>
            <dt className="text-label font-medium">GitLab</dt>
            <dd className="mt-1 flex flex-wrap items-center gap-2 text-sm">
              <StatusDot tone={integration.gitlab.configured ? "ok" : "idle"} label={integration.gitlab.configured ? "Configured" : "Not configured"} />
              <span className="text-muted-foreground">{hostLabel(integration.gitlab.url)}</span>
            </dd>
          </div>
          <div>
            <dt className="text-label font-medium">Endpoint console</dt>
            <dd className="mt-1 space-y-1 text-sm">
              <span className="flex flex-wrap items-center gap-2">
                <StatusDot tone={integration.uec.configured ? "ok" : "idle"} label={integration.uec.configured ? "Configured" : "Not configured"} />
                <span className="text-muted-foreground">{hostLabel(integration.uec.url)}</span>
              </span>
              <span className="block text-muted-foreground">
                Tenant {integration.uec.tenant || "not set"} · correlation {integration.uec.correlation_enabled ? "on" : "off"}
              </span>
            </dd>
          </div>
        </dl>
      )}
    </section>
  );
}

function runLabel(run: PlaybookRunSummary) {
  const detected = run.summary.detected ?? 0;
  return [
    `${run.summary.blocked} blocked`,
    `${detected} detected`,
    `${run.summary.allowed} allowed`,
    `${run.summary.error} errors`,
  ].join(" · ");
}

function QaPageInner() {
  const params = useSearchParams();
  const requestedPlaybook = params.get("playbook") || "";
  const [playbooks, setPlaybooks] = useState<PlaybookSummary[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState(requestedPlaybook);
  const [runs, setRuns] = useState<PlaybookRunSummary[]>([]);
  const [runsLoading, setRunsLoading] = useState(false);
  const [runId, setRunId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [integration, setIntegration] = useState<IntegrationStatus | null>(null);
  const [integrationError, setIntegrationError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    setIntegrationError("");
    try {
      const playbookResponse = await fetchPlaybooks();
      setPlaybooks(playbookResponse.playbooks);
      setSelectedPlaybook((current) => current || requestedPlaybook || playbookResponse.playbooks[0]?.id || "");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }, [requestedPlaybook]);

  const loadIntegrations = useCallback(async () => {
    setIntegrationError("");
    try {
      setIntegration(await fetchIntegrationStatus());
    } catch (e) {
      setIntegration(null);
      setIntegrationError(e instanceof Error ? e.message : "Request failed");
    }
  }, []);

  useEffect(() => {
    document.title = "Quality automation · Atomic Prevention";
    load();
    loadIntegrations();
  }, [load, loadIntegrations]);

  useEffect(() => {
    if (!selectedPlaybook) {
      setRuns([]);
      return;
    }

    setRunsLoading(true);
    setRunId(null);
    fetchPlaybookRuns(selectedPlaybook)
      .then((response) => setRuns(response.runs))
      .catch(() => setRuns([]))
      .finally(() => setRunsLoading(false));
  }, [selectedPlaybook]);

  if (runId) {
    return (
      <>
        <Button icon={ArrowLeft} variant="ghost" onClick={() => setRunId(null)}>Back to runs</Button>
        <PageHeader
          title="Quality automation"
          description="Validate the run, review evidence, analyze it with AI, and create a GitLab issue."
        />
        <div className="grid grid-cols-1 items-start gap-6 xl:grid-cols-[minmax(0,1fr)_430px]">
          <ResultDashboard runId={runId} />
          <div className="space-y-6">
            <IntegrationPanel integration={integration} error={integrationError} onRetry={loadIntegrations} />
            <QaWorkbench runId={runId} integration={integration} />
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Quality automation"
        description="Choose a playbook run, inspect evidence, then send AI-reviewed findings to GitLab."
      />

      {error ? (
        <ErrorState message={error} onRetry={load} />
      ) : loading ? (
        <Skeleton rows={4} />
      ) : (
        <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-3">
          <section className="surface overflow-hidden" aria-labelledby="qa-playbooks-h">
            <div className="border-b border-border p-4">
              <h2 id="qa-playbooks-h" className="text-lg font-semibold">Playbooks</h2>
            </div>
            {playbooks.length === 0 ? (
              <p className="p-6 text-sm text-muted-foreground">No playbooks yet.</p>
            ) : (
              <ul className="max-h-[60vh] divide-y divide-border overflow-y-auto">
                {playbooks.map((playbook) => (
                  <li key={playbook.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedPlaybook(playbook.id)}
                      aria-pressed={selectedPlaybook === playbook.id}
                      className={`flex w-full items-center gap-3 p-4 text-left hover:bg-muted ${selectedPlaybook === playbook.id ? "bg-primary/15" : ""}`}
                    >
                      <span className="min-w-0 flex-1">
                        <span className={`block truncate text-sm ${selectedPlaybook === playbook.id ? "font-semibold text-primary-accent" : "font-medium"}`}>
                          {playbook.name}
                        </span>
                        <span className="block text-xs text-muted-foreground">{playbook.test_count} tests</span>
                      </span>
                      <CaretRight size={16} className="text-muted-foreground" aria-hidden />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="surface overflow-hidden" aria-labelledby="qa-runs-h">
            <div className="border-b border-border p-4">
              <h2 id="qa-runs-h" className="text-lg font-semibold">Runs</h2>
            </div>
            {!selectedPlaybook ? (
              <p className="p-6 text-sm text-muted-foreground">Select a playbook to load its runs.</p>
            ) : runsLoading ? (
              <div className="p-4"><Skeleton rows={3} /></div>
            ) : runs.length === 0 ? (
              <div className="p-4">
                <Empty icon={ClipboardText} title="No runs for this playbook" hint="Run the playbook with an agent, then return here for analysis." />
              </div>
            ) : (
              <ul className="max-h-[60vh] divide-y divide-border overflow-y-auto">
                {runs.map((run) => (
                  <li key={run.id}>
                    <button
                      type="button"
                      onClick={() => setRunId(run.id)}
                      className="flex w-full items-center gap-4 p-4 text-left hover:bg-muted"
                      aria-label={`Open run ${run.id.slice(0, 8)}, ${runLabel(run)}`}
                    >
                      <ScoreRing score={preventionScore(run.summary)} size={54} />
                      <span className="min-w-0 flex-1">
                        <span className="block font-mono text-data">Run {run.id.slice(0, 8)}</span>
                        <span className="block truncate text-xs text-muted-foreground">
                          {run.hostname || "Unknown host"} · {formatDate(run.started_at, true)}
                        </span>
                        <span className="mt-1 block text-xs tabular-nums text-muted-foreground">{runLabel(run)}</span>
                      </span>
                      <CaretRight size={16} className="text-muted-foreground" aria-hidden />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <IntegrationPanel integration={integration} error={integrationError} onRetry={loadIntegrations} />
        </div>
      )}
    </>
  );
}

export default function QaPage() {
  return (
    <Suspense fallback={<Skeleton rows={4} />}>
      <QaPageInner />
    </Suspense>
  );
}
