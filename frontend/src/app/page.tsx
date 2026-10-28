"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowsClockwise, BookOpenText, CheckCircle, Database, Lightning, WarningCircle } from "@phosphor-icons/react";
import Button from "@/components/button";
import MitreMatrix from "@/components/mitre-matrix";
import PlaybookBuilder from "@/components/playbook-builder";
import ScoreRing from "@/components/score-ring";
import Stat from "@/components/stat";
import { ErrorState, PageHeader, Skeleton } from "@/components/page-parts";
import {
  fetchAllTechniques, fetchPlaybooks, fetchPreventionStats, fetchStats, fetchTechniqueVerdicts, syncSource,
  type DashboardStats, type PlaybookSummary, type PreventionStats, type Source, type Technique,
} from "@/lib/api";
import { formatDate } from "@/lib/attack";
import { visibilityScore } from "@/lib/status";

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [prevention, setPrevention] = useState<PreventionStats | null>(null);
  const [playbooks, setPlaybooks] = useState<PlaybookSummary[]>([]);
  const [techniques, setTechniques] = useState<Technique[]>([]);
  const [verdicts, setVerdicts] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [partial, setPartial] = useState(false);
  const [syncing, setSyncing] = useState<string | null>(null);
  const [syncMsg, setSyncMsg] = useState<{ id: string; text: string; ok: boolean } | null>(null);
  const [builder, setBuilder] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    // Partial state: only the headline stats are fatal; every other source degrades on its own.
    let failed = false;
    const soft = <T,>(p: Promise<T>, fallback: T) => p.catch(() => { failed = true; return fallback; });
    try {
      const [s, pb, techs, prev, v] = await Promise.all([
        fetchStats(),
        soft(fetchPlaybooks(), { playbooks: [] }),
        soft(fetchAllTechniques(), [] as Technique[]),
        soft(fetchPreventionStats(), null),
        soft(fetchTechniqueVerdicts(), {} as Record<string, string>),
      ]);
      setStats(s); setPlaybooks(pb.playbooks); setTechniques(techs); setPrevention(prev); setVerdicts(v);
      setPartial(failed);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { document.title = "Dashboard · Atomic Prevention"; load(); }, [load]);

  const sync = async (src: Source) => {
    setSyncing(src.id);
    setSyncMsg(null);
    try {
      const r = await syncSource(src.id);
      setSyncMsg({ id: src.id, ok: true, text: `Synced ${r.tests_persisted} tests across ${r.techniques_updated} techniques` });
      await load();
    } catch (e) {
      setSyncMsg({ id: src.id, ok: false, text: e instanceof Error ? e.message : "Sync failed" });
    } finally {
      setSyncing(null);
    }
  };

  const hasRuns = (prevention?.total_runs ?? 0) > 0;
  const score = hasRuns ? Math.round(prevention!.prevention_score) : null;
  const visibility = hasRuns ? visibilityScore(prevention!) : null;

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Atomic prevention testing: not everything needs to be detected."
        actions={<Button variant="primary" icon={Lightning} onClick={() => setBuilder(true)}>Generate playbook</Button>}
      />

      {loading ? (
        <Skeleton rows={3} />
      ) : error || !stats ? (
        <ErrorState message={error || "No data"} onRetry={load} />
      ) : (
        <>
          {partial && (
            <p className="flex items-center gap-2 text-sm text-status-degraded-text" role="status">
              <WarningCircle size={16} aria-hidden /> Some data did not load. Showing what arrived.
            </p>
          )}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-7">
            <Stat label="Techniques" value={stats.techniques.total_techniques} />
            <Stat label="Prevention tests" value={stats.techniques.total_tests} />
            <Stat label="Data sources" value={stats.sources.length} />
            <Stat label="Adversary groups" value={stats.adversaries.total_groups} />
            <Stat label="Detected tests" value={prevention?.total_detected ?? 0} />
            <div className="surface flex items-center gap-4 p-4">
              <ScoreRing score={score} />
              <div>
                <p className="text-label font-medium">Prevention score</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {hasRuns ? `${prevention!.total_blocked} blocked of ${prevention!.total_blocked + prevention!.total_allowed} tests` : "Run a playbook to see results"}
                </p>
              </div>
            </div>
            <div className="surface flex items-center gap-4 p-4">
              <ScoreRing score={visibility} />
              <div>
                <p className="text-label font-medium">Visibility score</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {hasRuns
                    ? `${(prevention!.total_blocked ?? 0) + (prevention!.total_detected ?? 0)} blocked or detected of ${(prevention!.total_blocked ?? 0) + (prevention!.total_detected ?? 0) + prevention!.total_allowed} tests`
                    : "Run a playbook to see results"}
                </p>
              </div>
            </div>
          </div>

          {techniques.length > 0 && <MitreMatrix techniques={techniques} verdicts={verdicts} />}

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <section className="surface overflow-hidden" aria-labelledby="pb-h">
              <div className="flex items-center justify-between border-b border-border p-4">
                <h2 id="pb-h" className="text-lg font-semibold">Recent playbooks</h2>
                <Link href="/playbooks" className="text-label font-medium text-primary-accent hover:underline">View all</Link>
              </div>
              {playbooks.length === 0 ? (
                <p className="p-6 text-sm text-muted-foreground">No playbooks yet. Generate one to get started.</p>
              ) : (
                <ul className="divide-y divide-border">
                  {playbooks.slice(0, 5).map((p) => (
                    <li key={p.id}>
                      <Link href={`/results?playbook=${p.id}`} className="flex items-center gap-3 p-4 hover:bg-muted">
                        <BookOpenText size={16} className="shrink-0 text-muted-foreground" aria-hidden />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-sm font-medium">{p.name}</span>
                          <span className="block text-xs text-muted-foreground">{p.adversary_group_name || "Custom"} · {p.test_count} tests</span>
                        </span>
                        <span className="text-xs tabular-nums text-muted-foreground">{formatDate(p.created_at)}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section className="surface overflow-hidden" aria-labelledby="src-h">
              <div className="border-b border-border p-4"><h2 id="src-h" className="text-lg font-semibold">Data sources</h2></div>
              {stats.sources.length === 0 ? (
                <p className="p-6 text-sm text-muted-foreground">No sources configured.</p>
              ) : (
                <ul className="divide-y divide-border">
                  {stats.sources.map((s) => (
                    <li key={s.id} className="p-4">
                      <div className="flex items-center gap-3">
                        <Database size={16} className="shrink-0 text-muted-foreground" aria-hidden />
                        <span className="min-w-0 flex-1">
                          <span className="block text-sm font-medium">{s.name}</span>
                          <span className="block text-xs text-muted-foreground">{s.test_count} tests · {s.platform}</span>
                        </span>
                        <Button size="sm" icon={ArrowsClockwise} loading={syncing === s.id} onClick={() => sync(s)}>Sync</Button>
                      </div>
                      {syncMsg?.id === s.id && (
                        <p role="status" className={`mt-2 flex items-center gap-1.5 text-xs ${syncMsg.ok ? "text-status-ok-text" : "text-status-error-text"}`}>
                          {syncMsg.ok ? <CheckCircle size={14} aria-hidden /> : <WarningCircle size={14} aria-hidden />}
                          {syncMsg.text}
                        </p>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </>
      )}

      <PlaybookBuilder open={builder} onClose={() => setBuilder(false)} onCreated={load} />
    </>
  );
}
