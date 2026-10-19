"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { BookOpenText, DownloadSimple, Plus, ChartBar } from "@phosphor-icons/react";
import Button, { btn } from "@/components/button";
import PlaybookBuilder from "@/components/playbook-builder";
import { Empty, ErrorState, PageHeader, Skeleton } from "@/components/page-parts";
import { API_BASE, exportPlaybook, fetchPlaybooks, type PlaybookSummary } from "@/lib/api";
import { formatDate } from "@/lib/attack";

export default function PlaybooksPage() {
  const [items, setItems] = useState<PlaybookSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [builder, setBuilder] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);
  const [exportError, setExportError] = useState("");
  const [base, setBase] = useState(API_BASE || "http://localhost:3000");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setItems((await fetchPlaybooks()).playbooks);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    document.title = "Playbooks · Atomic Prevention";
    if (!API_BASE) setBase(window.location.origin);
    load();
  }, [load]);

  const download = async (id: string) => {
    setExporting(id);
    setExportError("");
    try {
      const blob = new Blob([JSON.stringify(await exportPlaybook(id), null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = Object.assign(document.createElement("a"), { href: url, download: `playbook-${id}.json` });
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setExportError(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(null);
    }
  };

  return (
    <>
      <PageHeader
        title="Playbooks"
        description="Generate prevention test playbooks and export them to the agent."
        actions={<Button variant="primary" icon={Plus} onClick={() => setBuilder(true)}>New playbook</Button>}
      />

      <section className="surface space-y-4 p-4" aria-labelledby="qs-h">
        <h2 id="qs-h" className="text-lg font-semibold">Run a playbook</h2>
        <ol className="list-decimal space-y-1 pl-5 text-sm text-muted-foreground">
          <li>Generate a playbook, then choose Export JSON.</li>
          <li>Download the agent for the target platform from the sidebar.</li>
          <li>Run it on the target host:</li>
        </ol>
        <div className="grid gap-3 lg:grid-cols-2">
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">Windows (PowerShell)</p>
            <pre className="code-block">{`Import-Module .\\AtomicPrevention\\AtomicPrevention.psm1\nInvoke-AtomicPrevention -Playbook .\\playbook.json -ServerUrl ${base}`}</pre>
          </div>
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">macOS and Linux (Python)</p>
            <pre className="code-block">{`python3 atomic_prevention_runner.py --playbook ./playbook.json --server ${base}`}</pre>
          </div>
        </div>
      </section>

      {exportError && <p role="alert" className="text-sm text-status-error-text">Export failed: {exportError}</p>}

      {error ? (
        <ErrorState message={error} onRetry={load} />
      ) : loading ? (
        <Skeleton rows={3} />
      ) : items.length === 0 ? (
        <Empty icon={BookOpenText} title="No playbooks yet" hint="A playbook is an ordered set of prevention tests for one adversary group or a custom technique list." action={<Button variant="primary" icon={Plus} onClick={() => setBuilder(true)}>Generate playbook</Button>} />
      ) : (
        <ul className="space-y-3">
          {items.map((p) => (
            <li key={p.id} className="surface flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
              <BookOpenText size={20} className="shrink-0 text-muted-foreground" aria-hidden />
              <div className="min-w-0 flex-1">
                <h3 className="truncate text-sm font-medium">{p.name}</h3>
                <p className="mt-1 text-xs tabular-nums text-muted-foreground">
                  {p.adversary_group_name ? `${p.adversary_group_name} · ` : ""}{p.technique_count} techniques · {p.test_count} tests · {formatDate(p.created_at)}
                </p>
              </div>
              <div className="flex gap-2">
                <Button size="sm" icon={DownloadSimple} loading={exporting === p.id} onClick={() => download(p.id)}>Export JSON</Button>
                <Link href={`/results?playbook=${p.id}`} className={btn("secondary", "sm")}><ChartBar size={16} aria-hidden /> Results</Link>
              </div>
            </li>
          ))}
        </ul>
      )}

      <PlaybookBuilder open={builder} onClose={() => setBuilder(false)} onCreated={load} />
    </>
  );
}
