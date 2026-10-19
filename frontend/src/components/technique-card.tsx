"use client";

import { useState } from "react";
import { CaretDown, CaretUp, Flask, ArrowSquareOut } from "@phosphor-icons/react";
import { fetchTechnique, type PreventionTest, type Technique } from "@/lib/api";
import { platformLabel, tacticLabel } from "@/lib/attack";
import { canonicalRisk } from "@/lib/status";
import { Badge, Mono } from "./page-parts";
import StatusDot from "./status-dot";

type Props = {
  technique: Technique & { test_count?: number; sub_test_count?: number };
  platformFilter?: string;
};

export default function TechniqueCard({ technique, platformFilter }: Props) {
  const [open, setOpen] = useState(false);
  const [tests, setTests] = useState<PreventionTest[] | null>(null);
  const [fetchedFor, setFetchedFor] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const count = technique.test_count ?? 0;

  const toggle = async () => {
    if (!open && (tests === null || fetchedFor !== platformFilter)) {
      setLoading(true);
      setFailed(false);
      try {
        setTests((await fetchTechnique(technique.id, platformFilter)).tests ?? []);
        setFetchedFor(platformFilter);
      } catch {
        setFailed(true);
      } finally {
        setLoading(false);
      }
    }
    setOpen(!open);
  };

  return (
    <article className="surface overflow-hidden">
      <div className="flex items-start gap-3 p-4">
        <button onClick={toggle} aria-expanded={open} className="min-w-0 flex-1 text-left">
          <Mono>{technique.id}</Mono>
          <h3 className="mt-0.5 truncate text-sm font-medium">{technique.name}</h3>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {technique.platforms.map((p) => <Badge key={p}>{platformLabel(p)}</Badge>)}
            {technique.tactics.map((t) => <Badge key={t}>{tacticLabel(t)}</Badge>)}
          </div>
          {technique.sources.length > 0 && <p className="mt-2 text-xs text-muted-foreground">Sources: {technique.sources.join(", ")}</p>}
          {!!technique.sub_test_count && <p className="mt-1 text-xs text-muted-foreground">Includes {technique.sub_test_count} tests from sub-techniques</p>}
        </button>
        <div className="flex shrink-0 items-center gap-2">
          <span className="flex items-center gap-1 text-label tabular-nums text-muted-foreground" title={`${count} tests`}>
            <Flask size={14} aria-hidden /> {count}
          </span>
          {technique.url && (
            <a href={technique.url} target="_blank" rel="noopener noreferrer" aria-label={`${technique.id} on MITRE ATT&CK`} className="rounded-md p-1 text-muted-foreground hover:bg-muted">
              <ArrowSquareOut size={16} />
            </a>
          )}
          <button onClick={toggle} aria-label={open ? "Hide tests" : "Show tests"} className="rounded-md p-1 text-muted-foreground hover:bg-muted">
            {open ? <CaretUp size={16} /> : <CaretDown size={16} />}
          </button>
        </div>
      </div>

      {open && (
        <div className="border-t border-border bg-muted/40">
          {loading ? (
            <p className="p-4 text-sm text-muted-foreground">Loading tests</p>
          ) : failed ? (
            <p className="p-4 text-sm text-status-error-text">Could not load tests for {technique.id}.</p>
          ) : !tests || tests.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No tests for this technique{platformFilter ? ` on ${platformLabel(platformFilter)}` : ""}.</p>
          ) : (
            <ul className="divide-y divide-border">
              {tests.map((t) => {
                const risk = canonicalRisk(t.risk_level);
                return (
                  <li key={t.id} className="space-y-2 p-4">
                    <p className="text-sm font-medium">{t.name}</p>
                    {t.technique_id !== technique.id && <p className="text-xs text-muted-foreground">via <Mono>{t.technique_id}</Mono></p>}
                    {t.description && <p className="line-clamp-2 text-xs text-muted-foreground">{t.description}</p>}
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge>{t.executor || "No executor"}</Badge>
                      <Badge>{t.source}</Badge>
                      {t.elevation_required && <Badge>Needs elevation</Badge>}
                      {risk && <StatusDot tone={risk.tone} label={risk.label} />}
                    </div>
                    {t.command && <pre className="code-block whitespace-pre-wrap break-all">{t.command}</pre>}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </article>
  );
}
