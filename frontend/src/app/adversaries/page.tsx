"use client";

import { useCallback, useEffect, useState } from "react";
import { ArrowSquareOut, CaretDown, CaretUp, Lightning, MagnifyingGlass, UsersThree } from "@phosphor-icons/react";
import Button from "@/components/button";
import PlaybookBuilder from "@/components/playbook-builder";
import { Badge, Empty, ErrorState, Mono, PageHeader, Skeleton } from "@/components/page-parts";
import { fetchAdversaries, fetchAdversary, type AdversaryGroup } from "@/lib/api";
import { tacticLabel } from "@/lib/attack";

export default function AdversariesPage() {
  const [groups, setGroups] = useState<AdversaryGroup[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [detail, setDetail] = useState<AdversaryGroup | null>(null);
  const [detailState, setDetailState] = useState<"idle" | "loading" | "error">("idle");
  const [builderFor, setBuilderFor] = useState<AdversaryGroup | null>(null);

  useEffect(() => { document.title = "Adversaries · Atomic Prevention"; }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const d = await fetchAdversaries({ search: search || undefined, limit: 100 });
      setGroups(d.adversaries);
      setTotal(d.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }, [search]);

  useEffect(() => {
    const t = setTimeout(load, 300);
    return () => clearTimeout(t);
  }, [load]);

  const toggle = async (g: AdversaryGroup) => {
    if (openId === g.id) { setOpenId(null); return; }
    setOpenId(g.id);
    setDetail(null);
    setDetailState("loading");
    try {
      setDetail(await fetchAdversary(g.id));
      setDetailState("idle");
    } catch {
      setDetailState("error");
    }
  };

  return (
    <>
      <PageHeader title="Adversaries" description="MITRE ATT&CK threat groups and the techniques they use." />

      <div className="relative max-w-xl">
        <label htmlFor="q" className="sr-only">Search adversary groups</label>
        <MagnifyingGlass size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden />
        <input id="q" className="field pl-9" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search by name or alias" />
      </div>
      <p className="text-sm tabular-nums text-muted-foreground" role="status">{loading ? "Searching" : `${total} group${total === 1 ? "" : "s"}`}</p>

      {error ? (
        <ErrorState message={error} onRetry={load} />
      ) : loading ? (
        <Skeleton rows={4} />
      ) : groups.length === 0 ? (
        <Empty icon={UsersThree} title="No adversary groups found" hint="Sync data sources from the dashboard to populate groups." />
      ) : (
        <div className="grid grid-cols-1 items-start gap-4 md:grid-cols-2">
          {groups.map((g) => (
            <article key={g.id} className="surface overflow-hidden">
              <div className="p-4">
                <div className="flex items-start gap-3">
                  <button onClick={() => toggle(g)} aria-expanded={openId === g.id} className="min-w-0 flex-1 text-left">
                    <Mono>{g.id}</Mono>
                    <h3 className="mt-0.5 text-sm font-medium">{g.name}</h3>
                  </button>
                  {g.url && (
                    <a href={g.url} target="_blank" rel="noopener noreferrer" aria-label={`${g.name} on MITRE ATT&CK`} className="rounded-md p-1 text-muted-foreground hover:bg-muted">
                      <ArrowSquareOut size={16} />
                    </a>
                  )}
                  <Button size="sm" icon={Lightning} onClick={() => setBuilderFor(g)}>Playbook</Button>
                  <button onClick={() => toggle(g)} aria-label={openId === g.id ? "Hide techniques" : "Show techniques"} className="rounded-md p-1 text-muted-foreground hover:bg-muted">
                    {openId === g.id ? <CaretUp size={16} /> : <CaretDown size={16} />}
                  </button>
                </div>
                {g.aliases.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {g.aliases.slice(0, 5).map((a) => <Badge key={a}>{a}</Badge>)}
                    {g.aliases.length > 5 && <span className="text-xs text-muted-foreground">+{g.aliases.length - 5} more</span>}
                  </div>
                )}
                <p className="mt-3 text-xs tabular-nums text-muted-foreground">{g.technique_count} techniques</p>
              </div>

              {openId === g.id && (
                <div className="border-t border-border bg-muted/40 p-4">
                  {detailState === "loading" && <p className="text-sm text-muted-foreground">Loading techniques</p>}
                  {detailState === "error" && <p className="text-sm text-status-error-text">Could not load techniques for {g.id}.</p>}
                  {detailState === "idle" && detail && (
                    <>
                      {detail.description && <p className="mb-3 line-clamp-3 text-xs text-muted-foreground">{detail.description}</p>}
                      {!detail.techniques?.length ? (
                        <p className="text-sm text-muted-foreground">No techniques associated.</p>
                      ) : (
                        <ul className="max-h-80 space-y-1.5 overflow-y-auto">
                          {detail.techniques.map((t) => (
                            <li key={t.id} className="flex items-center gap-3 rounded-md border border-border bg-card px-3 py-2">
                              <span className="w-24 shrink-0"><Mono>{t.id}</Mono></span>
                              <span className="min-w-0 flex-1 truncate text-sm">{t.name}</span>
                              <span className="hidden shrink-0 text-xs text-muted-foreground sm:block">{t.tactics.slice(0, 2).map(tacticLabel).join(", ")}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </>
                  )}
                </div>
              )}
            </article>
          ))}
        </div>
      )}

      <PlaybookBuilder open={!!builderFor} onClose={() => setBuilderFor(null)} onCreated={() => {}} defaultAdversaryId={builderFor?.id} />
    </>
  );
}
