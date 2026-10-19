"use client";

import { useCallback, useEffect, useState } from "react";
import { CaretLeft, CaretRight, MagnifyingGlass, ShieldCheck, X } from "@phosphor-icons/react";
import Button from "@/components/button";
import TechniqueCard from "@/components/technique-card";
import { Empty, ErrorState, PageHeader, Skeleton } from "@/components/page-parts";
import { fetchSources, fetchTechniques, type Source, type Technique } from "@/lib/api";
import { PLATFORMS, TACTICS } from "@/lib/attack";

const PAGE_SIZE = 50;

export default function TechniquesPage() {
  const [items, setItems] = useState<Technique[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [tactic, setTactic] = useState("");
  const [platform, setPlatform] = useState("");
  const [source, setSource] = useState("");
  const [page, setPage] = useState(0);
  const [sources, setSources] = useState<Source[]>([]);

  // The matrix on the dashboard links here with ?search=<technique id>.
  useEffect(() => {
    document.title = "Techniques · Atomic Prevention";
    const q = new URLSearchParams(window.location.search).get("search");
    if (q) setSearch(q);
    fetchSources().then((d) => setSources(d.sources)).catch(() => {});
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const d = await fetchTechniques({ limit: PAGE_SIZE, skip: page * PAGE_SIZE, search: search || undefined, tactic: tactic || undefined, platform: platform || undefined, source: source || undefined });
      setItems(d.techniques);
      setTotal(d.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }, [search, tactic, platform, source, page]);

  useEffect(() => {
    const t = setTimeout(load, 300);
    return () => clearTimeout(t);
  }, [load]);

  const filter = (set: (v: string) => void) => (e: React.ChangeEvent<HTMLSelectElement>) => { set(e.target.value); setPage(0); };
  const active = [tactic, platform, source].filter(Boolean).length + (search ? 1 : 0);
  const clear = () => { setSearch(""); setTactic(""); setPlatform(""); setSource(""); setPage(0); };
  const pages = Math.ceil(total / PAGE_SIZE);

  return (
    <>
      <PageHeader title="Techniques" description="MITRE ATT&CK techniques and the prevention tests mapped to them." />

      <div className="surface grid grid-cols-1 gap-3 p-4 md:grid-cols-[1fr_repeat(3,minmax(0,200px))_auto]">
        <div className="relative">
          <label htmlFor="q" className="sr-only">Search techniques</label>
          <MagnifyingGlass size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <input id="q" className="field pl-9" value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }} placeholder="Search by ID, name or description" />
        </div>
        <label className="sr-only" htmlFor="tactic">Tactic</label>
        <select id="tactic" className="field" value={tactic} onChange={filter(setTactic)}>
          <option value="">All tactics</option>
          {TACTICS.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
        </select>
        <label className="sr-only" htmlFor="platform">Platform</label>
        <select id="platform" className="field" value={platform} onChange={filter(setPlatform)}>
          <option value="">All platforms</option>
          {PLATFORMS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
        </select>
        <label className="sr-only" htmlFor="source">Source</label>
        <select id="source" className="field" value={source} onChange={filter(setSource)}>
          <option value="">All sources</option>
          {sources.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.test_count})</option>)}
        </select>
        <Button icon={X} disabled={active === 0} onClick={clear}>Clear filters</Button>
      </div>

      <p className="text-sm tabular-nums text-muted-foreground" role="status">
        {loading ? "Searching" : `${total.toLocaleString()} technique${total === 1 ? "" : "s"}`}
      </p>

      {error ? (
        <ErrorState message={error} onRetry={load} />
      ) : loading ? (
        <Skeleton rows={5} />
      ) : items.length === 0 ? (
        <Empty icon={ShieldCheck} title="No techniques found" hint="Adjust the search or filters, or sync a data source from the dashboard." action={active > 0 ? <Button onClick={clear}>Clear filters</Button> : undefined} />
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {items.map((t) => <TechniqueCard key={t.id} technique={t} platformFilter={platform || undefined} />)}
          </div>
          {pages > 1 && (
            <nav aria-label="Pagination" className="flex items-center justify-between">
              <span className="text-sm tabular-nums text-muted-foreground">{page * PAGE_SIZE + 1} to {Math.min((page + 1) * PAGE_SIZE, total)} of {total}</span>
              <div className="flex gap-2">
                <Button size="sm" icon={CaretLeft} disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</Button>
                <Button size="sm" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next <CaretRight size={16} aria-hidden /></Button>
              </div>
            </nav>
          )}
        </>
      )}
    </>
  );
}
