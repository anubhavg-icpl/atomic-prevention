"use client";

// Playbook generator dialog. Native <dialog> gives focus trap, Escape and backdrop for free.
// Selecting a group auto-adds its techniques; those ids are tracked in groupTechIds so changing
// or clearing the group removes only what the group added, never techniques picked by hand.
import { useEffect, useMemo, useRef, useState } from "react";
import { MagnifyingGlass, X } from "@phosphor-icons/react";
import Button from "./button";
import { Mono } from "./page-parts";
import {
  fetchAdversaries, fetchAdversary, fetchAllTechniques, generatePlaybook,
  type AdversaryGroup, type GeneratePlaybookRequest, type Playbook, type Technique,
} from "@/lib/api";
import { PLATFORMS } from "@/lib/attack";

interface Props {
  open: boolean;
  onClose: () => void;
  onCreated: (p: Playbook) => void;
  defaultAdversaryId?: string;
}

export default function PlaybookBuilder({ open, onClose, onCreated, defaultAdversaryId }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const reqId = useRef(0);
  const [name, setName] = useState("");
  const [group, setGroup] = useState<AdversaryGroup | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [groupTech, setGroupTech] = useState<Set<string>>(new Set());
  const [platforms, setPlatforms] = useState<string[]>(["windows"]);
  const [payloads, setPayloads] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [groups, setGroups] = useState<AdversaryGroup[]>([]);
  const [techs, setTechs] = useState<(Technique & { test_count?: number })[]>([]);
  const [dataState, setDataState] = useState<"loading" | "ready" | "error">("loading");
  const [gq, setGq] = useState("");
  const [tq, setTq] = useState("");

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    // Each open starts from a blank form; otherwise the last playbook's picks silently carry over.
    setName(""); setGroup(null); setPicked(new Set()); setGroupTech(new Set());
    setPlatforms(["windows"]); setPayloads(""); setGq(""); setTq("");
    setDataState("loading");
    setError("");
    Promise.all([fetchAdversaries({ limit: 200 }), fetchAllTechniques()])
      .then(([g, t]) => {
        setGroups(g.adversaries);
        setTechs(t);
        setDataState("ready");
        const preset = defaultAdversaryId && g.adversaries.find((a) => a.id === defaultAdversaryId);
        if (preset) pickGroup(preset);
      })
      .catch(() => setDataState("error"));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, defaultAdversaryId]);

  const shownGroups = useMemo(() => {
    const q = gq.toLowerCase();
    return groups.filter((g) => !q || g.name.toLowerCase().includes(q) || g.id.toLowerCase().includes(q) || g.aliases.some((a) => a.toLowerCase().includes(q)));
  }, [groups, gq]);

  const shownTechs = useMemo(() => {
    const q = tq.toLowerCase();
    return techs.filter((t) => (t.test_count ?? 0) > 0 && (!q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q))).slice(0, 200);
  }, [techs, tq]);

  async function pickGroup(g: AdversaryGroup | null) {
    const id = ++reqId.current;
    setPicked((p) => { const n = new Set(p); groupTech.forEach((x) => n.delete(x)); return n; });
    setGroupTech(new Set());
    setGroup(g);
    if (!g) return;
    setName((n) => (!n || n.endsWith(" prevention test") ? `${g.name} prevention test` : n));
    try {
      const d = await fetchAdversary(g.id);
      if (id !== reqId.current) return; // a newer pick superseded this one
      const ids = new Set((d.techniques ?? []).map((t) => t.id));
      setPicked((p) => new Set([...p, ...ids]));
      setGroupTech(ids);
    } catch {
      setError("Could not load the group's techniques. You can still pick techniques by hand.");
    }
  }

  const toggle = (id: string) => setPicked((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const togglePlatform = (id: string) => setPlatforms((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!group && picked.size === 0) { setError("Pick an adversary group or at least one technique."); return; }
    if (platforms.length === 0) { setError("Pick at least one platform."); return; }
    const req: GeneratePlaybookRequest = { platforms };
    if (name.trim()) req.name = name.trim();
    if (group) { req.adversary_group_id = group.id; req.adversary_group_name = group.name; }
    if (picked.size) req.technique_ids = [...picked];
    const urls = payloads.split("\n").map((l) => l.trim()).filter(Boolean);
    if (urls.length) req.custom_payloads = urls.map((url, i) => ({ url, name: `Custom payload ${i + 1}`, executor: "powershell", technique_id: "T0000" }));
    setBusy(true);
    try {
      const pb = await generatePlaybook(req);
      onCreated(pb);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not generate the playbook");
    } finally {
      setBusy(false);
    }
  };

  return (
    <dialog ref={ref} onClose={onClose} onClick={(e) => e.target === ref.current && onClose()} className="m-auto w-full max-w-2xl rounded-xl border border-border bg-popover p-0 text-foreground shadow-xl">
      <form onSubmit={submit} className="flex max-h-[90dvh] flex-col">
        <div className="flex items-center justify-between border-b border-border p-5">
          <h2 className="text-xl font-semibold">Generate playbook</h2>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded-md p-1 text-muted-foreground hover:bg-muted"><X size={20} /></button>
        </div>

        <div className="space-y-6 overflow-y-auto p-5">
          <div className="space-y-2">
            <label htmlFor="pb-name" className="text-label font-medium">Playbook name</label>
            <input id="pb-name" className="field" value={name} onChange={(e) => setName(e.target.value)} placeholder="Named after the group if left empty" />
          </div>

          {dataState === "error" && <p className="text-sm text-status-error-text" role="alert">Could not load groups and techniques. Close and reopen to retry.</p>}

          <fieldset className="space-y-2">
            <legend className="text-label font-medium">Adversary group {group && <span className="font-normal text-muted-foreground">({group.name}, {group.technique_count} techniques)</span>}</legend>
            <div className="relative">
              <MagnifyingGlass size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden />
              <input aria-label="Search groups" className="field pl-9" value={gq} onChange={(e) => setGq(e.target.value)} placeholder="Search groups" />
            </div>
            <ul className="max-h-40 overflow-y-auto rounded-md border border-border">
              {dataState === "loading" ? <li className="p-3 text-sm text-muted-foreground">Loading</li> : shownGroups.length === 0 ? <li className="p-3 text-sm text-muted-foreground">No groups found</li> : shownGroups.map((g) => (
                <li key={g.id}>
                  <label className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-muted">
                    <input type="radio" name="group" checked={group?.id === g.id} onChange={() => pickGroup(g)} className="accent-primary" />
                    <Mono>{g.id}</Mono>
                    <span className="min-w-0 flex-1 truncate text-sm">{g.name}</span>
                    <span className="text-xs tabular-nums text-muted-foreground">{g.technique_count}</span>
                  </label>
                </li>
              ))}
            </ul>
            {group && <Button size="sm" variant="ghost" onClick={() => pickGroup(null)}>Clear group</Button>}
          </fieldset>

          <fieldset className="space-y-2">
            <legend className="text-label font-medium">Techniques <span className="font-normal text-muted-foreground">({picked.size} selected)</span></legend>
            <div className="relative">
              <MagnifyingGlass size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden />
              <input aria-label="Search techniques" className="field pl-9" value={tq} onChange={(e) => setTq(e.target.value)} placeholder="Search techniques with tests, e.g. T1059 or PowerShell" />
            </div>
            <ul className="max-h-48 overflow-y-auto rounded-md border border-border">
              {dataState === "loading" ? <li className="p-3 text-sm text-muted-foreground">Loading</li> : shownTechs.length === 0 ? <li className="p-3 text-sm text-muted-foreground">No techniques with tests found</li> : shownTechs.map((t) => (
                <li key={t.id}>
                  <label className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-muted">
                    <input type="checkbox" checked={picked.has(t.id)} onChange={() => toggle(t.id)} className="accent-primary" />
                    <span className="w-24 shrink-0"><Mono>{t.id}</Mono></span>
                    <span className="min-w-0 flex-1 truncate text-sm">{t.name}</span>
                    <span className="text-xs tabular-nums text-muted-foreground">{t.test_count} tests</span>
                  </label>
                </li>
              ))}
            </ul>
            {picked.size > 0 && <Button size="sm" variant="ghost" onClick={() => { setPicked(new Set()); setGroupTech(new Set()); }}>Clear all {picked.size}</Button>}
          </fieldset>

          <fieldset className="space-y-2">
            <legend className="text-label font-medium">Platforms</legend>
            <div className="flex gap-4">
              {PLATFORMS.map((p) => (
                <label key={p.id} className="flex cursor-pointer items-center gap-2 text-sm">
                  <input type="checkbox" checked={platforms.includes(p.id)} onChange={() => togglePlatform(p.id)} className="accent-primary" />
                  {p.label}
                </label>
              ))}
            </div>
          </fieldset>

          <div className="space-y-2">
            <label htmlFor="pb-payloads" className="text-label font-medium">Custom payload URLs <span className="font-normal text-muted-foreground">(optional, one per line)</span></label>
            <textarea id="pb-payloads" rows={2} className="field h-auto py-2 font-mono text-data" value={payloads} onChange={(e) => setPayloads(e.target.value)} placeholder="https://example.com/payload.ps1" />
            <p className="text-xs text-muted-foreground">The agent downloads and attempts to run each URL on the target host.</p>
          </div>

          {error && <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{error}</p>}
        </div>

        <div className="flex justify-end gap-2 border-t border-border p-5">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={busy}>Generate playbook</Button>
        </div>
      </form>
    </dialog>
  );
}
