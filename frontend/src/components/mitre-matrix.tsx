"use client";

// ATT&CK coverage matrix. Cell fill comes from the verdict vocabulary (status tokens);
// every cell also carries its verdict word in title/aria-label so colour is never the only signal.
// Capped at ROWS per tactic so the page stays scannable; the overflow count is shown per column.
import Link from "next/link";
import { useMemo } from "react";
import type { Technique } from "@/lib/api";
import { TACTICS } from "@/lib/attack";
import { canonicalVerdict } from "@/lib/status";

const ROWS = 12;
const FILL = {
  ok: "bg-status-ok/25 border-status-ok/50",
  error: "bg-status-error/25 border-status-error/50",
  degraded: "bg-status-degraded/25 border-status-degraded/50",
  idle: "bg-muted border-border",
};

const fillFor = (s: { tone: keyof typeof FILL; token?: "detected" }) =>
  s.token === "detected"
    ? "bg-status-info/25 border-status-info/50"
    : FILL[s.tone];

export default function MitreMatrix({ techniques, verdicts }: { techniques: Technique[]; verdicts: Record<string, string> }) {
  const columns = useMemo(
    () => TACTICS.map((t) => ({ ...t, items: techniques.filter((x) => x.tactics.includes(t.id)) })),
    [techniques]
  );

  return (
    <section className="surface p-4" aria-labelledby="matrix-h">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="matrix-h" className="text-lg font-semibold">ATT&amp;CK coverage</h2>
        <ul className="flex flex-wrap gap-4 text-xs text-muted-foreground">
          {(["blocked", "detected", "allowed", "untested"] as const).map((v) => {
            const s = canonicalVerdict(v);
            return (
              <li key={v} className="flex items-center gap-1.5">
                <span className={`size-3 rounded-sm border ${fillFor(s)}`} aria-hidden />
                {s.label}
              </li>
            );
          })}
        </ul>
      </div>
      <div className="mt-4 overflow-x-auto">
        <div className="grid min-w-[1500px] gap-1.5" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(0, 1fr))` }}>
          {columns.map((c) => (
            <div key={c.id} className="space-y-1">
              <div className="border-b border-border pb-1.5">
                <p className="truncate text-xs font-medium" title={c.label}>{c.label}</p>
                <p className="text-xs tabular-nums text-muted-foreground">{c.items.length}</p>
              </div>
              {c.items.slice(0, ROWS).map((t) => {
                const s = canonicalVerdict(verdicts[t.id] ?? "untested");
                return (
                  <Link
                    key={t.id}
                    href={`/techniques?search=${encodeURIComponent(t.id)}`}
                    title={`${t.id} ${t.name}: ${s.label}`}
                    aria-label={`${t.id} ${t.name}, ${s.label}`}
                    className={`block truncate rounded-sm border px-1.5 py-1 font-mono text-xs hover:brightness-95 ${fillFor(s)}`}
                  >
                    {t.id}
                  </Link>
                );
              })}
              {c.items.length > ROWS && <p className="text-xs text-muted-foreground">+{c.items.length - ROWS} more</p>}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
