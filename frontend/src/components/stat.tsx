// KPI tile: accent legend dot on the label, big tabular value, one sub line, no edge keyline.
export default function Stat({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="surface p-4">
      <p className="flex items-center gap-2 text-label font-medium text-muted-foreground">
        <span className="size-2 rounded-full bg-primary" aria-hidden />
        {label}
      </p>
      <p className="mt-2 text-3xl font-bold tabular-nums">{typeof value === "number" ? value.toLocaleString() : value}</p>
      {sub && <p className="mt-1 text-xs text-muted-foreground">{sub}</p>}
    </div>
  );
}
