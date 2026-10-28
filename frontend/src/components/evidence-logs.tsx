import type { ReactNode } from "react";

export type EvidenceLog = Record<string, unknown>;

function displayValue(value: unknown): string {
  if (typeof value === "string") return value || "Empty";
  if (value === null) return "None";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return "Could not display this value";
    }
  }
  return String(value);
}

export function EvidenceText({
  title,
  value,
  emptyMessage = "No output was captured.",
}: {
  title: string;
  value: string | null | undefined;
  emptyMessage?: string;
}) {
  return (
    <section aria-label={title}>
      <h4 className="text-label font-semibold">{title}</h4>
      {value ? (
        <pre className="code-block mt-2 max-h-64 overflow-y-auto whitespace-pre-wrap break-words">{value}</pre>
      ) : (
        <p className="mt-2 text-sm text-muted-foreground">{emptyMessage}</p>
      )}
    </section>
  );
}

export function EvidenceLogs({
  title,
  logs,
  emptyMessage = "No log entries were captured.",
}: {
  title: string;
  logs: EvidenceLog[] | null | undefined;
  emptyMessage?: string;
}) {
  const entries = Array.isArray(logs) ? logs : [];

  return (
    <section aria-label={title}>
      <h4 className="text-label font-semibold">{title}</h4>
      {entries.length === 0 ? (
        <p className="mt-2 text-sm text-muted-foreground">{emptyMessage}</p>
      ) : (
        <ul className="mt-2 space-y-2">
          {entries.map((entry, index) => {
            const fields = Object.entries(entry);
            return (
              <li key={`${title}-${index}`} className="rounded-md border border-border bg-muted p-3">
                {fields.length === 0 ? (
                  <p className="text-sm text-muted-foreground">Empty log entry</p>
                ) : (
                  <dl className="space-y-2">
                    {fields.map(([key, value]) => (
                      <div key={`${title}-${index}-${key}`} className="grid gap-1 sm:grid-cols-[minmax(8rem,auto)_1fr] sm:gap-3">
                        <dt className="font-mono text-data text-muted-foreground">{key}</dt>
                        <dd className="min-w-0 whitespace-pre-wrap break-words font-mono text-data">{displayValue(value)}</dd>
                      </div>
                    ))}
                  </dl>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

export function EvidenceGrid({ children }: { children: ReactNode }) {
  return <div className="grid gap-5 lg:grid-cols-2">{children}</div>;
}
