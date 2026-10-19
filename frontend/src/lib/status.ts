/*
 * The one place a verdict or risk value becomes a word and a tone (Law 17).
 * Pages never branch on `verdict === "..."` for colour: they call these and
 * render <StatusDot>, which always pairs the dot with the word (Law 7).
 * Unknown values fall back to idle so a new backend value never reads as a problem.
 */
export type Tone = "ok" | "degraded" | "error" | "idle";

export interface StatusInfo {
  label: string;
  tone: Tone;
}

const VERDICTS: Record<string, StatusInfo> = {
  blocked: { label: "Blocked", tone: "ok" },
  allowed: { label: "Allowed", tone: "error" },
  error: { label: "Error", tone: "degraded" },
  untested: { label: "Untested", tone: "idle" },
};

const RISKS: Record<string, StatusInfo> = {
  high: { label: "High risk", tone: "error" },
  medium: { label: "Medium risk", tone: "degraded" },
  low: { label: "Low risk", tone: "ok" },
};

export function canonicalVerdict(v: string | null | undefined): StatusInfo {
  return VERDICTS[(v || "").toLowerCase()] ?? { label: v || "Unknown", tone: "idle" };
}

export function canonicalRisk(v: string | null | undefined): StatusInfo | null {
  return v ? RISKS[v.toLowerCase()] ?? { label: v, tone: "idle" } : null;
}

/** Score bands: 80+ holds, 50+ is partial, below is failing. */
export function scoreTone(score: number | null): Tone {
  if (score === null) return "idle";
  return score >= 80 ? "ok" : score >= 50 ? "degraded" : "error";
}

export function preventionScore(s: { blocked: number; allowed: number }): number | null {
  const total = s.blocked + s.allowed;
  return total > 0 ? Math.round((s.blocked / total) * 100) : null;
}
