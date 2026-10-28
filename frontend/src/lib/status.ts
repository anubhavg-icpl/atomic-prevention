/*
 * The one place a verdict or risk value becomes a word and a tone (Law 17).
 * Pages never branch on `verdict === "..."` for colour: they call these and
 * render <StatusDot>, which always pairs the dot with the word (Law 7).
 * Unknown values fall back to idle so a new backend value never reads as a problem.
 */
export type Tone = "ok" | "degraded" | "error" | "idle";
export type StatusToken = "detected";

export interface StatusInfo {
  label: string;
  tone: Tone;
  token?: StatusToken;
}

const VERDICTS: Record<string, StatusInfo> = {
  blocked: { label: "Blocked", tone: "ok" },
  detected: { label: "Detected", tone: "degraded", token: "detected" },
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

export function preventionScore(s: { blocked: number; detected?: number; allowed: number }): number | null {
  const total = s.blocked + (s.detected ?? 0) + s.allowed;
  return total > 0 ? Math.round((s.blocked / total) * 100) : null;
}

/** Visibility includes tests that were blocked or detected. */
export function visibilityScore(s: {
  blocked?: number;
  total_blocked?: number;
  detected?: number;
  total_detected?: number;
  allowed?: number;
  total_allowed?: number;
}): number | null {
  const blocked = s.blocked ?? s.total_blocked ?? 0;
  const detected = s.detected ?? s.total_detected ?? 0;
  const allowed = s.allowed ?? s.total_allowed ?? 0;
  const total = blocked + detected + allowed;
  return total > 0 ? Math.round(((blocked + detected) / total) * 100) : null;
}

/** Compatibility alias for earlier UI copies. */
export const detectionScore = visibilityScore;
