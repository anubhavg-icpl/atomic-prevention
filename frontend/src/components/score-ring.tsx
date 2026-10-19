// Prevention score as an SVG ring. Stroke colour is a status token; the number is always printed
// inside, so colour is never the only signal. score=null renders the idle "no data" state.
import { scoreTone, type Tone } from "@/lib/status";

const STROKE: Record<Tone, string> = {
  ok: "stroke-status-ok",
  degraded: "stroke-status-degraded",
  error: "stroke-status-error",
  idle: "stroke-status-idle",
};

export default function ScoreRing({ score, size = 72 }: { score: number | null; size?: number }) {
  const r = 15.9155; // circumference = 100, so dasharray is the percentage directly
  const tone = scoreTone(score);
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={score === null ? "No score yet" : `Prevention score ${score} percent`}>
      <svg viewBox="0 0 36 36" className="size-full -rotate-90" fill="none" strokeWidth="3.5">
        <circle cx="18" cy="18" r={r} className="stroke-muted" />
        {score !== null && <circle cx="18" cy="18" r={r} strokeLinecap="round" strokeDasharray={`${score} 100`} className={STROKE[tone]} />}
      </svg>
      <span className="absolute inset-0 grid place-items-center text-sm font-semibold tabular-nums">{score === null ? "None" : `${score}%`}</span>
    </div>
  );
}
