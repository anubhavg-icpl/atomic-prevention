// Status is a dot plus its word, never colour alone. Only the error tone pulses.
import type { Tone } from "@/lib/status";

const DOT: Record<Tone, string> = {
  ok: "bg-status-ok",
  degraded: "bg-status-degraded",
  error: "bg-status-error motion-safe:animate-[pulse-dot_2s_ease-in-out_infinite]",
  idle: "bg-status-idle",
};
const TEXT: Record<Tone, string> = {
  ok: "text-status-ok-text",
  degraded: "text-status-degraded-text",
  error: "text-status-error-text",
  idle: "text-status-idle-text",
};

export default function StatusDot({ tone, label }: { tone: Tone; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 text-label font-medium ${TEXT[tone]}`}>
      <span className={`size-2 rounded-full ${DOT[tone]}`} aria-hidden />
      {label}
    </span>
  );
}
