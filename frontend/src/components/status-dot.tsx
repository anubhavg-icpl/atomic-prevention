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
const TOKEN_FILL = {
  detected: { dot: "bg-status-info", text: "text-status-info-text" },
};

export default function StatusDot({
  tone,
  label,
  token,
}: {
  tone: Tone;
  label: string;
  token?: "detected";
}) {
  const tokenStyle = token ? TOKEN_FILL[token] : undefined;
  return (
    <span className={`inline-flex items-center gap-1.5 text-label font-medium ${tokenStyle?.text ?? TEXT[tone]}`}>
      <span className={`size-2 rounded-full ${tokenStyle?.dot ?? DOT[tone]}`} aria-hidden />
      {label}
    </span>
  );
}
