// MITRE ATT&CK enterprise tactic order (v19+, https://attack.mitre.org/tactics/enterprise/).
// The backend stores tactic slugs; this is the single display-name table.
export const TACTICS: { id: string; label: string }[] = [
  { id: "reconnaissance", label: "Reconnaissance" },
  { id: "resource-development", label: "Resource development" },
  { id: "initial-access", label: "Initial access" },
  { id: "execution", label: "Execution" },
  { id: "persistence", label: "Persistence" },
  { id: "privilege-escalation", label: "Privilege escalation" },
  { id: "stealth", label: "Stealth" },
  { id: "defense-impairment", label: "Defense impairment" },
  { id: "credential-access", label: "Credential access" },
  { id: "discovery", label: "Discovery" },
  { id: "lateral-movement", label: "Lateral movement" },
  { id: "collection", label: "Collection" },
  { id: "command-and-control", label: "Command and control" },
  { id: "exfiltration", label: "Exfiltration" },
  { id: "impact", label: "Impact" },
];

const LABELS = Object.fromEntries(TACTICS.map((t) => [t.id, t.label]));

export const tacticLabel = (id: string) => LABELS[id] ?? id.replace(/-/g, " ");

export const PLATFORMS = [
  { id: "windows", label: "Windows" },
  { id: "linux", label: "Linux" },
  { id: "macos", label: "macOS" },
];

const PLATFORM_LABELS: Record<string, string> = Object.fromEntries(PLATFORMS.map((p) => [p.id, p.label]));

export const platformLabel = (id: string) => PLATFORM_LABELS[id.toLowerCase()] ?? id;

export const formatDate = (iso: string | null, withTime = false) =>
  iso ? (withTime ? new Date(iso).toLocaleString() : new Date(iso).toLocaleDateString()) : "Not recorded";
