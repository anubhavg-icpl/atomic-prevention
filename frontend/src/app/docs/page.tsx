"use client";

import { useEffect, useState } from "react";
import { ArrowSquareOut, CaretDown, CaretRight, Check, Copy, Play } from "@phosphor-icons/react";
import Button from "@/components/button";
import { PageHeader } from "@/components/page-parts";
import { API_BASE } from "@/lib/api";

interface Endpoint {
  method: "GET" | "POST";
  path: string;
  description: string;
  params?: { name: string; type: string; required: boolean; description: string }[];
  body?: string;
  example_response: string;
  notes?: string;
}

interface Section {
  title: string;
  description: string;
  endpoints: Endpoint[];
}

const API_SECTIONS: Section[] = [
  {
    title: "Health & Stats",
    description: "System health and overall statistics",
    endpoints: [
      {
        method: "GET",
        path: "/api/health",
        description: "Health check — verify the backend is running",
        example_response: `{
  "status": "ok",
  "version": "0.1.0"
}`,
      },
      {
        method: "GET",
        path: "/api/techniques/stats",
        description: "Total technique and test counts across all sources",
        example_response: `{
  "total_techniques": 692,
  "total_tests": 4808
}`,
      },
    ],
  },
  {
    title: "Techniques",
    description: "Browse and search MITRE ATT&CK techniques with prevention tests",
    endpoints: [
      {
        method: "GET",
        path: "/api/techniques",
        description: "List techniques with optional filtering and pagination",
        params: [
          { name: "search", type: "string", required: false, description: "Search by technique ID or name" },
          { name: "platform", type: "string", required: false, description: "Filter by platform: windows, linux, macos" },
          { name: "tactic", type: "string", required: false, description: "Filter by ATT&CK tactic (e.g., execution, persistence)" },
          { name: "source", type: "string", required: false, description: "Filter by data source (e.g., lolbas, atomic-red-team)" },
          { name: "limit", type: "integer", required: false, description: "Results per page (default: 50)" },
          { name: "skip", type: "integer", required: false, description: "Offset for pagination (default: 0)" },
        ],
        example_response: `{
  "techniques": [
    {
      "id": "T1059.001",
      "name": "PowerShell",
      "description": "Adversaries may abuse PowerShell...",
      "tactics": ["execution"],
      "platforms": ["windows"],
      "test_count": 42,
      "sources": ["atomic-red-team", "lolbas", "custom"]
    }
  ],
  "total": 692
}`,
      },
      {
        method: "GET",
        path: "/api/techniques/{id}",
        description: "Get full technique details including all prevention tests",
        params: [
          { name: "id", type: "string", required: true, description: "MITRE technique ID (e.g., T1059.001)" },
        ],
        example_response: `{
  "id": "T1059.001",
  "name": "PowerShell",
  "description": "Adversaries may abuse PowerShell...",
  "tactics": ["execution"],
  "platforms": ["windows"],
  "url": "https://attack.mitre.org/techniques/T1059/001/",
  "tests": [
    {
      "id": "a1b2c3d4-...",
      "name": "ART: Mimikatz via PowerShell",
      "description": "Downloads and executes Mimikatz...",
      "command": "powershell.exe -c IEX ...",
      "executor": "powershell",
      "source": "atomic-red-team",
      "risk_level": "high",
      "elevation_required": true,
      "platforms": ["windows"],
      "cleanup_command": "Remove-Item ..."
    }
  ]
}`,
      },
    ],
  },
  {
    title: "Adversary Groups",
    description: "170+ MITRE ATT&CK threat groups with technique mappings",
    endpoints: [
      {
        method: "GET",
        path: "/api/adversaries",
        description: "List adversary groups with search and pagination",
        params: [
          { name: "search", type: "string", required: false, description: "Search by group name or alias" },
          { name: "limit", type: "integer", required: false, description: "Results per page (default: 50)" },
          { name: "skip", type: "integer", required: false, description: "Offset for pagination" },
        ],
        example_response: `{
  "adversaries": [
    {
      "id": "G1017",
      "name": "Volt Typhoon",
      "description": "Chinese state-sponsored group...",
      "aliases": ["BRONZE SILHOUETTE", "Vanguard Panda"],
      "technique_count": 82,
      "url": "https://attack.mitre.org/groups/G1017/"
    }
  ],
  "total": 172
}`,
      },
      {
        method: "GET",
        path: "/api/adversaries/{id}",
        description: "Get group details with full technique list",
        params: [
          { name: "id", type: "string", required: true, description: "MITRE group ID (e.g., G1017)" },
        ],
        example_response: `{
  "id": "G1017",
  "name": "Volt Typhoon",
  "description": "Chinese state-sponsored group targeting critical infrastructure...",
  "aliases": ["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391"],
  "technique_count": 82,
  "technique_ids": ["T1059.001", "T1059.003", "T1105", "T1047", "..."],
  "url": "https://attack.mitre.org/groups/G1017/"
}`,
      },
    ],
  },
  {
    title: "Playbooks",
    description: "Generate and manage adversary-specific prevention playbooks",
    endpoints: [
      {
        method: "POST",
        path: "/api/playbooks/generate",
        description: "Generate a playbook from an adversary group or technique list",
        body: `{
  "adversary_group_id": "G1017",   // OR
  "technique_ids": ["T1059.001", "T1218.011"],
  "platforms": ["windows"],
  "name": "Optional custom name"
}`,
        example_response: `{
  "id": "pb-a1b2c3d4-...",
  "name": "Volt Typhoon Prevention Playbook",
  "adversary_group_id": "G1017",
  "technique_ids": ["T1059.001", "T1059.003", "..."],
  "test_ids": ["test-1", "test-2", "..."],
  "platforms": ["windows"],
  "created_at": "2026-03-28T20:00:00Z"
}`,
        notes: "Use adversary_group_id for group-based playbooks, or technique_ids for custom selections. Both can be combined.",
      },
      {
        method: "GET",
        path: "/api/playbooks/{id}/export",
        description: "Export a playbook as JSON for the agent runner",
        params: [
          { name: "id", type: "string", required: true, description: "Playbook ID" },
        ],
        example_response: `{
  "playbook_id": "pb-a1b2c3d4-...",
  "name": "Volt Typhoon Prevention Playbook",
  "created_at": "2026-03-28T20:00:00Z",
  "tests": [
    {
      "id": "test-1",
      "technique_id": "T1059.001",
      "name": "ART: PowerShell execution",
      "command": "powershell.exe -c ...",
      "executor": "powershell",
      "platforms": ["windows"],
      "cleanup_command": "...",
      "risk_level": "high"
    }
  ]
}`,
        notes: "This is the JSON format consumed by both the PowerShell and Python agents.",
      },
    ],
  },
  {
    title: "Results",
    description: "Submit and retrieve prevention test results",
    endpoints: [
      {
        method: "POST",
        path: "/api/results/submit",
        description: "Upload test results from the agent",
        body: `{
  "playbook_id": "pb-a1b2c3d4-...",
  "hostname": "WORKSTATION-01",
  "platform": "windows",
  "os_version": "Windows 11 23H2",
  "results": [
    {
      "test_id": "test-1",
      "verdict": "blocked",
      "exit_code": 1,
      "execution_time_ms": 1250,
      "started_at": "2026-10-27T12:00:00Z",
      "completed_at": "2026-10-27T12:00:01Z",
      "stdout": "...",
      "stderr": "Access denied",
      "agent_logs": [...]
    }
  ]
}`,
        example_response: `{
  "run_id": "run-a1b2c3d4-...",
  "summary": { "blocked": 37, "detected": 1, "allowed": 4, "error": 0 }
}`,
      },
      {
        method: "POST",
        path: "/api/results/upload",
        description: "Upload a results JSON file (multipart form)",
        example_response: `{
  "run_id": "run-a1b2c3d4-...",
  "summary": { "blocked": 37, "detected": 1, "allowed": 4, "error": 0 }
}`,
        notes: "Accepts a file upload (results JSON exported by the agent).",
      },
      {
        method: "GET",
        path: "/api/results/runs/{id}",
        description: "Get detailed results for a specific test run",
        params: [
          { name: "id", type: "string", required: true, description: "Run ID" },
        ],
        example_response: `{
  "run_id": "run-a1b2c3d4-...",
  "playbook_id": "pb-...",
  "hostname": "WORKSTATION-01",
  "platform": "windows",
  "submitted_at": "2026-03-28T20:30:00Z",
  "summary": {
    "blocked": 37,
    "detected": 1,
    "allowed": 4,
    "error": 0,
    "prevention_score": 88.1,
    "visibility_score": 90.5
  },
  "results": [...]
}`,
      },
    ],
  },
  {
    title: "Data Sources",
    description: "Manage LOL data source ingestion and sync",
    endpoints: [
      {
        method: "GET",
        path: "/api/sources",
        description: "List all registered data sources with test counts",
        example_response: `{
  "sources": [
    {
      "id": "lolbas",
      "name": "LOLBAS",
      "description": "Living Off The Land Binaries...",
      "repo_url": "https://github.com/LOLBAS-Project/LOLBAS",
      "platform": "windows",
      "test_count": 462
    },
    {
      "id": "atomic-red-team",
      "name": "Atomic Red Team",
      "platform": "multi",
      "test_count": 1758
    }
  ]
}`,
      },
      {
        method: "POST",
        path: "/api/sources/{source_id}/sync",
        description: "Sync a data source — clones/pulls repo and re-parses tests",
        params: [
          { name: "source_id", type: "string", required: true, description: "Source ID (e.g., lolbas, gtfobins, sysinternals)" },
        ],
        example_response: `{
  "source": "lolbas",
  "tests_persisted": 462,
  "techniques_updated": 56
}`,
        notes: "Available sources: lolbas, atomic-red-team, loldrivers, lolrmm, loobins, lolapi, lottunnels, persistence-info, gtfobins, loas, sysinternals",
      },
    ],
  },
  {
    title: "QA automation",
    description: "UEC correlation, Claude analysis, and GitLab issue tracking",
    endpoints: [
      {
        method: "GET",
        path: "/api/integrations/status",
        description: "Show whether optional integrations are enabled and configured",
        example_response: `{
  "claude": { "enabled": true, "configured": true, "model": "claude-sonnet-4-5" },
  "gitlab": { "enabled": true, "configured": true },
  "uec": { "enabled": true, "configured": true, "correlation_enabled": true }
}`,
      },
      {
        method: "GET",
        path: "/api/integrations/gitlab/projects",
        description: "Search accessible GitLab projects",
        params: [
          { name: "search", type: "string", required: true, description: "Project name or path fragment" },
        ],
        example_response: `{ "projects": [{ "id": "532", "path_with_namespace": "infopercept/xdr/uec/uec" }] }`,
      },
      {
        method: "POST",
        path: "/api/qa/runs/{run_id}/analyze",
        description: "Correlate UEC evidence and create an optional Claude or deterministic QA analysis",
        params: [
          { name: "run_id", type: "string", required: true, description: "Playbook run identifier" },
        ],
        example_response: `{
  "provider": "claude",
  "model": "claude-sonnet-4-5",
  "result": { "summary": "...", "findings": [...], "issue": {...} }
}`,
      },
      {
        method: "POST",
        path: "/api/qa/analyses/{analysis_id}/issue",
        description: "Create or link an idempotent consolidated GitLab issue",
        body: `{
  "project_id": "532",
  "title": "Endpoint control QA findings",
  "labels": ["qa", "endpoint-security"]
}`,
        example_response: `{ "web_url": "https://gitlab.invinsense.dev/...", "created": "created" }`,
        notes: "The issue description contains a deterministic run marker. Retries link to the existing issue instead of creating another one.",
      },
    ],
  },
  {
    title: "Agent Downloads",
    description: "Download the prevention testing agents",
    endpoints: [
      {
        method: "GET",
        path: "/api/agent/download",
        description: "Download the full agent bundle as a zip (PowerShell + Python)",
        example_response: `<binary zip file>
Contents:
  AtomicPrevention/
    AtomicPrevention.psm1
    AtomicPrevention.psd1
    Public/Invoke-AtomicPrevention.ps1
    Public/Test-Prevention.ps1
    Public/Test-DriverLoad.ps1
    Public/Send-Results.ps1
    Public/New-EvasionTest.ps1
    Private/Get-ExecutionVerdict.ps1
    Private/Write-TestLog.ps1
    atomic_prevention_runner.py`,
      },
      {
        method: "GET",
        path: "/api/agent/download-python",
        description: "Download just the Python agent (single file, zero dependencies)",
        example_response: `<python file>
Usage: python3 atomic_prevention_runner.py --playbook ./playbook.json
       python3 atomic_prevention_runner.py -p ./pb.json --server http://server:3000
       python3 atomic_prevention_runner.py -p ./pb.json --dry-run`,
        notes: "Single-file Python 3.8+ script. No pip install needed. Supports macOS (Gatekeeper/TCC detection) and Linux (AppArmor/SELinux detection).",
      },
    ],
  },
];


// Method word is the label; colour is the existing status vocabulary (read = ok, write = degraded).
function MethodBadge({ method }: { method: string }) {
  const tone = method === "GET" ? "border-status-ok/40 bg-status-ok/10 text-status-ok-text" : "border-status-degraded/50 bg-status-degraded/15 text-status-degraded-text";
  return <span className={`inline-block w-12 rounded-sm border py-0.5 text-center font-mono text-xs font-semibold ${tone}`}>{method}</span>;
}

function Block({ children }: { children: string }) {
  return <pre className="code-block max-h-96 overflow-y-auto">{children}</pre>;
}

function Heading({ children }: { children: string }) {
  return <h4 className="mb-2 text-xs font-semibold text-muted-foreground">{children}</h4>;
}

function EndpointCard({ endpoint, baseUrl }: { endpoint: Endpoint; baseUrl: string }) {
  const [open, setOpen] = useState(false);
  const [live, setLive] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const isDownload = endpoint.path.startsWith("/api/agent/download");
  const canTry = endpoint.method === "GET" && !endpoint.path.includes("{") && !isDownload;

  const tryIt = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}${endpoint.path}`);
      setLive(JSON.stringify(await res.json(), null, 2));
    } catch (e) {
      setLive(`Request failed: ${e instanceof Error ? e.message : e}`);
    } finally {
      setLoading(false);
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(live || endpoint.example_response);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard blocked (non-secure origin): button simply does not confirm */
    }
  };

  const curl =
    endpoint.method === "GET"
      ? isDownload ? `curl -fLJO ${baseUrl}${endpoint.path}` : `curl -s ${baseUrl}${endpoint.path} | python3 -m json.tool`
      : `curl -s -X POST ${baseUrl}${endpoint.path} \\\n  -H "Content-Type: application/json" \\\n  -d '${endpoint.body?.replace(/\n\s*/g, " ").replace(/'/g, "\\'") || "{}"}'`;

  return (
    <div className="surface overflow-hidden">
      <button onClick={() => setOpen(!open)} aria-expanded={open} className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-muted">
        {open ? <CaretDown size={16} aria-hidden /> : <CaretRight size={16} aria-hidden />}
        <MethodBadge method={endpoint.method} />
        <code className="font-mono text-data">{endpoint.path}</code>
        <span className="ml-auto hidden text-xs text-muted-foreground lg:block">{endpoint.description}</span>
      </button>

      {open && (
        <div className="space-y-4 border-t border-border bg-muted/40 p-4">
          <p className="text-sm">{endpoint.description}</p>
          {endpoint.params && (
            <div>
              <Heading>Parameters</Heading>
              <dl className="space-y-1 text-xs">
                {endpoint.params.map((p) => (
                  <div key={p.name} className="flex flex-wrap items-baseline gap-x-3">
                    <dt className="font-mono text-data text-primary-accent">{p.name}</dt>
                    <dd className="text-muted-foreground">{p.type}{p.required ? ", required" : ""}. {p.description}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
          {endpoint.body && <div><Heading>Request body</Heading><Block>{endpoint.body}</Block></div>}
          {endpoint.notes && <p className="rounded-md border border-border bg-card p-3 text-xs text-muted-foreground">{endpoint.notes}</p>}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <Heading>{live ? "Live response" : "Example response"}</Heading>
              <div className="flex gap-2">
                {canTry && <Button size="sm" icon={Play} loading={loading} onClick={tryIt}>Try it</Button>}
                <Button size="sm" variant="ghost" icon={copied ? Check : Copy} onClick={copy} aria-label="Copy response">{copied ? "Copied" : "Copy"}</Button>
              </div>
            </div>
            <Block>{live || endpoint.example_response}</Block>
          </div>
          <div><Heading>cURL</Heading><Block>{curl}</Block></div>
        </div>
      )}
    </div>
  );
}

export default function DocsPage() {
  const [baseUrl, setBaseUrl] = useState(API_BASE || "http://localhost:3000");

  useEffect(() => {
    document.title = "API Docs · Atomic Prevention";
    if (!API_BASE) setBaseUrl(window.location.origin);
  }, []);

  return (
    <>
      <PageHeader title="API docs" description="Every endpoint returns JSON." />
      <p className="text-sm text-muted-foreground">
        Base URL <code className="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-data text-foreground">{baseUrl}</code>
      </p>
      <p className="flex flex-wrap gap-x-5 gap-y-1 text-label font-medium">
        <a href={`${API_BASE}/api/docs`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-primary-accent hover:underline"><ArrowSquareOut size={14} aria-hidden />OpenAPI (Swagger UI)</a>
        <a href={`${API_BASE}/api/redoc`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-primary-accent hover:underline"><ArrowSquareOut size={14} aria-hidden />ReDoc</a>
      </p>

      {API_SECTIONS.map((s) => (
        <section key={s.title} className="space-y-3" aria-labelledby={`s-${s.title}`}>
          <div>
            <h2 id={`s-${s.title}`} className="text-lg font-semibold">{s.title}</h2>
            <p className="text-sm text-muted-foreground">{s.description}</p>
          </div>
          <div className="space-y-2">
            {s.endpoints.map((e) => <EndpointCard key={`${e.method}-${e.path}`} endpoint={e} baseUrl={baseUrl} />)}
          </div>
        </section>
      ))}

      <section className="surface space-y-3 p-4" aria-labelledby="e2e-h">
        <h2 id="e2e-h" className="text-lg font-semibold">End-to-end workflow</h2>
        <div><Heading>1. Sync data sources</Heading><Block>{`for src in lolbas atomic-red-team loldrivers lolrmm loobins gtfobins loas sysinternals; do\n  curl -s -X POST ${baseUrl}/api/sources/$src/sync\ndone`}</Block></div>
        <div><Heading>2. Generate a playbook for Volt Typhoon</Heading><Block>{`curl -s -X POST ${baseUrl}/api/playbooks/generate \\\n  -H "Content-Type: application/json" \\\n  -d '{"adversary_group_id": "G1017", "platforms": ["windows"]}'`}</Block></div>
        <div><Heading>3. Export and run on the target</Heading><Block>{`curl -s ${baseUrl}/api/playbooks/<id>/export > playbook.json\n\n# Windows\nImport-Module .\\AtomicPrevention\\AtomicPrevention.psm1\nInvoke-AtomicPrevention -Playbook .\\playbook.json -ServerUrl ${baseUrl}\n\n# macOS and Linux\npython3 atomic_prevention_runner.py --playbook ./playbook.json --server ${baseUrl}`}</Block></div>
      </section>
    </>
  );
}
