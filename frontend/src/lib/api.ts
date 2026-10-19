export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ||
  (process.env.NODE_ENV === "development" ? "http://localhost:8000" : "");

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    ...options,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `API error: ${res.status}`);
  }

  return res.json();
}

// ---- Types ----

export interface Technique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  sources: string[];
  url: string;
  tests?: PreventionTest[];
}

export interface PreventionTest {
  id: string;
  technique_id: string;
  source: string;
  name: string;
  description: string;
  command: string;
  executor: string;
  cleanup_command: string;
  elevation_required: boolean;
  binary_path: string;
  risk_level: string;
  platforms: string[];
  runnable?: boolean;
  readiness_reasons?: string[];
}

export interface AdversaryGroup {
  id: string;
  name: string;
  description: string;
  aliases: string[];
  technique_count: number;
  url: string;
  techniques?: { id: string; name: string; tactics: string[]; platforms: string[] }[];
}

export interface PlaybookSummary {
  id: string;
  name: string;
  adversary_group_name: string | null;
  technique_count: number;
  test_count: number;
  created_at: string | null;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  adversary_group_id: string | null;
  adversary_group_name: string | null;
  technique_ids: string[];
  test_ids: string[];
  metadata: Record<string, unknown>;
  created_at: string | null;
}

export interface PlaybookRunSummary {
  id: string;
  hostname: string;
  started_at: string | null;
  summary: { blocked: number; allowed: number; error: number };
}

export interface TestResultItem {
  id: string;
  test_id: string;
  verdict: "blocked" | "allowed" | "error";
  exit_code: number | null;
  error_message: string | null;
  execution_time_ms: number;
}

export interface RunDetail {
  id: string;
  playbook_id: string;
  hostname: string;
  started_at: string | null;
  completed_at: string | null;
  summary: { blocked: number; allowed: number; error: number };
  results: TestResultItem[];
}

export interface Source {
  id: string;
  name: string;
  description: string;
  repo_url: string;
  platform: string;
  test_count: number;
}

export interface GeneratePlaybookRequest {
  adversary_group_id?: string;
  adversary_group_name?: string;
  technique_ids?: string[];
  name?: string;
  platforms?: string[];
  custom_payloads?: { url?: string; name?: string; executor?: string; technique_id?: string }[];
}

export interface PreventionStats {
  prevention_score: number;
  total_blocked: number;
  total_allowed: number;
  total_error: number;
  total_runs: number;
}

export interface TechniqueStats {
  total_techniques: number;
  total_tests: number;
}

export interface AdversaryStats {
  total_groups: number;
}

export interface PlaybookStats {
  total_playbooks: number;
  total_runs: number;
}

export interface DashboardStats {
  techniques: TechniqueStats;
  adversaries: AdversaryStats;
  playbooks: PlaybookStats;
  sources: Source[];
}

// ---- Techniques ----

export interface TechniqueParams {
  tactic?: string;
  platform?: string;
  source?: string;
  search?: string;
  skip?: number;
  limit?: number;
}

export async function fetchTechniques(
  params: TechniqueParams = {}
): Promise<{ techniques: Technique[]; total: number }> {
  const sp = new URLSearchParams();
  if (params.tactic) sp.set("tactic", params.tactic);
  if (params.platform) sp.set("platform", params.platform);
  if (params.source) sp.set("source", params.source);
  if (params.search) sp.set("search", params.search);
  if (params.skip !== undefined) sp.set("skip", String(params.skip));
  if (params.limit !== undefined) sp.set("limit", String(params.limit));

  const qs = sp.toString();
  return apiFetch(`/api/techniques${qs ? `?${qs}` : ""}`);
}

export async function fetchAllTechniques(
  params: Omit<TechniqueParams, "skip" | "limit"> = {}
): Promise<Technique[]> {
  const limit = 200;
  const first = await fetchTechniques({ ...params, skip: 0, limit });
  const techniques = [...first.techniques];
  // Remaining pages are independent once the total is known; fetch them in parallel.
  const skips: number[] = [];
  for (let skip = limit; skip < first.total; skip += limit) skips.push(skip);
  const rest = await Promise.all(skips.map((skip) => fetchTechniques({ ...params, skip, limit })));
  for (const page of rest) techniques.push(...page.techniques);
  return techniques;
}

export async function fetchTechnique(id: string, platform?: string): Promise<Technique> {
  const params = platform ? `?platform=${encodeURIComponent(platform)}` : "";
  return apiFetch(`/api/techniques/${encodeURIComponent(id)}${params}`);
}

// ---- Adversaries ----

export async function fetchAdversaries(
  params: { search?: string; skip?: number; limit?: number } = {}
): Promise<{ adversaries: AdversaryGroup[]; total: number }> {
  const sp = new URLSearchParams();
  if (params.search) sp.set("search", params.search);
  if (params.skip !== undefined) sp.set("skip", String(params.skip));
  if (params.limit !== undefined) sp.set("limit", String(params.limit));

  const qs = sp.toString();
  return apiFetch(`/api/adversaries${qs ? `?${qs}` : ""}`);
}

export async function fetchAdversary(id: string): Promise<AdversaryGroup> {
  return apiFetch(`/api/adversaries/${encodeURIComponent(id)}`);
}

// ---- Playbooks ----

export async function fetchPlaybooks(): Promise<{
  playbooks: PlaybookSummary[];
}> {
  return apiFetch("/api/playbooks");
}

export async function fetchPlaybook(id: string): Promise<Playbook> {
  return apiFetch(`/api/playbooks/${encodeURIComponent(id)}`);
}

export async function generatePlaybook(
  request: GeneratePlaybookRequest
): Promise<Playbook> {
  return apiFetch("/api/playbooks/generate", {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export async function exportPlaybook(
  id: string
): Promise<Record<string, unknown>> {
  return apiFetch(`/api/playbooks/${encodeURIComponent(id)}/export`);
}

// ---- Results ----

export async function submitResults(data: {
  playbook_id: string;
  hostname: string;
  results: {
    test_id: string;
    verdict: string;
    exit_code?: number;
    error_message?: string;
    execution_time_ms?: number;
  }[];
}): Promise<{ run_id: string; summary: Record<string, number> }> {
  return apiFetch("/api/results/submit", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function uploadResultsFile(
  file: File
): Promise<{ run_id: string; summary: Record<string, number>; filename: string }> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/api/results/upload`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Upload failed: ${res.status}`);
  }

  return res.json();
}

export async function fetchRunResults(runId: string): Promise<RunDetail> {
  return apiFetch(`/api/results/runs/${encodeURIComponent(runId)}`);
}

export async function fetchPlaybookRuns(
  playbookId: string
): Promise<{ runs: PlaybookRunSummary[] }> {
  return apiFetch(
    `/api/results/playbook/${encodeURIComponent(playbookId)}`
  );
}

// ---- Sources ----

export async function fetchSources(): Promise<{ sources: Source[] }> {
  return apiFetch("/api/sources");
}

export async function syncSource(
  id: string
): Promise<{ source: string; tests_persisted: number; techniques_updated: number }> {
  return apiFetch(`/api/sources/${encodeURIComponent(id)}/sync`, {
    method: "POST",
  });
}

// ---- Prevention Stats ----

export async function fetchPreventionStats(): Promise<PreventionStats> {
  return apiFetch("/api/results/stats");
}

export async function fetchTechniqueVerdicts(): Promise<Record<string, "blocked" | "allowed" | "untested">> {
  const data = await apiFetch<{ verdicts: Record<string, "blocked" | "allowed" | "untested"> }>("/api/results/verdicts");
  return data.verdicts;
}

// ---- Stats (aggregated) ----

export async function fetchStats(): Promise<DashboardStats> {
  const [techniques, adversaries, playbooks, sourcesData] = await Promise.all([
    apiFetch<TechniqueStats>("/api/techniques/stats"),
    apiFetch<AdversaryStats>("/api/adversaries/stats"),
    apiFetch<PlaybookStats>("/api/playbooks/stats"),
    apiFetch<{ sources: Source[] }>("/api/sources"),
  ]);

  return {
    techniques,
    adversaries,
    playbooks,
    sources: sourcesData.sources,
  };
}
