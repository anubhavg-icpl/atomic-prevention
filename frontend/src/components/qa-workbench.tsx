"use client";

import { useEffect, useState, type FormEvent } from "react";
import { ArrowUpRight, MagnifyingGlass, Sparkle } from "@phosphor-icons/react";
import Button, { btn } from "./button";
import StatusDot from "./status-dot";
import {
  analyzeQaRun,
  createQaIssue,
  createQaIssues,
  fetchQaAnalysis,
  searchGitLabProjects,
  type GitLabIssueResult,
  type GitLabProject,
  type IntegrationStatus,
  type QaAnalysis,
} from "@/lib/api";
import { formatDate } from "@/lib/attack";
import { canonicalVerdict } from "@/lib/status";

export default function QaWorkbench({
  runId,
  integration,
}: {
  runId: string;
  integration: IntegrationStatus | null;
}) {
  const [analysis, setAnalysis] = useState<QaAnalysis | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisError, setAnalysisError] = useState("");
  const [projectQuery, setProjectQuery] = useState("");
  const [projects, setProjects] = useState<GitLabProject[]>([]);
  const [projectSearching, setProjectSearching] = useState(false);
  const [projectError, setProjectError] = useState("");
  const [selectedProject, setSelectedProject] = useState<GitLabProject | null>(null);
  const [issueTitle, setIssueTitle] = useState("");
  const [issueDescription, setIssueDescription] = useState("");
  const [issueLabels, setIssueLabels] = useState("");
  const [issueMode, setIssueMode] = useState<"consolidated" | "finding">("finding");
  const [creatingIssue, setCreatingIssue] = useState(false);
  const [issue, setIssue] = useState<GitLabIssueResult | null>(null);
  const [issues, setIssues] = useState<GitLabIssueResult[]>([]);
  const [issueError, setIssueError] = useState("");

  useEffect(() => {
    let active = true;
    setAnalysis(null);
    setAnalysisError("");
    setIssue(null);
    setIssueError("");

    fetchQaAnalysis(runId)
      .then((next) => {
        if (active) {
          setAnalysis(next);
          setIssue(next.gitlab_issues?.[0] ?? null);
        }
      })
      .catch((e) => {
        const message = e instanceof Error ? e.message : "";
        if (active && message && message !== "Analysis not found") {
          setAnalysisError(message);
        }
      });

    return () => {
      active = false;
    };
  }, [runId]);

  useEffect(() => {
    const draft = analysis?.result.issue;
    setIssueTitle(draft?.title ?? "");
    setIssueDescription(draft?.description ?? "");
    setIssueLabels(draft?.labels?.join(", ") ?? "");
  }, [analysis]);

  const analyze = async () => {
    setAnalysisLoading(true);
    setAnalysisError("");
    setIssue(null);
    setIssueError("");
    try {
      const next = await analyzeQaRun(runId);
      setAnalysis(next);
      setIssue(next.gitlab_issues?.[0] ?? null);
    } catch (e) {
      setAnalysisError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setAnalysisLoading(false);
    }
  };

  const searchProjects = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const query = projectQuery.trim();
    if (query.length < 2) {
      setProjectError("Enter at least two characters to search.");
      setProjects([]);
      return;
    }

    setProjectSearching(true);
    setProjectError("");
    try {
      const response = await searchGitLabProjects(query);
      setProjects(response.projects);
      if (!response.projects.some((project) => project.id === selectedProject?.id)) {
        setSelectedProject(response.projects[0] ?? null);
      }
    } catch (e) {
      setProjects([]);
      setSelectedProject(null);
      setProjectError(e instanceof Error ? e.message : "Project search failed");
    } finally {
      setProjectSearching(false);
    }
  };

  const createIssue = async () => {
    if (!analysis || !selectedProject) return;
    setCreatingIssue(true);
    setIssueError("");
    setIssue(null);
    setIssues([]);
    const labels = issueLabels
      .split(",")
      .map((label) => label.trim())
      .filter(Boolean);
    try {
      if (issueMode === "finding") {
        // Per-finding mode: server builds each issue from its finding, so the draft title/description are not sent.
        const response = await createQaIssues(analysis.id, { project_id: selectedProject.id, mode: "finding", labels });
        setIssues(response.issues);
      } else {
        setIssue(await createQaIssue(analysis.id, {
          project_id: selectedProject.id,
          title: issueTitle.trim() || undefined,
          description: issueDescription.trim() || undefined,
          labels,
        }));
      }
    } catch (e) {
      setIssueError(e instanceof Error ? e.message : "Issue creation failed");
    } finally {
      setCreatingIssue(false);
    }
  };

  const result = analysis?.result;
  const usage = result?.usage;
  const findings = result?.findings ?? [];

  return (
    <section className="surface space-y-5 p-4" aria-labelledby="qa-workbench-h">
      <div>
        <h2 id="qa-workbench-h" className="text-lg font-semibold">AI analysis and issue tracking</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          {integration?.claude.configured
            ? `Claude ${integration.claude.model} reviews the full run and creates an editable GitLab draft.`
            : "Claude is not configured, so analysis uses the built-in deterministic reviewer."}
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" icon={Sparkle} loading={analysisLoading} onClick={analyze}>
          Analyze run
        </Button>
        {analysis && (
          <span className="text-xs text-muted-foreground">
            {analysis.provider === "claude" ? `Claude · ${analysis.model}` : "Rules reviewer"} · {formatDate(analysis.created_at, true)}
          </span>
        )}
      </div>

      {analysisLoading && <p role="status" className="text-sm text-muted-foreground">Analyzing detections, logs, and UEC evidence.</p>}
      {analysisError && <p role="alert" className="text-sm text-status-error-text">{analysisError}</p>}

      {analysis && result && (
        <div className="space-y-4 rounded-md border border-border bg-muted p-3">
          <div className="flex flex-wrap items-center gap-3">
            {result.overall_status && (
              <StatusDot {...canonicalVerdict(result.overall_status)} />
            )}
            {result.confidence && <span className="text-xs text-muted-foreground">Confidence: {result.confidence}</span>}
            {usage && (
              <span className="text-xs tabular-nums text-muted-foreground">
                Tokens: {usage.input_tokens ?? 0} input · {usage.output_tokens ?? 0} output
              </span>
            )}
          </div>
          <p className="text-sm">{result.summary || analysis.summary}</p>
          {result.integration_notes?.length ? (
            <ul className="space-y-1 text-xs text-status-degraded-text">
              {result.integration_notes.map((note) => <li key={note}>{note}</li>)}
            </ul>
          ) : null}
          {findings.length > 0 && (
            <div>
              <h3 className="text-label font-semibold">Findings</h3>
              <ul className="mt-2 space-y-3">
                {findings.map((finding, index) => {
                  const status = canonicalVerdict(finding.status);
                  return (
                    <li key={`${finding.test_id || finding.title}-${index}`} className="rounded-md border border-border bg-card p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <StatusDot tone={status.tone} label={status.label} token={status.token} />
                        <span className="min-w-0 flex-1 truncate text-sm font-medium" title={finding.title}>{finding.title}</span>
                        {finding.severity && <span className="text-xs text-muted-foreground">{finding.severity} severity</span>}
                      </div>
                      {(finding.technique_id || finding.test_id) && (
                        <p className="mt-2 font-mono text-xs text-muted-foreground">
                          {[finding.technique_id, finding.test_id].filter(Boolean).join(" · ")}
                        </p>
                      )}
                      {finding.detail && <p className="mt-2 text-sm">{finding.detail}</p>}
                      {finding.recommendation && (
                        <p className="mt-2 text-sm text-muted-foreground"><span className="font-medium">Recommendation:</span> {finding.recommendation}</p>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </div>
      )}

      <form onSubmit={searchProjects} className="space-y-2">
        <label htmlFor="gitlab-project-search" className="text-label font-medium">GitLab project search</label>
        <div className="flex gap-2">
          <input
            id="gitlab-project-search"
            className="field"
            value={projectQuery}
            onChange={(event) => setProjectQuery(event.target.value)}
            placeholder="Search projects you can access"
            autoComplete="off"
            minLength={2}
          />
          <button type="submit" className={btn("secondary")} disabled={projectSearching} aria-busy={projectSearching}>
            <MagnifyingGlass size={16} aria-hidden />
            Search
          </button>
        </div>
        <p className="text-xs text-muted-foreground">Search uses the server-side GitLab token and never exposes it to this page.</p>
      </form>

      {projectSearching && <p role="status" className="text-sm text-muted-foreground">Searching GitLab projects.</p>}
      {projectError && <p role="alert" className="text-sm text-status-error-text">{projectError}</p>}

      {projects.length > 0 && (
        <fieldset className="space-y-2">
          <legend className="text-label font-medium">Select a project</legend>
          <ul className="max-h-64 space-y-2 overflow-y-auto pr-1">
            {projects.map((project) => (
              <li key={project.id}>
                <label className={`flex cursor-pointer gap-3 rounded-md border p-3 transition-colors ${selectedProject?.id === project.id ? "border-primary bg-primary/10" : "border-border hover:bg-muted"}`}>
                  <input
                    type="radio"
                    name="gitlab-project"
                    value={project.id}
                    checked={selectedProject?.id === project.id}
                    onChange={() => setSelectedProject(project)}
                    className="mt-1"
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{project.name}</span>
                    <span className="block truncate text-xs text-muted-foreground">{project.path_with_namespace}</span>
                    <span className="mt-1 block text-xs tabular-nums text-muted-foreground">
                      {project.open_issues_count} open issues · {formatDate(project.last_activity_at)}
                    </span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        </fieldset>
      )}

      {selectedProject && (
        <a href={selectedProject.web_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-sm text-primary-accent">
          View {selectedProject.path_with_namespace}
          <ArrowUpRight size={14} aria-hidden />
        </a>
      )}

      <div className="space-y-3">
        <h3 className="text-label font-semibold">Issue draft</h3>
        {!analysis ? (
          <p className="text-sm text-muted-foreground">Run the analysis before creating an issue.</p>
        ) : (
          <>
            <div>
              <label htmlFor="issue-title" className="text-label font-medium">Issue title</label>
              <input id="issue-title" className="field mt-1" value={issueTitle} onChange={(event) => setIssueTitle(event.target.value)} />
            </div>
            <div>
              <label htmlFor="issue-description" className="text-label font-medium">Issue description</label>
              <textarea
                id="issue-description"
                className="field mt-1 min-h-40 resize-y font-mono text-data"
                value={issueDescription}
                onChange={(event) => setIssueDescription(event.target.value)}
              />
            </div>
            <div>
              <label htmlFor="issue-labels" className="text-label font-medium">Issue labels</label>
              <input
                id="issue-labels"
                className="field mt-1"
                value={issueLabels}
                onChange={(event) => setIssueLabels(event.target.value)}
                placeholder="qa, endpoint-security"
              />
              <p className="mt-1 text-xs text-muted-foreground">Separate labels with commas.</p>
            </div>
            <fieldset>
              <legend className="text-label font-medium">Issue mode</legend>
              <div className="mt-1 flex flex-wrap gap-4 text-sm">
                <label className="flex items-center gap-2">
                  <input type="radio" name="issue-mode" checked={issueMode === "finding"} onChange={() => setIssueMode("finding")} />
                  One issue per finding
                </label>
                <label className="flex items-center gap-2">
                  <input type="radio" name="issue-mode" checked={issueMode === "consolidated"} onChange={() => setIssueMode("consolidated")} />
                  Single consolidated issue
                </label>
              </div>
            </fieldset>
            <Button loading={creatingIssue} disabled={!selectedProject} onClick={createIssue}>
              {issueMode === "finding" ? "Create GitLab issues" : "Create GitLab issue"}
            </Button>
            {!selectedProject && <p className="text-xs text-muted-foreground">Select a GitLab project first.</p>}
          </>
        )}
      </div>

      {issueError && <p role="alert" className="text-sm text-status-error-text">{issueError}</p>}
      {issues.length > 0 && (
        <ul role="status" className="space-y-1 text-sm text-status-ok-text">
          {issues.map((item) => (
            <li key={item.id}>
              {item.created === "created" ? "Created" : "Linked existing"}:{" "}
              <a href={item.web_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline">
                #{item.iid} {item.title}
                <ArrowUpRight size={14} aria-hidden />
              </a>
            </li>
          ))}
        </ul>
      )}
      {issue && (
        <p role="status" className="flex flex-wrap items-center gap-2 text-sm text-status-ok-text">
          {issue.created === "created" ? "Created issue" : "Linked an existing issue"}:
          <a href={issue.web_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline">
            Issue #{issue.iid}
            <ArrowUpRight size={14} aria-hidden />
          </a>
        </p>
      )}
    </section>
  );
}
