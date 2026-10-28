# AI QA automation and issue tracking

Atomic Prevention provides one console workflow for authorised end-to-end control
validation:

1. Generate a playbook.
2. Execute it with the Python or PowerShell agent.
3. Capture command output, phase logs, UEC sensor logs, and sensor benchmarks.
4. Correlate allowed executions with authoritative UEC threat findings.
5. Review AI findings and evidence in the QA automation page.
6. Create idempotent GitLab issues in the configured UEC project.

## Verdicts

- **Blocked** — a prevention control stopped execution.
- **Detected** — execution completed, but UEC observed a matching threat finding.
- **Allowed** — execution completed without prevention or matching detection.
- **Error** — the test harness could not produce a control verdict.

The prevention score is `blocked / (blocked + detected + allowed)`. The
visibility score is `(blocked + detected) / (blocked + detected + allowed)`.
Keeping these scores separate prevents detection-only coverage from looking
like prevention.

## Evidence and benchmarks

Agents upload bounded, redacted:

- per-test command, executor, start/end time, exit code, stdout, and stderr;
- prerequisite, execution, verdict, cleanup, and UEC correlation logs;
- local UEC sensor log tails;
- UEC sensor CPU, RSS, host load, and host memory samples.

Set `UEC_SENSOR_LOG_PATH` to an explicit sensor log file, and
`UEC_SENSOR_LOG_LINES` to bound its tail. Set `ATOMIC_PREVENTION_PERF_FILE` to
reuse a numeric performance CSV produced by an existing UEC detection kit.
All values are truncated and credential patterns are replaced before storage,
AI analysis, UI display, or GitLab issue creation.

### Import an already-running ART + UEC detection kit

After an older kit finishes and writes its report, import its per-test verdicts,
agent health, and benchmark phases without waiting for another execution:

```bash
python3 agent/import_art_uec_report.py \
  --results-dir /path/to/kit/results/<run> \
  --server http://atomic-prevention:3000 \
  --name "UEC detection kit - Ubuntu 24.04" \
  --analyze
```

Use `--dry-run` first to inspect the normalized payload. The importer preserves
the kit's detection verdicts and treats executed-but-undetected tests as
allowed; not-run rows remain local evidence and are not submitted as control
verdicts.

## UEC integration

Configure the development tenant with:

```text
MA_UEC_ENABLED=true
MA_UEC_BASE_URL=https://platform-dev.invinsense.dev/xdr/uec
MA_UEC_TENANT=default
MA_UEC_USERNAME=...
MA_UEC_PASSWORD=...
```

A pre-issued access token may be used instead with `MA_UEC_TOKEN`. Correlation
uses the UEC threat-detection findings API, resolves the device by hostname,
filters findings to the execution interval, and matches the ATT&CK parent or
sub-technique. Only `allowed` is promoted to `detected`; blocked and error
verdicts never change.

## Claude analysis

Claude is optional and disabled by default:

```text
MA_CLAUDE_ENABLED=true
MA_ANTHROPIC_API_KEY=...
MA_ANTHROPIC_MODEL=claude-sonnet-4-5
MA_ANTHROPIC_MAX_TOKENS=700
```

The backend uses the Anthropic Messages API directly, pins Sonnet by default,
requests JSON, and persists input/output token usage. Claude never receives an
integration token and never performs a mutating action. If Claude is disabled
or unavailable, a deterministic reviewer produces an issue draft from the same
bounded evidence.

## GitLab issue tracking

Configure only through environment variables:

```text
MA_GITLAB_ENABLED=true
MA_GITLAB_URL=https://gitlab.invinsense.dev
MA_GITLAB_TOKEN=...
MA_GITLAB_DEFAULT_PROJECT=infopercept/xdr/uec/uec
```

The QA page can search accessible projects and create either one consolidated
issue or one issue per actionable finding. Set:

```text
MA_GITLAB_AUTO_CREATE_ISSUES=true
MA_GITLAB_AUTO_ISSUE_MODE=finding
```

to create issues automatically after an analysis. Every issue contains a
deterministic marker such as `atomic-prevention-run:<run id>`. The backend
checks its local issue table and searches GitLab before creating, so retries do
not duplicate the same issue.

## Deployment checklist

- Put every secret in `.env`, deployment secrets, or CI protected variables.
- Keep optional integrations disabled when their secrets are absent.
- Do not expose the write-capable QA endpoints publicly without an authentication proxy.
- Verify `/api/health`, `/api/integrations/status`, and a dry-run playbook.
- Run `python -m pytest -q`, `npm run typecheck`, and `npm run build` before deployment.
