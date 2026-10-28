#!/usr/bin/env python3
"""Import a completed ART + UEC detection-kit report into Atomic Prevention.

The kit is intentionally fast while tests execute and performs its expensive
report correlation at completion. This importer consumes the completed report
artifacts and submits their per-test verdicts, UEC agent health, and benchmark
phases to the Atomic Prevention QA console.

Usage:
  python3 import_art_uec_report.py --results-dir ./results/run --server http://server:3000
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _hostname(summary: dict[str, Any], report_dir: Path) -> str:
    host = str(summary.get("host", ""))
    match = re.search(r"(?im)^host=([^\n]+)$", host)
    if match:
        return match.group(1).strip()
    # The report is normally generated in <results>/report.
    return report_dir.parent.parent.name or "unknown-kit-host"


def _verdict(row: dict[str, str]) -> str:
    kit_verdict = row.get("verdict", "").lower()
    executed = row.get("executed", "").strip().lower() == "true"
    if kit_verdict.startswith("detected"):
        return "detected"
    if not executed:
        return "error"
    exec_status = row.get("exec_status", "").upper()
    if exec_status in {"PREREQ FAILED", "TOOL MISSING"} or exec_status.startswith("TIMEOUT"):
        return "error"
    return "allowed"


def _safe_int(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _read_output(results_root: Path, relative_path: str) -> str:
    if not relative_path:
        return ""
    path = results_root / relative_path
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:16_000]
    except OSError:
        return ""


def _tests(report_dir: Path, results_root: Path) -> list[dict[str, Any]]:
    path = report_dir / "per_test.csv"
    if not path.exists():
        return []
    tests: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                technique = row.get("technique", "").strip()
                test_number = row.get("test", "").strip()
                if not technique or not test_number:
                    continue
                verdict = _verdict(row)
                if verdict == "error" and row.get("verdict", "").strip().lower() == "not run":
                    # Preserve not-run rows as local debug evidence, but do not
                    # submit them as executable control verdicts.
                    continue
                output = _read_output(results_root, row.get("output_file", ""))
                error_line = row.get("first_error_line", "")
                tests.append({
                    "test_id": f"art-kit:{technique}:t{test_number}",
                    "technique_id": technique,
                    "test_name": row.get("name") or f"{technique} test {test_number}",
                    "source": "art-uec-kit",
                    "command": row.get("failing_commands", ""),
                    "executor": row.get("executor", "bash"),
                    "verdict": verdict,
                    "exit_code": _safe_int(row.get("attack_rc")),
                    "error_message": error_line or row.get("why_failed") or None,
                    "execution_time_ms": _safe_int(row.get("duration_s") or 0) or 0,
                    "stdout": output,
                    "stderr": error_line,
                    "agent_logs": [{
                        "source": "art-uec-kit",
                        "phase": "report_import",
                        "level": "info" if verdict == "detected" else "warning",
                        "message": row.get("verdict", ""),
                        "rules": row.get("rules", ""),
                        "latency_s": row.get("first_finding_latency_s", ""),
                    }],
                })
    except OSError:
        return []
    return tests


def build_payload(results_root: Path, name: str | None) -> dict[str, Any]:
    report_dir = results_root / "report"
    summary = _read_json(report_dir / "summary.json")
    performance = _read_json(report_dir / "performance_phases.json")
    agent_health = _read_json(report_dir / "agent_health.json")
    tests = _tests(report_dir, results_root)
    if not tests and not summary:
        raise SystemExit(f"No completed kit report found under {report_dir}")

    return {
        "playbook_id": name or f"art-uec-kit:{results_root.name}",
        "hostname": _hostname(summary, report_dir),
        "started_at": summary.get("started_at") or datetime.now(timezone.utc).isoformat(),
        "completed_at": summary.get("completed_at") or datetime.now(timezone.utc).isoformat(),
        "platform": "linux",
        "os_version": str(summary.get("host", ""))[:8_000],
        "agent_name": "art-uec-kit",
        "agent_version": "art-uec-kit",
        "performance": performance or summary.get("performance", {}),
        "sensor_logs": [{
            "source": "uec-agent-health",
            "level": "error" if (
                agent_health.get("agent_went_silent")
                or agent_health.get("too_large")
                or agent_health.get("valhalla_failed")
            ) else "info",
            "message": "Imported completed detection-kit agent health report.",
            "data": agent_health,
        }],
        "debug_logs": [{
            "source": "art-uec-kit",
            "phase": "report_import",
            "level": "info",
            "message": "Imported completed ART + UEC detection-kit report.",
            "summary": summary,
        }],
        "results": tests,
    }


def submit(server: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not server:
        raise SystemExit("A server URL is required unless --dry-run is used")
    request = urllib.request.Request(
        server.rstrip("/") + "/api/results/submit",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:1000]
        raise SystemExit(f"Upload failed with HTTP {exc.code}: {body}") from exc
    except (urllib.error.URLError, ValueError) as exc:
        raise SystemExit(f"Upload failed: {exc}") from exc


def analyze(server: str, run_id: str) -> None:
    request = urllib.request.Request(
        server.rstrip("/") + f"/api/qa/runs/{run_id}/analyze",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            response.read()
    except (urllib.error.URLError, ValueError) as exc:
        print(f"QA analysis request failed: {exc}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True, help="Kit results directory containing report/")
    parser.add_argument("--server", help="Atomic Prevention base URL")
    parser.add_argument("--name", help="Stable playbook/run-set name")
    parser.add_argument("--analyze", action="store_true", help="Run QA analysis after upload")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    payload = build_payload(Path(args.results_dir).resolve(), args.name)
    print(f"Prepared {len(payload['results'])} test results from {payload['hostname']}")
    if args.dry_run:
        print(json.dumps(payload, indent=2)[:20_000])
        return
    response = submit(args.server, payload)
    print(f"Uploaded run {response.get('run_id')} with summary {response.get('summary')}")
    if args.analyze and response.get("run_id"):
        analyze(args.server, str(response["run_id"]))
        print("QA analysis requested; automatic GitLab issue creation follows server configuration.")


if __name__ == "__main__":
    main()
