import csv
import json
from pathlib import Path

from agent.import_art_uec_report import build_payload


def test_completed_kit_report_becomes_detected_and_allowed_results(tmp_path: Path):
    report = tmp_path / "report"
    report.mkdir()
    (report / "summary.json").write_text(json.dumps({
        "host": "kernel=6.8\nhost=kit-host\n",
        "performance": {"atomic tests": {"agent_cpu_avg": 4.2}},
    }))
    (report / "performance_phases.json").write_text(json.dumps({
        "atomic tests": {"agent_cpu_avg": 4.2, "agent_rss_max": 180}
    }))
    (report / "agent_health.json").write_text(json.dumps({"agent_went_silent": False}))
    with (report / "per_test.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "technique", "test", "name", "executor", "executed", "exec_status",
            "verdict", "attack_rc", "duration_s", "failing_commands",
            "first_error_line", "rules", "first_finding_latency_s", "output_file",
        ])
        writer.writeheader()
        writer.writerow({
            "technique": "T1059.004", "test": "1", "name": "Shell test",
            "executor": "sh", "executed": "True", "exec_status": "OK",
            "verdict": "DETECTED - correct technique", "attack_rc": "0",
            "duration_s": "0.4", "failing_commands": "id", "first_error_line": "",
            "rules": "Sigma: Shell", "first_finding_latency_s": "0.1",
            "output_file": "",
        })
        writer.writerow({
            "technique": "T1070.004", "test": "2", "name": "Delete file",
            "executor": "sh", "executed": "True", "exec_status": "OK",
            "verdict": "not detected", "attack_rc": "0", "duration_s": "0.2",
            "failing_commands": "rm", "first_error_line": "", "rules": "",
            "first_finding_latency_s": "", "output_file": "",
        })
        writer.writerow({
            "technique": "T9999", "test": "3", "name": "Manual",
            "executor": "manual", "executed": "False", "exec_status": "NOT RUN",
            "verdict": "not run", "attack_rc": "", "duration_s": "",
            "failing_commands": "", "first_error_line": "", "rules": "",
            "first_finding_latency_s": "", "output_file": "",
        })

    payload = build_payload(tmp_path, "kit-import")
    assert payload["hostname"] == "kit-host"
    assert payload["performance"]["atomic tests"]["agent_rss_max"] == 180
    assert [result["verdict"] for result in payload["results"]] == ["detected", "allowed"]
    assert payload["results"][0]["technique_id"] == "T1059.004"
