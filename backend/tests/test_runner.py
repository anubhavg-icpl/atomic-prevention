from pathlib import Path

from agent.atomic_prevention_runner import _get_verdict, _parse_performance_csv, _run_test


def _test(command: str, prerequisites=None) -> dict:
    return {
        "id": "fixture",
        "name": "fixture",
        "technique_id": "T0000",
        "command": command,
        "executor": "bash",
        "runnable": True,
        "prerequisites": prerequisites or [],
    }


def test_passing_prerequisite_skips_getter(tmp_path: Path):
    ready = tmp_path / "ready"
    getter_ran = tmp_path / "getter-ran"
    main_ran = tmp_path / "main-ran"
    ready.touch()
    result = _run_test(_test(
        f"touch {main_ran}",
        [{
            "description": "ready",
            "executor": "bash",
            "check_command": f"test -f {ready}",
            "get_command": f"touch {getter_ran}",
        }],
    ), 5, "linux", prerequisite_timeout_seconds=5)

    assert result["verdict"] == "allowed"
    assert main_ran.exists()
    assert not getter_ran.exists()


def test_failed_recheck_returns_error_without_running_main(tmp_path: Path):
    main_ran = tmp_path / "main-ran"
    result = _run_test(_test(
        f"touch {main_ran}",
        [{
            "description": "never ready",
            "executor": "bash",
            "check_command": "exit 1",
            "get_command": "true",
        }],
    ), 5, "linux", prerequisite_timeout_seconds=5)

    assert result["verdict"] == "error"
    assert "remains unsatisfied" in result["error_message"]
    assert not main_ran.exists()


def test_nonzero_exit_without_block_evidence_is_error():
    result = _run_test(_test("command-that-does-not-exist"), 5, "linux")
    assert result["verdict"] == "error"
    assert result["exit_code"] == 127


def test_result_contains_bounded_timing_and_phase_logs(tmp_path: Path):
    marker = tmp_path / "marker"
    result = _run_test(_test(f"touch {marker}; echo runner-output"), 5, "linux")

    assert result["verdict"] == "allowed"
    assert result["started_at"]
    assert result["completed_at"]
    assert result["stdout"].strip() == "runner-output"
    assert any(entry.get("phase") == "execute" for entry in result["agent_logs"])
    assert any(entry.get("phase") == "verdict" for entry in result["agent_logs"])


def test_explicit_policy_denial_is_blocked():
    verdict, _ = _get_verdict(
        process_started=True,
        exit_code=1,
        timed_out=False,
        stderr_text="Execution was blocked by policy",
        stdout_text="",
        error_message=None,
        plat="linux",
    )
    assert verdict == "blocked"


def test_performance_csv_is_bounded_and_normalized(tmp_path: Path):
    path = tmp_path / "perf.csv"
    path.write_text(
        "ts_utc,load1,agent_cpu_pct,agent_rss_mb\n"
        "2026-10-27T12:00:00Z,0.50,2.25,175\n"
        "2026-10-27T12:00:02Z,0.75,4.50,176\n",
        encoding="utf-8",
    )
    report = _parse_performance_csv(path)
    assert report["available"] is True
    assert report["sample_count"] == 2
    assert report["summary"]["sensor_cpu_pct"]["average"] == 3.375
    assert report["samples"][0]["load_1m"] == 0.5
