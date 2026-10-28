#!/usr/bin/env python3
"""
Atomic Prevention  Cross-Platform Prevention Validation Agent  v0.1.0

A single-file, zero-dependency Python agent that executes Atomic Prevention
prevention validation playbooks on macOS and Linux.

Usage:
    python3 atomic_prevention_runner.py --playbook ./my-playbook.json
    python3 atomic_prevention_runner.py --playbook ./my-playbook.json --server http://server:3000
    python3 atomic_prevention_runner.py --playbook ./my-playbook.json --dry-run

DISCLAIMER: Atomic Prevention is an authorized prevention validation tool. It
executes benign indicators of adversary techniques to test whether your
endpoint security controls correctly block them. Only run this tool on
systems where you have explicit authorization to perform security testing.
The authors assume no liability for unauthorized use.

Requires: Python 3.8+  (stdlib only -- no pip install needed)
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# ANSI colour helpers (disabled when stdout is not a TTY or NO_COLOR is set)
# ---------------------------------------------------------------------------
_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR", "") != ""

_RESET = "" if _NO_COLOR else "\033[0m"
_BOLD = "" if _NO_COLOR else "\033[1m"
_DIM = "" if _NO_COLOR else "\033[2m"

_GREEN = "" if _NO_COLOR else "\033[32m"
_RED = "" if _NO_COLOR else "\033[31m"
_YELLOW = "" if _NO_COLOR else "\033[33m"
_CYAN = "" if _NO_COLOR else "\033[36m"
_WHITE = "" if _NO_COLOR else "\033[37m"
_DARK_GRAY = "" if _NO_COLOR else "\033[90m"
_DARK_GREEN = "" if _NO_COLOR else "\033[32;2m"
_DARK_CYAN = "" if _NO_COLOR else "\033[36;2m"
_DARK_YELLOW = "" if _NO_COLOR else "\033[33;2m"


def _c(text: str, color: str) -> str:
    """Wrap *text* in ANSI colour codes."""
    return f"{color}{text}{_RESET}"


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
def _current_platform() -> str:
    """Return a normalised platform tag: 'macos', 'linux', or 'windows'."""
    s = sys.platform.lower()
    if s.startswith("darwin"):
        return "macos"
    if s.startswith("linux"):
        return "linux"
    if s.startswith("win"):
        return "windows"
    return s


def _os_version() -> str:
    """Return a human-readable OS version string."""
    try:
        return platform.platform()
    except Exception:
        return f"{sys.platform} (details unavailable)"


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _is_root() -> bool:
    """Return True if the current user has root / admin privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows
        return False


# ---------------------------------------------------------------------------
# Verdict detection
# ---------------------------------------------------------------------------

# Patterns that, when found in stderr, indicate a security control blocked
# the process.  Order does not matter -- we check all of them.
_BLOCK_PATTERNS_COMMON: List[str] = [
    "permission denied",
    "operation not permitted",
    "blocked by policy",
    "was blocked",
    "blocked:",
    "quarantined",
    "access denied",
    "malicious content",
    "not allowed to run",
    "code integrity",
    "applocker",
]

_BLOCK_PATTERNS_MACOS: List[str] = [
    "gatekeeper",
    "malware",
    "translocated",
    "xprotect",
    "tcc",
    "privacy preferences",
    "not verified",
    "cannot be opened because",
    "unidentified developer",
    "damaged and can't be opened",
    "macOS cannot verify",
    "com.apple.quarantine",
    "killed: 9",  # SIGKILL from TCC / sandbox
]

_BLOCK_PATTERNS_LINUX: List[str] = [
    "apparmor",
    "selinux",
    "seccomp",
    "avc:",  # SELinux AVC denial
    "operation not allowed",
    "permission denied",
    "bad system call",  # seccomp SIGSYS
]

# Signals that indicate a security kill
_BLOCK_SIGNALS: set = {
    signal.SIGKILL,  # 9  -- TCC / sandbox kill on macOS
}
_DETECT_PATTERNS: List[Tuple[str, str]] = [
    (r"(?<!not )\bdetected\b", "detected"),
    (r"(?<!no )\bdetection\b", "detection"),
    (r"(?<!not )\balerted\b", "alerted"),
    (r"\balert triggered\b", "alert triggered"),
    (r"(?<!not )\bsuspicious\b", "suspicious"),
    (r"\bthreat found\b", "threat found"),
    (r"\bsigma match\b", "sigma match"),
    (r"\bpolicy audit\b", "policy audit"),
    (r"\baudit event\b", "audit event"),
]
if hasattr(signal, "SIGSYS"):
    _BLOCK_SIGNALS.add(signal.SIGSYS)  # 31 -- seccomp


def _stderr_matches_block(stderr_text: str, plat: str) -> Tuple[bool, Optional[str]]:
    """Check *stderr_text* for known block indicators.

    Returns (is_blocked, matched_pattern_or_None).
    """
    lower = stderr_text.lower()

    patterns = list(_BLOCK_PATTERNS_COMMON)
    if plat == "macos":
        patterns.extend(_BLOCK_PATTERNS_MACOS)
    elif plat == "linux":
        patterns.extend(_BLOCK_PATTERNS_LINUX)

    for pat in patterns:
        if pat in lower:
            return True, pat

    return False, None


def _output_matches_detection(text: str) -> Tuple[bool, Optional[str]]:
    lower = text.lower()
    for pattern, label in _DETECT_PATTERNS:
        try:
            if re.search(pattern, lower):
                return True, label
        except re.error:
            continue
    return False, None


def _get_verdict(
    *,
    process_started: bool,
    exit_code: Optional[int],
    timed_out: bool,
    stderr_text: str,
    stdout_text: str,
    error_message: Optional[str],
    plat: str,
) -> Tuple[str, str]:
    """Determine verdict for a single test execution.

    Returns (verdict, reason) where verdict is one of
    'blocked', 'detected', 'allowed', or 'error'.

    The logic mirrors the PowerShell agent's Get-ExecutionVerdict but adds
    platform-specific checks for macOS (Gatekeeper, TCC, quarantine) and
    Linux (AppArmor, SELinux, seccomp).
    """

    # ------------------------------------------------------------------
    # Case 1: Process failed to start entirely
    # ------------------------------------------------------------------
    if not process_started:
        reason = error_message or "Process failed to start"

        # Check the error message for block indicators
        block_found, matched = _stderr_matches_block(reason, plat)
        if block_found:
            return "blocked", f"Security control prevented execution ({matched}): {reason}"

        # FileNotFoundError / PermissionError from subprocess are often
        # the result of application-control policies removing or
        # quarantining the binary.
        err_lower = reason.lower()
        if any(kw in err_lower for kw in ("permission", "errno 13", "errno 1")):
            return "blocked", f"Security control prevented execution: {reason}"
        detected, matched = _output_matches_detection(reason)
        if detected:
            return "detected", f"Detection indicator observed without a block ({matched}): {reason}"

        return "error", f"Process failed to start (non-security): {reason}"

    # Always inspect process output, even when the exit code or timeout state
    # looks benign. Security tools can report an event without changing the
    # process exit code. Block evidence remains more specific than a
    # detection-only indicator.
    #
    # First, always check output for block patterns even when exit code
    # looks "normal".  Some security tools write denial messages to
    # stderr but still allow the process to exit 0.
    evidence_text = f"{stderr_text}\n{stdout_text}"
    if evidence_text.strip():
        block_found, matched = _stderr_matches_block(evidence_text, plat)
        if block_found:
            return "blocked", f"Security control indicator observed ({matched})"

    detected, detected_pattern = _output_matches_detection(evidence_text)
    if detected:
        return "detected", f"Detection indicator observed without a block ({detected_pattern})"

    # ------------------------------------------------------------------
    # Case 2: Process started but timed out
    # ------------------------------------------------------------------
    if timed_out:
        # The process was able to run -- it was not blocked.
        return "allowed", "Process was still running after timeout (not blocked)"

    # ------------------------------------------------------------------
    # Case 3: Process started and exited -- inspect exit code
    # ------------------------------------------------------------------

    if exit_code is None:
        return "error", "Process started but exit code could not be determined"

    if exit_code == 0:
        return "allowed", f"Process exited successfully with code {exit_code}"

    # Check for negative exit codes (killed by signal on Unix)
    if exit_code < 0:
        sig = -exit_code
        if sig in {s.value if hasattr(s, "value") else s for s in _BLOCK_SIGNALS}:
            sig_name = "unknown"
            try:
                sig_name = signal.Signals(sig).name
            except (ValueError, AttributeError):
                pass
            return "blocked", f"Process killed by signal {sig} ({sig_name}) -- likely security control"
        return "error", f"Test command was interrupted by signal {-exit_code}"

    return "error", (
        f"Test command failed with exit code {exit_code} without prevention evidence"
    )


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------

def _resolve_shell(executor: str, plat: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """Return (shell_prefix, error) for a given executor on this platform.

    The prefix is a list that will be prepended to the command string, or
    None on error (with the error description as the second element).
    """
    ex = executor.lower()

    if ex in ("sh", "bash", "command_prompt", "cmd"):
        shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
        return [shell, "-c"], None
    if ex == "zsh":
        return ["/bin/zsh", "-c"], None
    if ex in ("powershell", "pwsh"):
        # Try pwsh (PowerShell Core) which is available cross-platform
        for candidate in ("pwsh", "/usr/local/bin/pwsh", "/usr/bin/pwsh"):
            if _which(candidate):
                return [candidate, "-NoProfile", "-NonInteractive", "-Command"], None
        return None, "PowerShell (pwsh) not found on this system"

    # Default: try to use /bin/sh -c
    return ["/bin/sh", "-c"], None


def _which(name: str) -> Optional[str]:
    """Poor-man's shutil.which for Python 3.8 compat (shutil.which exists
    since 3.3, but we re-implement to avoid import issues on restricted
    systems)."""
    import shutil
    return shutil.which(name)


def _execute_command(
    command: str, executor: str, timeout_seconds: int, plat: str
) -> Dict[str, Any]:
    """Execute a raw command and return process facts without a verdict."""
    raw: Dict[str, Any] = {
        "process_started": False,
        "timed_out": False,
        "exit_code": None,
        "error_message": None,
        "execution_time_ms": 0,
        "stdout": "",
        "stderr": "",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "agent_logs": [],
    }
    shell_prefix, shell_err = _resolve_shell(executor, plat)
    if shell_err or not shell_prefix:
        raw["error_message"] = shell_err or f"Unsupported executor: {executor}"
        return raw

    cmd_list = shell_prefix + [command]
    process_started = False
    timed_out = False
    error_message: Optional[str] = None
    stderr_text = ""

    start_time = time.monotonic()

    try:
        proc = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            # Do not let the child inherit our signals -- we manage
            # cleanup ourselves.
            preexec_fn=os.setpgrp if hasattr(os, "setpgrp") else None,
        )
        process_started = True
        raw["exit_code"] = proc.returncode

        try:
            raw["stdout"] = proc.stdout.decode("utf-8", errors="replace")[:4096]
        except Exception:
            raw["stdout"] = ""
        try:
            stderr_text = proc.stderr.decode("utf-8", errors="replace")[:4096]
            raw["stderr"] = stderr_text
        except Exception:
            stderr_text = ""

    except subprocess.TimeoutExpired:
        process_started = True
        timed_out = True

    except PermissionError as exc:
        error_message = f"PermissionError: {exc}"

    except FileNotFoundError as exc:
        error_message = f"FileNotFoundError: {exc}"

    except OSError as exc:
        error_message = f"OSError: {exc}"

    except Exception as exc:
        error_message = f"{type(exc).__name__}: {exc}"

    elapsed_ms = int((time.monotonic() - start_time) * 1000)
    raw["process_started"] = process_started
    raw["timed_out"] = timed_out
    raw["error_message"] = error_message
    raw["execution_time_ms"] = elapsed_ms
    return raw


def _run_test(
    test: Dict[str, Any],
    timeout_seconds: int,
    plat: str,
    dry_run: bool = False,
    prerequisite_timeout_seconds: int = 120,
) -> Dict[str, Any]:
    """Execute a single prevention test and return the result dict."""
    test_id = test.get("id", "")
    test_name = test.get("name", "")
    technique_id = test.get("technique_id", "")
    command = test.get("command", "")
    executor = test.get("executor", "sh")
    result: Dict[str, Any] = {
        "test_id": test_id,
        "test_name": test_name,
        "technique_id": technique_id,
        "verdict": "error",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finish_time": None,
        "completed_at": None,
        "process_started": False,
        "timed_out": False,
        "exit_code": None,
        "error_message": None,
        "execution_time_ms": 0,
        "stdout": "",
        "stderr": "",
        "agent_logs": [],
    }

    if not command or not command.strip():
        result["error_message"] = "Test has no command defined"
        _append_event_log(result, "error", "validate", result["error_message"])
        return _finalize_result(result)
    if not executor:
        result["error_message"] = "Test has no executor defined"
        _append_event_log(result, "error", "validate", result["error_message"])
        return _finalize_result(result)
    if test.get("runnable") is False:
        result["error_message"] = "Test is not marked runnable"
        _append_event_log(result, "error", "validate", result["error_message"])
        return _finalize_result(result)
    if dry_run:
        result["verdict"] = "skipped"
        result["error_message"] = "Dry-run mode: test was not executed"
        _append_event_log(result, "debug", "skip", "Dry-run mode requested")
        return _finalize_result(result)

    result["agent_logs"].append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "debug",
        "phase": "start",
        "message": f"Prepared {executor} test",
        "command": _redact_log_text(command),
    })

    for prerequisite in test.get("prerequisites", []):
        prereq_executor = prerequisite.get("executor") or executor
        check_command = prerequisite.get("check_command", "")
        get_command = prerequisite.get("get_command", "")
        description = prerequisite.get("description", "").strip()

        if check_command.strip():
            check = _execute_command(
                check_command, prereq_executor, prerequisite_timeout_seconds, plat
            )
            _append_result_log(result, "debug", "prerequisite_check", check_command, check)
            if (check["process_started"] and not check["timed_out"]
                    and check["exit_code"] == 0):
                continue
        else:
            check = None

        if not get_command.strip():
            result["error_message"] = (
                f"Prerequisite is unsatisfied and has no setup command: {description}"
            )
            if check:
                result["stdout"] = _redact_log_text(check["stdout"])
                result["stderr"] = _redact_log_text(check["stderr"])
                _append_event_log(result, "error", "prerequisite_check", result["error_message"])
            return _finalize_result(result)

        setup = _execute_command(
            get_command, prereq_executor, prerequisite_timeout_seconds, plat
        )
        _append_result_log(result, "debug", "prerequisite_setup", get_command, setup)
        if (not setup["process_started"] or setup["timed_out"]
                or setup["exit_code"] != 0):
            result["error_message"] = f"Prerequisite setup failed: {description}"
            result["stdout"] = _redact_log_text(setup["stdout"])
            result["stderr"] = _redact_log_text(setup["stderr"])
            return _finalize_result(result)

        if check_command.strip():
            recheck = _execute_command(
                check_command, prereq_executor, prerequisite_timeout_seconds, plat
            )
            _append_result_log(result, "debug", "prerequisite_recheck", check_command, recheck)
            if (not recheck["process_started"] or recheck["timed_out"]
                    or recheck["exit_code"] != 0):
                result["error_message"] = (
                    f"Prerequisite remains unsatisfied after setup: {description}"
                )
                result["stdout"] = _redact_log_text(recheck["stdout"])
                result["stderr"] = _redact_log_text(recheck["stderr"])
                return _finalize_result(result)

    execution = _execute_command(command, executor, timeout_seconds, plat)
    result["exit_code"] = execution["exit_code"]
    result["process_started"] = execution["process_started"]
    result["timed_out"] = execution["timed_out"]
    result["execution_time_ms"] = execution["execution_time_ms"]
    result["stdout"] = _redact_log_text(execution["stdout"])
    result["stderr"] = _redact_log_text(execution["stderr"])
    _append_result_log(result, "info", "execute", command, execution)

    # Determine verdict
    verdict, reason = _get_verdict(
        process_started=execution["process_started"],
        exit_code=execution["exit_code"],
        timed_out=execution["timed_out"],
        stderr_text=execution["stderr"],
        stdout_text=execution["stdout"],
        error_message=execution["error_message"],
        plat=plat,
    )

    result["verdict"] = verdict
    result["error_message"] = reason
    result["agent_logs"].append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "info" if verdict in ("blocked", "detected", "allowed") else "error",
        "phase": "verdict",
        "message": _redact_log_text(reason),
    })

    return _finalize_result(result)


def _finalize_result(result: Dict[str, Any]) -> Dict[str, Any]:
    if not result.get("finish_time"):
        finished_at = datetime.now(timezone.utc).isoformat()
        result["finish_time"] = finished_at
        result["completed_at"] = finished_at
    return result


def _append_result_log(
    result: Dict[str, Any], level: str, phase: str, command: str, execution: Dict[str, Any]
) -> None:
    result.setdefault("agent_logs", []).append({
        "timestamp": execution.get("started_at") or datetime.now(timezone.utc).isoformat(),
        "level": level,
        "phase": phase,
        "command": _redact_log_text(command),
        "exit_code": execution.get("exit_code"),
        "duration_ms": execution.get("execution_time_ms", 0),
        "error": _redact_log_text(execution.get("error_message") or ""),
        "stdout": _redact_log_text((execution.get("stdout") or "")[:2000]),
        "stderr": _redact_log_text((execution.get("stderr") or "")[:2000]),
    })


def _append_event_log(
    result: Dict[str, Any], level: str, phase: str, message: str
) -> None:
    result.setdefault("agent_logs", []).append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "phase": phase,
        "message": _redact_log_text(message),
    })


def _run_cleanup(
    cleanup_command: Optional[str],
    executor: str,
    plat: str,
    timeout: int = 10,
) -> None:
    """Run a cleanup command (best-effort, errors are silenced)."""
    if not cleanup_command or not cleanup_command.strip():
        return

    shell_prefix, _ = _resolve_shell(executor, plat)
    if not shell_prefix:
        return

    try:
        subprocess.run(
            shell_prefix + [cleanup_command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            preexec_fn=os.setpgrp if hasattr(os, "setpgrp") else None,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# UEC benchmark telemetry
# ---------------------------------------------------------------------------
_MAX_PERFORMANCE_SAMPLES = 8100
_PERFORMANCE_INTERVAL_SECONDS = 2.0
_PERFORMANCE_METRICS = (
    "load_1m",
    "host_cpu_busy_pct",
    "host_cpu_iowait_pct",
    "memory_used_pct",
    "memory_available_mb",
    "sensor_cpu_pct",
    "sensor_rss_mb",
    "sensor_threads",
    "sensor_fds",
    "sensor_read_kb",
    "sensor_write_kb",
    "sensor_db_mb",
    "sensor_processes",
)
_PERFORMANCE_CSV_FIELDS = {
    "load1": "load_1m",
    "cpu_busy_pct": "host_cpu_busy_pct",
    "cpu_iowait_pct": "host_cpu_iowait_pct",
    "mem_used_pct": "memory_used_pct",
    "mem_avail_mb": "memory_available_mb",
    "agent_cpu_pct": "sensor_cpu_pct",
    "agent_rss_mb": "sensor_rss_mb",
    "agent_threads": "sensor_threads",
    "agent_fds": "sensor_fds",
    "agent_read_kb": "sensor_read_kb",
    "agent_write_kb": "sensor_write_kb",
    "agent_db_mb": "sensor_db_mb",
    "agent_procs": "sensor_processes",
}


def _uec_process_snapshot() -> Tuple[
    Dict[int, Tuple[int, int, int]], List[Dict[str, Any]]
]:
    """Read UEC sensor process facts directly from procfs.

    No subprocess is executed because every process launch can affect an
    endpoint security agent and distort benchmark telemetry.
    """
    metrics: Dict[int, Tuple[int, int, int]] = {}
    identities: List[Dict[str, Any]] = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return metrics, identities

    own_pid = os.getpid()
    for entry in entries:
        if not entry.isdigit() or int(entry) == own_pid:
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                cmdline = handle.read().replace(b"\0", b" ").decode(
                    "utf-8", errors="replace"
                ).strip()
            if not re.search(r"(^|/)uec-sensor(\s|$)", cmdline):
                continue
            with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
                stat_parts = handle.read().rsplit(")", 1)[1].split()
            utime = int(stat_parts[11])
            stime = int(stat_parts[12])
            rss_kb = 0
            threads = 0
            with open(f"/proc/{pid}/status", "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("VmRSS:"):
                        rss_kb = int(line.split()[1])
                    elif line.startswith("Threads:"):
                        threads = int(line.split()[1])
            metrics[pid] = (utime + stime, rss_kb, threads)
            try:
                executable = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                executable = ""
            identities.append({
                "pid": pid,
                "command_line": _redact_log_text(cmdline),
                "executable": executable,
                "start_time_ticks": int(stat_parts[19]),
            })
        except (OSError, ValueError, IndexError):
            continue
    return metrics, identities


def _read_loadavg() -> Optional[float]:
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as handle:
            return float(handle.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _read_memory() -> Tuple[Optional[float], Optional[int]]:
    try:
        values: Dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith(("MemTotal:", "MemAvailable:")):
                    key, value = line.split(":", 1)
                    values[key] = int(value.strip().split()[0])
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)
        if total <= 0:
            return None, None
        used_pct = round(100.0 * (total - available) / total, 2)
        return used_pct, available // 1024
    except (OSError, ValueError, IndexError):
        return None, None


class _UecBenchmarkSampler:
    """Bounded procfs sampler for the local UEC sensor process."""

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._samples: List[Dict[str, Any]] = []
        self._truncated = False
        self._last_cpu: Dict[int, int] = {}
        self._last_monotonic = 0.0
        self._identities: List[Dict[str, Any]] = []
        self._restarts = 0

    def start(self) -> None:
        snapshot, identities = _uec_process_snapshot()
        self._last_cpu = {pid: values[0] for pid, values in snapshot.items()}
        self._last_monotonic = time.monotonic()
        self._identities = identities
        self._thread = threading.Thread(
            target=self._run, name="uec-benchmark-sampler", daemon=True
        )
        self._thread.start()

    def stop(self) -> Dict[str, Any]:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        with self._lock:
            samples = list(self._samples)
            identities = list(self._identities)
            truncated = self._truncated
            restarts = self._restarts
        return _performance_report(
            samples=samples,
            source="live-procfs",
            interval_seconds=_PERFORMANCE_INTERVAL_SECONDS,
            truncated=truncated,
            process_identity=identities,
            available=True,
            restarts=restarts,
        )

    def _run(self) -> None:
        while not self._stop_event.wait(_PERFORMANCE_INTERVAL_SECONDS):
            sample = self._sample_once()
            if sample is None:
                continue
            with self._lock:
                if len(self._samples) < _MAX_PERFORMANCE_SAMPLES:
                    self._samples.append(sample)
                else:
                    self._truncated = True

    def _sample_once(self) -> Optional[Dict[str, Any]]:
        now = time.monotonic()
        elapsed = now - self._last_monotonic
        snapshot, identities = _uec_process_snapshot()

        previous = self._last_cpu
        current = {pid: values[0] for pid, values in snapshot.items()}
        common = set(previous) & set(current)
        cpu_percent = None
        if elapsed > 0 and common:
            try:
                clock_ticks = os.sysconf("SC_CLK_TCK")
                cpu_seconds = sum(current[pid] - previous[pid] for pid in common) / clock_ticks
                cpu_percent = round(
                    (cpu_seconds / elapsed) * 100.0 * (os.cpu_count() or 1), 3
                )
            except (KeyError, ValueError, ZeroDivisionError, OSError):
                cpu_percent = None

        if set(snapshot) != set(previous):
            self._restarts += 1
            with self._lock:
                for identity in identities:
                    if identity not in self._identities:
                        self._identities.append(identity)
        rss_kb = sum(values[1] for values in snapshot.values())
        threads = sum(values[2] for values in snapshot.values())
        memory_used_pct, memory_available_mb = _read_memory()
        sample: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sensor_processes": len(snapshot),
            "sensor_rss_mb": round(rss_kb / 1024.0, 3) if rss_kb else 0,
            "sensor_threads": threads,
            "load_1m": _read_loadavg(),
            "memory_used_pct": memory_used_pct,
            "memory_available_mb": memory_available_mb,
        }
        if cpu_percent is not None:
            sample["sensor_cpu_pct"] = cpu_percent

        self._last_cpu = current
        self._last_monotonic = now
        return sample


def _percentile(values: List[float], percentile: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(percentile * (len(ordered) - 1)))))
    return round(ordered[index], 3)


def _performance_metric_summary(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    for metric in _PERFORMANCE_METRICS:
        values = [
            float(sample[metric]) for sample in samples
            if isinstance(sample.get(metric), (int, float))
        ]
        if not values:
            continue
        summary[metric] = {
            "average": round(sum(values) / len(values), 3),
            "p95": _percentile(values, 0.95),
            "max": round(max(values), 3),
        }
    return summary


def _performance_report(
    *,
    samples: List[Dict[str, Any]],
    source: str,
    interval_seconds: Optional[float],
    truncated: bool = False,
    process_identity: Optional[List[Dict[str, Any]]] = None,
    available: bool = True,
    reason: Optional[str] = None,
    restarts: Optional[int] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "source": source,
        "available": available,
        "sample_count": len(samples),
        "bounded": True,
        "truncated": truncated,
        "samples": samples,
    }
    if interval_seconds is not None:
        report["interval_seconds"] = interval_seconds
    metric_summary = _performance_metric_summary(samples)
    report["summary"] = metric_summary
    report["averages"] = {
        metric: values["average"] for metric, values in metric_summary.items()
    }
    report["p95"] = {
        metric: values["p95"] for metric, values in metric_summary.items()
    }
    report["max"] = {
        metric: values["max"] for metric, values in metric_summary.items()
    }
    if process_identity is not None:
        report["process_identity"] = process_identity
    if restarts is not None:
        report["process_restarts"] = restarts
    if reason:
        report["reason"] = reason
    if error:
        report["error"] = error
    return report


def _parse_performance_csv(path: Path) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    truncated = False
    try:
        if not path.is_file():
            raise FileNotFoundError(str(path))
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                sample: Dict[str, Any] = {}
                timestamp = row.get("ts_utc")
                if timestamp:
                    sample["timestamp"] = timestamp[:64]
                for source_field, target_field in _PERFORMANCE_CSV_FIELDS.items():
                    value = row.get(source_field)
                    if value is None or value == "":
                        continue
                    try:
                        number = float(value)
                    except ValueError:
                        continue
                    if math.isfinite(number):
                        sample[target_field] = number
                if sample:
                    rows.append(sample)
                if len(rows) > _MAX_PERFORMANCE_SAMPLES:
                    rows.pop(0)
                    truncated = True
                    break
    except (OSError, csv.Error) as exc:
        return _performance_report(
            samples=[], source="kit-csv", interval_seconds=None,
            available=False, error=f"{type(exc).__name__}: unable to read performance file"
        )

    timestamps = [
        _utc_epoch(row.get("timestamp")) for row in rows if row.get("timestamp")
    ]
    interval = None
    if len(timestamps) > 1:
        interval = round(
            (timestamps[-1] - timestamps[0]) / (len(timestamps) - 1), 3
        )
    return _performance_report(
        samples=rows, source="kit-csv", interval_seconds=interval,
        truncated=truncated, process_identity=[],
    )


def _annotate_performance_phases(
    performance: Dict[str, Any], results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    starts = [
        _utc_epoch(result.get("started_at")) for result in results
        if result.get("verdict") != "skipped" and _utc_epoch(result.get("started_at"))
    ]
    finishes = [
        _utc_epoch(result.get("finish_time")) for result in results
        if result.get("verdict") != "skipped" and _utc_epoch(result.get("finish_time"))
    ]
    samples = performance.get("samples")
    if not starts or not finishes or not isinstance(samples, list):
        return performance

    attack_start = min(starts) - 5.0
    attack_finish = max(finishes) + 5.0
    idle_floor = attack_start - 3600.0
    phase_samples: Dict[str, List[Dict[str, Any]]] = {"idle": [], "attack": []}
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        timestamp = _utc_epoch(sample.get("timestamp"))
        if timestamp is None:
            continue
        if idle_floor <= timestamp < attack_start:
            sample["phase"] = "idle"
            phase_samples["idle"].append(sample)
        elif timestamp <= attack_finish:
            sample["phase"] = "attack"
            phase_samples["attack"].append(sample)

    performance["phases"] = {
        phase: {"sample_count": len(items), "summary": _performance_metric_summary(items)}
        for phase, items in phase_samples.items()
    }
    return performance


_SENSITIVE_LOG_PATTERNS = [
    re.compile(r"(?i)(x-api-key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)\S+"),
    re.compile(
        r'(?i)((?:password|passwd|secret|token|api[_-]?key)"?\s*[:=]\s*)'
        r'(?:"[^"\n]*"|\'[^\n]*\'|\S+)'
    ),
    re.compile(r"(?i)((?:token|api[_-]?key|secret|password)=)[^&\s]+"),
    re.compile(r"(?i)(cookie\s*[:=]\s*)\S+"),
]
_AWS_ACCESS_KEY_PATTERN = re.compile(r"(?i)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")


def _redact_log_text(text: str) -> str:
    redacted = text
    for pattern in _SENSITIVE_LOG_PATTERNS:
        redacted = pattern.sub(r"\1<redacted>", redacted)
    redacted = _AWS_ACCESS_KEY_PATTERN.sub("<redacted>", redacted)
    return redacted


def _sensor_log_paths(plat: str) -> List[Path]:
    override = os.environ.get("UEC_SENSOR_LOG_PATH")
    if override:
        return [Path(override)] if override.strip() else []
    if plat == "windows":
        programData = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        roots = [
            programData / "UEC" / "Sensor" / "Logs",
            programData / "UEC Sensor" / "Logs",
            programData / "Infopercept" / "UecSensor" / "logs",
        ]
        return sorted(
            path for root in roots
            for path in root.rglob("*.log")
        )[:40]
    if plat == "macos":
        return sorted(Path("/Library/Logs/UECSensor").glob("*.log"))[:40]
    if plat == "linux":
        return sorted(Path("/var/log/uec-sensor").rglob("*.log"))[:40]
    return []


def _collect_uec_sensor_logs(plat: str) -> List[Dict[str, Any]]:
    """Collect a bounded, redacted tail of local UEC sensor logs."""
    try:
        max_lines = max(0, min(int(os.environ.get("UEC_SENSOR_LOG_LINES", "200")), 2000))
    except ValueError:
        max_lines = 200
    logs: List[Dict[str, Any]] = []
    total_bytes = 0
    for path in _sensor_log_paths(plat):
        try:
            if not path.is_file():
                continue
            text = _redact_log_text(
                _tail_text(path, min(131_072, max_lines * 4096), max_lines)
            )
            payload_bytes = len(text.encode("utf-8"))
            if total_bytes + payload_bytes > 131_072:
                remaining = max(0, 131_072 - total_bytes)
                text = text[:remaining]
                payload_bytes = len(text.encode("utf-8"))
            total_bytes += payload_bytes
            logs.append({
                "source": "uec-sensor",
                "path": str(path),
                "lines": text.splitlines(),
            })
            if total_bytes >= 131_072:
                break
        except Exception as exc:
            logs.append({
                "source": "uec-sensor",
                "path": str(path),
                "error": f"{type(exc).__name__}: unable to read log",
            })
    return logs


def _utc_epoch(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError):
        return None


def _uec_detection_payload(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        text = str(value)
    return _redact_log_text(text)[:1500]


def _uec_detection_techniques(value: Any) -> List[str]:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if not isinstance(value, dict):
        return []
    values = value.get("techniques") or value.get("attackTechniques")
    if not isinstance(values, list):
        return []
    return [str(item).upper() for item in values if item]


def _uec_technique_matches(expected: Optional[str], actual: List[str]) -> bool:
    if not expected or not actual:
        return False
    parent = expected.upper().split(".", 1)[0]
    return any(
        value.upper() == expected or value.upper().split(".", 1)[0] == parent
        for value in actual
    )


def _correlate_uec_findings(
    results: List[Dict[str, Any]], plat: str
) -> Dict[str, Any]:
    """Correlate Linux UEC findings directly from the sensor SQLite database.

    The query is local, read-only, and bounded to the complete test interval
    plus five seconds on either side. Remote UEC correlation remains a backend
    concern and is intentionally not attempted here.
    """
    metadata: Dict[str, Any] = {
        "source": "uec-sensor-db",
        "platform": plat,
        "matched": 0,
        "promoted": 0,
    }
    if plat != "linux":
        metadata["available"] = False
        metadata["reason"] = "Direct database correlation is supported on Linux"
        return metadata

    windows: List[Tuple[Dict[str, Any], float, float]] = []
    for result in results:
        if result.get("verdict") == "skipped":
            continue
        start = _utc_epoch(result.get("started_at"))
        finish = _utc_epoch(result.get("finish_time"))
        if start is None:
            continue
        if finish is None:
            finish = datetime.now(timezone.utc).timestamp()
        windows.append((result, start - 5.0, finish + 5.0))

    if not windows:
        metadata["available"] = False
        metadata["reason"] = "No executed test intervals were available"
        return metadata

    db_path = Path(os.environ.get("UEC_DB", "/var/lib/uec-sensor/uec-sensor.db"))
    try:
        # is_file() stats the path, which raises PermissionError (not caught below) when the
        # agent runs as a non-root user and /var/lib/uec-sensor/ is root-only (the common case).
        db_exists = db_path.is_file()
    except OSError as exc:
        metadata["available"] = False
        metadata["reason"] = f"{type(exc).__name__}: unable to read UEC database (permission denied)"
        return metadata
    if not db_exists:
        metadata["available"] = False
        metadata["reason"] = "UEC sensor database was not found"
        return metadata

    query_start = min(window[1] for window in windows)
    query_finish = max(window[2] for window in windows)
    try:
        connection = sqlite3.connect(
            f"{db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=2.0
        )
        try:
            connection.execute("PRAGMA query_only = ON")
            rows = connection.execute(
                """
                SELECT id, detected_at_unix, state, payload
                FROM detection_findings
                WHERE CAST(detected_at_unix AS REAL) BETWEEN ? AND ?
                ORDER BY detected_at_unix, id
                """,
                (query_start, query_finish),
            ).fetchall()
        finally:
            connection.close()
    except (sqlite3.Error, OSError) as exc:
        metadata["available"] = False
        metadata["reason"] = f"{type(exc).__name__}: unable to read UEC database"
        return metadata

    metadata["available"] = True
    metadata["findings"] = len(rows)
    metadata["observed"] = 0
    for row_id, detected_at, state, payload in rows:
        try:
            detected_epoch = float(detected_at)
        except (TypeError, ValueError):
            continue
        for result, start, finish in windows:
            if not (start <= detected_epoch <= finish):
                continue
            finding_techniques = _uec_detection_techniques(payload)
            result_technique = result.get("technique_id")
            # If the finding carries ATT&CK tags, require a parent/sub-technique
            # match. Findings without tags remain evidence but cannot promote a
            # verdict on a busy, overlapping host.
            authoritative_match = _uec_technique_matches(result_technique, finding_techniques)
            logs = result.setdefault("agent_logs", [])
            if sum(1 for item in logs if item.get("phase") == "uec_detection") >= 10:
                continue
            logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "info",
                "phase": "uec_detection",
                "message": "Matched a UEC detection finding",
                "source": "uec-sensor-db",
                "detection_id": row_id,
                "detected_at_unix": detected_epoch,
                "state": state,
                "payload": _uec_detection_payload(payload),
            })
            result["uec_detection_count"] = result.get("uec_detection_count", 0) + 1
            if authoritative_match:
                metadata["matched"] += 1
            else:
                metadata["observed"] += 1

            completed = (
                result.get("process_started") is True
                and result.get("timed_out") is not True
                and result.get("exit_code") is not None
            )
            if result.get("verdict") == "allowed" and completed and authoritative_match:
                result["verdict"] = "detected"
                result["error_message"] = (
                    "UEC detection evidence matched the test interval; "
                    "the process completed without a block"
                )
                result.setdefault("agent_logs", []).append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": "info",
                    "phase": "uec_correlation",
                    "message": "Promoted allowed result to detected",
                    "source": "uec-sensor-db",
                })
                metadata["promoted"] += 1

    return metadata


def _tail_text(path: Path, byte_limit: int, line_limit: int) -> str:
    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, size - byte_limit))
        raw = handle.read(byte_limit)
    text = raw.decode("utf-8", errors="replace")
    # A partial first UTF-8 character or sliced line is harmless, but drop the
    # incomplete prefix so the UI does not show a misleading log fragment.
    return "\n".join(text.splitlines()[-line_limit:])


def _build_debug_logs(results: List[Dict[str, Any]], tests_by_id: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    logs: List[Dict[str, Any]] = []
    for result in results:
        test = tests_by_id.get(result.get("test_id", ""), {})
        logs.append({
            "timestamp": result.get("started_at"),
            "level": (
                "info" if result.get("verdict") in ("blocked", "detected", "allowed")
                else "error"
            ),
            "test_id": result.get("test_id", ""),
            "technique_id": result.get("technique_id", ""),
            "command": _redact_log_text(test.get("command", ""))[:2000],
            "executor": test.get("executor", ""),
            "verdict": result.get("verdict", "error"),
            "exit_code": result.get("exit_code"),
            "stdout": _redact_log_text(result.get("stdout", ""))[:4000],
            "stderr": _redact_log_text(result.get("stderr", ""))[:4000],
            "agent_log_count": len(result.get("agent_logs", [])),
        })
    return logs


# ---------------------------------------------------------------------------
# Platform filtering
# ---------------------------------------------------------------------------

# Mapping of playbook platform tags to our normalised platform string.
_PLATFORM_ALIASES: Dict[str, str] = {
    "macos": "macos",
    "darwin": "macos",
    "osx": "macos",
    "mac": "macos",
    "linux": "linux",
    "windows": "windows",
    "win": "windows",
}


def _test_matches_platform(test: Dict[str, Any], plat: str) -> bool:
    """Return True if *test* should run on the current platform."""
    platforms = test.get("platforms", [])
    if not platforms:
        # No platform restriction -> run everywhere
        return True

    for p in platforms:
        normalised = _PLATFORM_ALIASES.get(p.lower().strip(), p.lower().strip())
        if normalised == plat:
            return True

    return False


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------

def _print_banner(plat: str, hostname: str, os_ver: str) -> None:
    header = f"""\
{_c('', _CYAN)}
{_c('  ============================================================', _CYAN)}
{_c('    Atomic Prevention  Prevention Validation Agent  v' + __version__, _CYAN)}
{_c('    Python Cross-Platform Runner', _CYAN)}
{_c('  ============================================================', _CYAN)}
{_c('    Authorized security testing only', _CYAN)}
{_c('    Ensure you have explicit permission before proceeding.', _CYAN)}
{_c('  ============================================================', _CYAN)}
{_c('    Hostname : ' + hostname, _WHITE)}
{_c('    Platform : ' + plat, _WHITE)}
{_c('    OS       : ' + os_ver, _WHITE)}
{_c('    User     : ' + _get_username(), _WHITE)}
{_c('    Root     : ' + ('yes' if _is_root() else 'no'), _WHITE)}
{_c('  ============================================================', _CYAN)}
"""
    print(header)


def _get_username() -> str:
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        try:
            import pwd
            return pwd.getpwuid(os.geteuid()).pw_name
        except Exception:
            return "unknown"


def _print_verdict_line(
    index: int,
    total: int,
    verdict: str,
    technique_id: str,
    test_name: str,
    guidance: Optional[Dict[str, str]],
    reason: Optional[str],
) -> None:
    prefix = f"  [{index}/{total}]"
    if verdict == "blocked":
        print(f"{prefix} {_c('BLOCKED', _GREEN)} {technique_id} | {test_name}")
        if guidance and guidance.get("if_blocked"):
            print(f"         {_c(guidance['if_blocked'], _DARK_GREEN)}")
    elif verdict == "detected":
        print(f"{prefix} {_c('DETECTED', _CYAN)} {technique_id} | {test_name}")
        if reason:
            print(f"         {_c(reason, _DARK_CYAN)}")
    elif verdict == "allowed":
        print(f"{prefix} {_c('ALLOWED', _RED)} {technique_id} | {test_name}")
        if guidance and guidance.get("if_allowed"):
            print(f"         {_c(guidance['if_allowed'], _YELLOW)}")
        if guidance and guidance.get("mitre_reference"):
            print(f"         {_c('Reference: ' + guidance['mitre_reference'], _DARK_CYAN)}")
    elif verdict == "skipped":
        print(f"{prefix} {_c('SKIP   ', _DARK_GRAY)} {technique_id} | {test_name}")
    else:
        print(f"{prefix} {_c('ERROR  ', _YELLOW)} {technique_id} | {test_name}")
        if reason:
            print(f"         {_c(reason, _DARK_YELLOW)}")


def _print_summary(
    total: int,
    blocked: int,
    detected: int,
    allowed: int,
    errors: int,
    skipped: int,
) -> None:
    print()
    print(_c("  ============================================================", _CYAN))
    print(_c("    Results summary", _CYAN))
    print(_c("  ============================================================", _CYAN))
    print(f"{_c('    Total tests : ', _WHITE)}{total}")
    print(f"{_c('    Blocked     : ', _WHITE)}{_c(str(blocked), _GREEN)}")
    print(f"{_c('    Detected    : ', _WHITE)}{_c(str(detected), _CYAN)}")
    print(f"{_c('    Allowed     : ', _WHITE)}{_c(str(allowed), _RED)}")
    print(f"{_c('    Errors      : ', _WHITE)}{_c(str(errors), _YELLOW)}")
    print(f"{_c('    Skipped     : ', _WHITE)}{_c(str(skipped), _DARK_GRAY)}")
    print(_c("  ============================================================", _CYAN))

    executed = blocked + detected + allowed
    visible = blocked + detected
    if executed > 0:
        score = round((blocked / executed) * 100, 1)
        if score >= 80:
            score_color = _GREEN
        elif score >= 50:
            score_color = _YELLOW
        else:
            score_color = _RED
        visibility = round((visible / executed) * 100, 1)
        print(f"{_c('    Prevention : ', _WHITE)}{_c(f'{score}% ({blocked}/{executed} tests blocked)', score_color)}")
        print(f"{_c('    Visibility : ', _WHITE)}{_c(f'{visibility}% ({visible}/{executed} tests blocked or detected)', score_color)}")
        print(_c("  ============================================================", _CYAN))

    print()


def _print_remediation(
    allowed_results: List[Dict[str, Any]],
    tests_by_id: Dict[str, Dict[str, Any]],
) -> None:
    """Print a remediation report for tests that were not blocked."""
    if not allowed_results:
        return

    print(_c("  ============================================================", _RED))
    print(_c("    Remediation needed", _RED))
    print(_c("  ============================================================", _RED))
    print()
    print(f"    The following {len(allowed_results)} test(s) were not blocked:")
    print()

    for i, res in enumerate(allowed_results, 1):
        tid = res.get("technique_id", "")
        tname = res.get("test_name", "")
        test_def = tests_by_id.get(res.get("test_id", ""), {})
        guidance = test_def.get("guidance", {})

        print(f"    {_c(f'{i}. {tid} | {tname}', _RED)}")
        if guidance.get("if_allowed"):
            print(f"       {_c(guidance['if_allowed'], _YELLOW)}")
        if test_def.get("technique_url"):
            print(f"       {_c('MITRE: ' + test_def['technique_url'], _DARK_CYAN)}")
        resources = test_def.get("resources", {})
        if resources:
            if resources.get("lolbas_url"):
                print(f"       {_c('LOLBAS: ' + resources['lolbas_url'], _DARK_CYAN)}")
            if resources.get("loldrivers_url"):
                print(f"       {_c('LOLDrivers: ' + resources['loldrivers_url'], _DARK_CYAN)}")
            if resources.get("atomic_url"):
                print(f"       {_c('Atomic: ' + resources['atomic_url'], _DARK_CYAN)}")
        print()

    print(_c("  ============================================================", _RED))
    print()


def _summarize_results(results: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {
        "blocked": 0,
        "detected": 0,
        "allowed": 0,
        "error": 0,
        "skipped": 0,
    }
    for result in results:
        verdict = result.get("verdict", "error")
        key = verdict if verdict in summary else "error"
        summary[key] += 1
    return summary


# ---------------------------------------------------------------------------
# Log file
# ---------------------------------------------------------------------------

def _write_log_line(
    log_path: Path,
    test_name: str,
    technique_id: str,
    verdict: str,
    reason: str,
    execution_time_ms: int,
    exit_code: Optional[int],
) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.") + f"{datetime.now().microsecond // 1000:03d}"
    exit_code_str = str(exit_code) if exit_code is not None else "N/A"
    line = (
        f"[{ts}] [{verdict.upper()}] {technique_id} | {test_name} "
        f"| ExitCode={exit_code_str} | {execution_time_ms}ms | {reason}\n"
    )
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def _bounded_debug_log_items(
    logs: Optional[List[Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    if not logs:
        return []
    bounded: List[Dict[str, Any]] = []
    for item in logs[-200:]:
        if not isinstance(item, dict):
            continue
        compact = dict(item)
        for field in ("stdout", "stderr", "command"):
            if isinstance(compact.get(field), str):
                compact[field] = compact[field][:2000]
        bounded.append(compact)
    return bounded


# ---------------------------------------------------------------------------
# Results upload
# ---------------------------------------------------------------------------

def _upload_results(
    server_url: str,
    results_endpoint: str,
    playbook_id: str,
    hostname: str,
    all_results: List[Dict[str, Any]],
    platform_name: str = "",
    os_version: str = "",
    sensor_logs: Optional[List[Dict[str, Any]]] = None,
    debug_logs: Optional[List[Dict[str, Any]]] = None,
    run_started_at: Optional[str] = None,
    run_completed_at: Optional[str] = None,
    performance: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """POST results to the Atomic Prevention server.

    Returns (success, run_id_or_error, summary_or_None).
    """
    payloads = []
    for r in all_results:
        if r["verdict"] == "skipped":
            continue
        payloads.append({
            "test_id": r["test_id"],
            "verdict": r["verdict"],
            "exit_code": r["exit_code"],
            "error_message": r["error_message"],
            "execution_time_ms": r["execution_time_ms"],
            "executed_at": r.get("started_at"),
            "started_at": r.get("started_at"),
            "finish_time": r.get("finish_time"),
            "completed_at": r.get("completed_at"),
            "stdout": r.get("stdout", ""),
            "stderr": r.get("stderr", ""),
            "agent_logs": (r.get("agent_logs") or [])[-100:],
        })

    if not payloads:
        return False, "No results to submit (all tests were skipped)", None

    body = json.dumps({
        "playbook_id": playbook_id,
        "hostname": hostname,
        "agent_name": "python-agent",
        "started_at": run_started_at,
        "completed_at": run_completed_at,
        "platform": platform_name,
        "os_version": os_version,
        "agent_version": __version__,
        "sensor_logs": sensor_logs or [],
        "debug_logs": _bounded_debug_log_items(debug_logs),
        "performance": performance or {},
        "results": payloads,
    }).encode("utf-8")

    url = server_url.rstrip("/") + results_endpoint

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(resp_body)
            return True, data.get("run_id"), data.get("summary")
    except urllib.error.HTTPError as exc:
        body_text = ""
        try:
            body_text = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return False, f"HTTP {exc.code}: {body_text[:500]}", None
    except urllib.error.URLError as exc:
        return False, f"Connection error: {exc.reason}", None
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}", None


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_playbook(
    playbook_path: str,
    server_url: Optional[str] = None,
    dry_run: bool = False,
    output_dir: Optional[str] = None,
    skip_test_ids: Optional[List[str]] = None,
    only_technique_ids: Optional[List[str]] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Load and execute a playbook, returning the full results payload."""

    plat = _current_platform()
    hostname = _hostname()
    os_ver = _os_version()

    # Banner
    _print_banner(plat, hostname, os_ver)

    # ------------------------------------------------------------------
    # Load playbook
    # ------------------------------------------------------------------
    print(f"  {_c('[*] Loading playbook...', _WHITE)}")

    pb_path = Path(playbook_path)
    if not pb_path.is_file():
        print(f"  {_c('[!] Playbook file not found: ' + str(pb_path), _RED)}")
        sys.exit(1)

    try:
        with open(pb_path, "r", encoding="utf-8") as f:
            playbook_data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"  {_c('[!] Failed to parse playbook JSON: ' + str(exc), _RED)}")
        sys.exit(1)

    # Validate structure
    if "playbook" not in playbook_data or "tests" not in playbook_data:
        msg = '[!] Invalid playbook format. Expected "playbook" and "tests" keys.'
        print(f"  {_c(msg, _RED)}")
        sys.exit(1)

    pb_meta = playbook_data["playbook"]
    tests: List[Dict[str, Any]] = list(playbook_data["tests"])
    config = playbook_data.get("config", {})
    timeout_seconds = config.get("timeout_seconds", 5)
    prerequisite_timeout_seconds = config.get("prerequisite_timeout_seconds", 120)
    results_endpoint = config.get("results_endpoint", "/api/results/submit")

    print(f"  {_c('[*] Playbook  : ' + pb_meta.get('name', ''), _WHITE)}")
    print(f"  {_c('[*] Adversary : ' + str(pb_meta.get('adversary_group', '')), _WHITE)}")
    print(f"  {_c('[*] Tests     : ' + str(len(tests)), _WHITE)}")
    print(f"  {_c('[*] Timeout   : ' + str(timeout_seconds) + 's per test', _WHITE)}")

    if dry_run:
        print(f"  {_c('[*] Mode      : Dry run (no commands will be executed)', _YELLOW)}")

    print()

    # ------------------------------------------------------------------
    # Prepare output directory
    # ------------------------------------------------------------------
    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = Path.cwd() / "AtomicPrevention-Results"
    out_dir.mkdir(parents=True, exist_ok=True)

    run_timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = out_dir / f"atomic-prevention-{run_timestamp}.log"
    result_path = out_dir / f"atomic-prevention-{run_timestamp}.json"

    # ------------------------------------------------------------------
    # Filter tests
    # ------------------------------------------------------------------
    if only_technique_ids:
        only_set = set(only_technique_ids)
        tests = [t for t in tests if t.get("technique_id") in only_set]
        print(f"  {_c(f'[*] Filtered to {len(tests)} tests matching techniques: ' + ', '.join(only_technique_ids), _WHITE)}")

    if skip_test_ids:
        skip_set = set(skip_test_ids)
        tests = [t for t in tests if t.get("id") not in skip_set]
        print(f"  {_c(f'[*] Skipped {len(skip_test_ids)} test(s)', _WHITE)}")

    # Build a lookup dict for guidance/remediation output
    tests_by_id: Dict[str, Dict[str, Any]] = {t["id"]: t for t in tests}

    # ------------------------------------------------------------------
    # Execute tests
    # ------------------------------------------------------------------
    run_started_at = datetime.now(timezone.utc).isoformat()
    performance_file = os.environ.get("ATOMIC_PREVENTION_PERF_FILE", "").strip()
    if performance_file:
        performance = _parse_performance_csv(Path(performance_file))
        benchmark_sampler = None
    else:
        benchmark_sampler = _UecBenchmarkSampler()
        benchmark_sampler.start()

    all_results: List[Dict[str, Any]] = []
    summary = {
        "blocked": 0,
        "detected": 0,
        "allowed": 0,
        "error": 0,
        "skipped": 0,
    }

    total_tests = len(tests)
    for idx, test in enumerate(tests, 1):
        technique_id = test.get("technique_id", "")
        test_name = test.get("name", "")
        test_id = test.get("id", "")
        guidance = test.get("guidance")

        # Show what this test validates
        if guidance and guidance.get("what_this_tests"):
            print(f"         {_c(guidance['what_this_tests'], _DARK_GRAY)}")

        # Platform filter
        if not _test_matches_platform(test, plat):
            print(f"  [{idx}/{total_tests}] {_c('SKIP   ', _DARK_GRAY)} {technique_id} | {test_name} (not a {plat} test)")
            summary["skipped"] += 1
            all_results.append({
                "test_id": test_id,
                "test_name": test_name,
                "technique_id": technique_id,
                "verdict": "skipped",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finish_time": None,
                "completed_at": None,
                "exit_code": None,
                "error_message": f"Test not applicable to platform: {plat}",
                "execution_time_ms": 0,
                "stdout": "",
                "stderr": "",
                "agent_logs": [],
            })
            _finalize_result(all_results[-1])
            continue

        # Elevation check
        if test.get("elevation_required") and not _is_root():
            print(f"  [{idx}/{total_tests}] {_c('SKIP   ', _DARK_GRAY)} {technique_id} | {test_name} (requires root)")
            summary["skipped"] += 1
            skip_result = {
                "test_id": test_id,
                "test_name": test_name,
                "technique_id": technique_id,
                "verdict": "skipped",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finish_time": None,
                "completed_at": None,
                "exit_code": None,
                "error_message": "Test requires root but agent is not running as root",
                "execution_time_ms": 0,
                "stdout": "",
                "stderr": "",
                "agent_logs": [],
            }
            all_results.append(skip_result)
            _finalize_result(skip_result)
            _write_log_line(
                log_path, test_name, technique_id, "error",
                "Skipped: requires root", 0, None,
            )
            continue

        # Execute
        test_result = _run_test(
            test,
            timeout_seconds,
            plat,
            dry_run=dry_run,
            prerequisite_timeout_seconds=prerequisite_timeout_seconds,
        )
        all_results.append(test_result)

        verdict = test_result["verdict"]
        summary_key = verdict if verdict in summary else "error"
        summary[summary_key] += 1

        # Display
        _print_verdict_line(
            idx, total_tests, verdict, technique_id, test_name,
            guidance, test_result.get("error_message"),
        )

        # Verbose: show stdout/stderr snippets
        if verbose and test_result.get("stdout"):
            stdout_preview = test_result["stdout"].strip()[:200]
            if stdout_preview:
                print(f"         {_c('stdout: ' + stdout_preview, _DARK_GRAY)}")
        if verbose and test_result.get("stderr"):
            stderr_preview = test_result["stderr"].strip()[:200]
            if stderr_preview:
                print(f"         {_c('stderr: ' + stderr_preview, _DARK_GRAY)}")

        # Log
        log_verdict = (
            verdict if verdict in ("blocked", "detected", "allowed", "error") else "error"
        )
        _write_log_line(
            log_path, test_name, technique_id, log_verdict,
            test_result.get("error_message", ""),
            test_result.get("execution_time_ms", 0),
            test_result.get("exit_code"),
        )

        # Cleanup after a process ran, including detection-only outcomes.
        if verdict in ("allowed", "detected") and not dry_run:
            _run_cleanup(
                test.get("cleanup_command"),
                test.get("executor", "sh"),
                plat,
            )

    # ------------------------------------------------------------------
    # Local UEC correlation is deliberately separate from backend remote UEC
    # correlation. On Linux it uses the sensor's SQLite database directly.
    # ------------------------------------------------------------------
    # Belt-and-suspenders: this is optional enrichment uploaded with the run, never a
    # reason to lose 43 tests' worth of results to an unanticipated local-DB error.
    try:
        uec_correlation = _correlate_uec_findings(all_results, plat)
    except Exception as exc:
        uec_correlation = {"available": False, "reason": f"{type(exc).__name__}: correlation failed"}
    summary = _summarize_results(all_results)
    run_completed_at = datetime.now(timezone.utc).isoformat()
    if benchmark_sampler is not None:
        performance = benchmark_sampler.stop()
    performance = _annotate_performance_phases(performance, all_results)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    sensor_logs = _collect_uec_sensor_logs(plat)
    debug_logs = _build_debug_logs(all_results, tests_by_id)
    _print_summary(
        total_tests,
        summary["blocked"],
        summary["detected"],
        summary["allowed"],
        summary["error"],
        summary["skipped"],
    )

    # Remediation
    allowed_results = [r for r in all_results if r["verdict"] == "allowed"]
    _print_remediation(allowed_results, tests_by_id)

    # ------------------------------------------------------------------
    # Save results locally
    # ------------------------------------------------------------------
    output_payload: Dict[str, Any] = {
        "atomic_prevention_version": __version__,
        "agent": "python",
        "agent_name": "python-agent",
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "started_at": run_started_at,
        "completed_at": run_completed_at,
        "hostname": hostname,
        "platform": plat,
        "os_version": os_ver,
        "agent_version": __version__,
        "playbook": {
            "id": pb_meta.get("id", ""),
            "name": pb_meta.get("name", ""),
            "adversary_group": pb_meta.get("adversary_group", ""),
        },
        "summary": summary,
        "metadata": {"uec_detection_correlation": uec_correlation},
        "performance": performance,
        "sensor_logs": sensor_logs,
        "debug_logs": debug_logs,
        "results": [
            {
                "test_id": r["test_id"],
                "test_name": r.get("test_name", ""),
                "technique_id": r.get("technique_id", ""),
                "verdict": r["verdict"],
                "started_at": r.get("started_at"),
                "finish_time": r.get("finish_time"),
                "completed_at": r.get("completed_at"),
                "exit_code": r["exit_code"],
                "error_message": r["error_message"],
                "execution_time_ms": r["execution_time_ms"],
                "stdout": r.get("stdout", ""),
                "stderr": r.get("stderr", ""),
                "agent_logs": r.get("agent_logs", []),
                "uec_detection_count": r.get("uec_detection_count", 0),
            }
            for r in all_results
        ],
    }

    try:
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(output_payload, f, indent=2, ensure_ascii=False)
        print(f"  {_c('[*] Results saved to: ' + str(result_path), _WHITE)}")
        print(f"  {_c('[*] Log saved to   : ' + str(log_path), _WHITE)}")
    except Exception as exc:
        print(f"  {_c('[!] Failed to save results: ' + str(exc), _RED)}")

    # ------------------------------------------------------------------
    # Upload results to server (optional)
    # ------------------------------------------------------------------
    if server_url and not dry_run:
        print(f"\n  {_c('Uploading results to ' + server_url + results_endpoint + ' ...', _CYAN)}")
        success, run_id_or_err, srv_summary = _upload_results(
            server_url, results_endpoint,
            pb_meta.get("id", ""),
            hostname, all_results,
            plat, os_ver, sensor_logs, debug_logs,
            run_started_at, run_completed_at, performance,
        )
        if success:
            print(f"  {_c('Upload successful. Run ID: ' + str(run_id_or_err), _GREEN)}")
            if srv_summary:
                print(
                    f"  {_c('Server summary -- Blocked: ' + str(srv_summary.get('blocked', 0)) + ', Detected: ' + str(srv_summary.get('detected', 0)) + ', Allowed: ' + str(srv_summary.get('allowed', 0)) + ', Error: ' + str(srv_summary.get('error', 0)), _CYAN)}"
                )
        else:
            print(f"  {_c('[!] Failed to upload results: ' + str(run_id_or_err), _YELLOW)}")
            print(f"  {_c('[!] Results are saved locally. You can retry upload later.', _YELLOW)}")
    elif server_url and dry_run:
        print(f"  {_c('[*] Dry-run mode: skipping result upload to server.', _YELLOW)}")

    print()
    return output_payload


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="atomic_prevention_runner",
        description="Atomic Prevention Cross-Platform Prevention Validation Agent",
        epilog=(
            "Examples:\n"
            "  python3 atomic_prevention_runner.py --playbook ./apt29-playbook.json\n"
            "  python3 atomic_prevention_runner.py --playbook ./playbook.json --server http://10.0.0.5:8000\n"
            "  python3 atomic_prevention_runner.py --playbook ./playbook.json --dry-run\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--playbook", "-p",
        required=True,
        help="Path to a playbook JSON file exported from the Atomic Prevention backend.",
    )
    parser.add_argument(
        "--server", "-s",
        default=None,
        help="Base URL of the Atomic Prevention server for uploading results (e.g. http://localhost:3000).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show what tests would run without executing any commands.",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Directory for result JSON and log files (default: ./AtomicPrevention-Results).",
    )
    parser.add_argument(
        "--skip-test",
        action="append",
        default=None,
        dest="skip_test_ids",
        help="Skip test(s) by ID.  Can be specified multiple times.",
    )
    parser.add_argument(
        "--only-technique",
        action="append",
        default=None,
        dest="only_technique_ids",
        help="Only run tests for specific technique ID(s).  Can be specified multiple times.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Show stdout/stderr snippets for each test.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    run_playbook(
        playbook_path=args.playbook,
        server_url=args.server,
        dry_run=args.dry_run,
        output_dir=args.output_dir,
        skip_test_ids=args.skip_test_ids,
        only_technique_ids=args.only_technique_ids,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
