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
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
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
    'blocked', 'allowed', 'error'.

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

        return "error", f"Process failed to start (non-security): {reason}"

    # ------------------------------------------------------------------
    # Case 2: Process started but timed out
    # ------------------------------------------------------------------
    if timed_out:
        # The process was able to run -- it was not blocked.
        return "allowed", "Process was still running after timeout (not blocked)"

    # ------------------------------------------------------------------
    # Case 3: Process started and exited -- inspect exit code + stderr
    # ------------------------------------------------------------------

    # First, always check stderr for block patterns even when exit code
    # looks "normal".  Some security tools write denial messages to
    # stderr but still allow the process to exit 0.
    evidence_text = f"{stderr_text}\n{stdout_text}"
    if evidence_text.strip():
        block_found, matched = _stderr_matches_block(evidence_text, plat)
        if block_found:
            return "blocked", f"Security control indicator observed ({matched})"

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
        "exit_code": None,
        "error_message": None,
        "execution_time_ms": 0,
        "stdout": "",
        "stderr": "",
    }

    if not command or not command.strip():
        result["error_message"] = "Test has no command defined"
        return result
    if not executor:
        result["error_message"] = "Test has no executor defined"
        return result
    if test.get("runnable") is False:
        result["error_message"] = "Test is not marked runnable"
        return result
    if dry_run:
        result["verdict"] = "skipped"
        result["error_message"] = "Dry-run mode: test was not executed"
        return result

    for prerequisite in test.get("prerequisites", []):
        prereq_executor = prerequisite.get("executor") or executor
        check_command = prerequisite.get("check_command", "")
        get_command = prerequisite.get("get_command", "")
        description = prerequisite.get("description", "").strip()

        if check_command.strip():
            check = _execute_command(
                check_command, prereq_executor, prerequisite_timeout_seconds, plat
            )
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
                result["stdout"] = check["stdout"]
                result["stderr"] = check["stderr"]
            return result

        setup = _execute_command(
            get_command, prereq_executor, prerequisite_timeout_seconds, plat
        )
        if (not setup["process_started"] or setup["timed_out"]
                or setup["exit_code"] != 0):
            result["error_message"] = f"Prerequisite setup failed: {description}"
            result["stdout"] = setup["stdout"]
            result["stderr"] = setup["stderr"]
            return result

        if check_command.strip():
            recheck = _execute_command(
                check_command, prereq_executor, prerequisite_timeout_seconds, plat
            )
            if (not recheck["process_started"] or recheck["timed_out"]
                    or recheck["exit_code"] != 0):
                result["error_message"] = (
                    f"Prerequisite remains unsatisfied after setup: {description}"
                )
                result["stdout"] = recheck["stdout"]
                result["stderr"] = recheck["stderr"]
                return result

    execution = _execute_command(command, executor, timeout_seconds, plat)
    result["exit_code"] = execution["exit_code"]
    result["execution_time_ms"] = execution["execution_time_ms"]
    result["stdout"] = execution["stdout"]
    result["stderr"] = execution["stderr"]

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

    return result


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
{_c('    AUTHORIZED SECURITY TESTING ONLY', _CYAN)}
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
    allowed: int,
    errors: int,
    skipped: int,
) -> None:
    print()
    print(_c("  ============================================================", _CYAN))
    print(_c("    RESULTS SUMMARY", _CYAN))
    print(_c("  ============================================================", _CYAN))
    print(f"{_c('    Total tests : ', _WHITE)}{total}")
    print(f"{_c('    Blocked     : ', _WHITE)}{_c(str(blocked), _GREEN)}")
    print(f"{_c('    Allowed     : ', _WHITE)}{_c(str(allowed), _RED)}")
    print(f"{_c('    Errors      : ', _WHITE)}{_c(str(errors), _YELLOW)}")
    print(f"{_c('    Skipped     : ', _WHITE)}{_c(str(skipped), _DARK_GRAY)}")
    print(_c("  ============================================================", _CYAN))

    executed = blocked + allowed
    if executed > 0:
        score = round((blocked / executed) * 100, 1)
        if score >= 80:
            score_color = _GREEN
        elif score >= 50:
            score_color = _YELLOW
        else:
            score_color = _RED
        print(f"{_c('    Prevention  : ', _WHITE)}{_c(f'{score}% ({blocked}/{executed} tests blocked)', score_color)}")
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
    print(_c("    REMEDIATION NEEDED", _RED))
    print(_c("  ============================================================", _RED))
    print()
    print(f"    The following {len(allowed_results)} test(s) were NOT blocked:")
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


# ---------------------------------------------------------------------------
# Results upload
# ---------------------------------------------------------------------------

def _upload_results(
    server_url: str,
    results_endpoint: str,
    playbook_id: str,
    hostname: str,
    all_results: List[Dict[str, Any]],
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
        })

    if not payloads:
        return False, "No results to submit (all tests were skipped)", None

    body = json.dumps({
        "playbook_id": playbook_id,
        "hostname": hostname,
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
        print(f"  {_c('[*] Mode      : DRY RUN (no commands will be executed)', _YELLOW)}")

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
    all_results: List[Dict[str, Any]] = []
    summary = {"blocked": 0, "allowed": 0, "error": 0, "skipped": 0}

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
                "exit_code": None,
                "error_message": f"Test not applicable to platform: {plat}",
                "execution_time_ms": 0,
            })
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
                "exit_code": None,
                "error_message": "Test requires root but agent is not running as root",
                "execution_time_ms": 0,
            }
            all_results.append(skip_result)
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
        log_verdict = verdict if verdict in ("blocked", "allowed", "error") else "error"
        _write_log_line(
            log_path, test_name, technique_id, log_verdict,
            test_result.get("error_message", ""),
            test_result.get("execution_time_ms", 0),
            test_result.get("exit_code"),
        )

        # Cleanup (only if the test was allowed and not in dry-run mode)
        if verdict == "allowed" and not dry_run:
            _run_cleanup(
                test.get("cleanup_command"),
                test.get("executor", "sh"),
                plat,
            )

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    _print_summary(total_tests, summary["blocked"], summary["allowed"],
                   summary["error"], summary["skipped"])

    # Remediation
    allowed_results = [r for r in all_results if r["verdict"] == "allowed"]
    _print_remediation(allowed_results, tests_by_id)

    # ------------------------------------------------------------------
    # Save results locally
    # ------------------------------------------------------------------
    output_payload: Dict[str, Any] = {
        "atomic_prevention_version": __version__,
        "agent": "python",
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": hostname,
        "platform": plat,
        "os_version": os_ver,
        "playbook": {
            "id": pb_meta.get("id", ""),
            "name": pb_meta.get("name", ""),
            "adversary_group": pb_meta.get("adversary_group", ""),
        },
        "summary": summary,
        "results": [
            {
                "test_id": r["test_id"],
                "test_name": r.get("test_name", ""),
                "technique_id": r.get("technique_id", ""),
                "verdict": r["verdict"],
                "exit_code": r["exit_code"],
                "error_message": r["error_message"],
                "execution_time_ms": r["execution_time_ms"],
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
        )
        if success:
            print(f"  {_c('Upload successful. Run ID: ' + str(run_id_or_err), _GREEN)}")
            if srv_summary:
                print(
                    f"  {_c('Server summary -- Blocked: ' + str(srv_summary.get('blocked', 0)) + ', Allowed: ' + str(srv_summary.get('allowed', 0)) + ', Error: ' + str(srv_summary.get('error', 0)), _CYAN)}"
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
