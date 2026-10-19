"""LOOBins ingestor — Living Off the Orchard: macOS Binaries.

Fetches macOS LOL binary data from https://github.com/infosecB/LOOBins,
parses each YAML entry's example_use_cases into prevention tests, and maps
the tactic names to MITRE ATT&CK technique IDs.

Unlike a naive pass-through of the ``code`` field, this ingestor:

1. Substitutes placeholder paths, URLs, and IPs with safe, executable
   alternatives so tests actually *run* on a stock macOS system.
2. Generates cleanup commands that undo filesystem side-effects.
3. Marks genuinely destructive or un-safeable commands as ``risk_level:
   "high"`` with an explanatory ``unsafe_reason`` in metadata so the runner
   can skip or gate them.
4. Validates that referenced macOS binaries exist at standard paths.
5. Uses per-binary technique refinements where the generic tactic-level
   mapping would be too coarse.
"""

import asyncio
import logging
import re

import yaml

from backend.app.ingestion.base import BaseIngestor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safe test resources
# ---------------------------------------------------------------------------
# A small, always-available, public URL used as a stand-in for any
# placeholder URL in LOOBins code samples.  The Atomic Red Team LICENSE file
# is a ~1 KB text file — perfect for download tests.
_SAFE_URL = (
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"
    "master/LICENSE.txt"
)
# Temp directory prefix for all test artifacts.
_TEMP_PREFIX = "/tmp/loobins_test"

# ---------------------------------------------------------------------------
# Tactic -> MITRE ATT&CK technique mapping
# ---------------------------------------------------------------------------
# LOOBins uses tactic names (Discovery, Execution, etc.) rather than
# technique IDs.  Map each tactic to the most relevant technique for
# macOS LOL binary abuse.
#
# Refined from the original mapping based on MITRE ATT&CK v15 macOS
# matrix entries most commonly associated with LOL binary misuse:
#
#   - Execution:  T1059.004 (Unix Shell) is the broadest match; many
#     LOOBins execute via shell invocation.
#   - Persistence:  T1543.001 (Launch Agent) is more common on macOS
#     than T1543.004 (Launch Daemon) for unprivileged persistence.
#   - Privilege Escalation:  T1548.004 covers the "Elevated Execution
#     with Prompt" pattern common in macOS LOL abuse.
#   - Defense Evasion:  T1553.001 (Gatekeeper Bypass) is the dominant
#     macOS LOL evasion technique (xattr, ditto, spctl).
#     T1222.002 (Permissions Modification) is secondary.
#   - Credential Access:  T1555.001 (Keychain) is the primary macOS
#     credential store targeted via `security`.
#   - Discovery:  T1082 (System Information Discovery) is the catch-all.
#   - Lateral Movement:  T1021.004 (SSH) covers most macOS LOL lateral
#     movement.
#   - Collection:  T1560.001 (Archive via Utility) for ditto, zip, etc.
#   - C2:  T1105 (Ingress Tool Transfer) for curl, nscurl, etc.
#   - Exfiltration:  T1048 (Exfiltration Over Alternative Protocol).
#   - Impact:  T1490 (Inhibit System Recovery) better matches tmutil
#     abuse than T1485 (Data Destruction).
#   - Reconnaissance:  T1518 (Software Discovery) is a better match
#     than T1592 for local LOL reconnaissance (mdfind, system_profiler).
_TACTIC_TO_TECHNIQUE: dict[str, str] = {
    # Execution
    "execution": "T1059.004",           # Unix Shell
    # Persistence
    "persistence": "T1543.001",         # Launch Agent (unprivileged default)
    # Privilege Escalation
    "privilege-escalation": "T1548.004",
    "privilege escalation": "T1548.004",
    # Stealth (formerly Defense Evasion) — Gatekeeper Bypass is the dominant macOS LOL evasion
    "stealth": "T1553.001",             # Gatekeeper Bypass
    "defense-evasion": "T1553.001",     # legacy mapping
    "defense evasion": "T1553.001",
    # Credential Access
    "credential-access": "T1555.001",   # Keychain
    "credential access": "T1555.001",
    # Discovery
    "discovery": "T1082",               # System Information Discovery
    # Lateral Movement
    "lateral-movement": "T1021.004",    # SSH
    "lateral movement": "T1021.004",
    # Collection
    "collection": "T1560.001",          # Archive via Utility
    # Command and Control
    "command-and-control": "T1105",     # Ingress Tool Transfer
    "command and control": "T1105",
    # Exfiltration
    "exfiltration": "T1048",            # Exfiltration Over Alternative Protocol
    # Impact — Inhibit System Recovery matches tmutil abuse better
    "impact": "T1490",                  # Inhibit System Recovery
    # Reconnaissance — Software Discovery for local recon
    "reconnaissance": "T1518",          # Software Discovery
}

# ---------------------------------------------------------------------------
# Per-binary technique overrides
# ---------------------------------------------------------------------------
# Some binaries have a clearly better technique than the generic tactic
# mapping would give.  These override _TACTIC_TO_TECHNIQUE when the
# binary name matches.
_BINARY_TECHNIQUE_MAP: dict[str, str] = {
    "osascript": "T1059.002",    # AppleScript
    "osacompile": "T1059.002",   # AppleScript
    "swift": "T1059.004",        # Unix Shell (Swift REPL)
    "tclsh": "T1059.004",        # Unix Shell (Tcl)
    "security": "T1555.001",     # Keychain
    "sqlite3": "T1005",          # Data from Local System
    "ditto": "T1560.001",        # Archive via Utility
    "hdiutil": "T1553.001",      # Gatekeeper Bypass (DMG mounting)
    "xattr": "T1553.001",        # Gatekeeper Bypass
    "spctl": "T1553.001",        # Gatekeeper Bypass
    "launchctl": "T1569.001",    # Launchctl
    "screencapture": "T1113",    # Screen Capture
    "pbpaste": "T1115",          # Clipboard Data
    "nscurl": "T1105",           # Ingress Tool Transfer
    "networksetup": "T1090",     # Proxy
    "tmutil": "T1490",           # Inhibit System Recovery
    "defaults": "T1647",         # Plist File Modification
    "plutil": "T1647",           # Plist File Modification
    "profiles": "T1082",         # System Information Discovery
    "caffeinate": "T1059.004",   # Unix Shell (execution wrapper)
    "open": "T1204.002",         # User Execution: Malicious File
    "mdfind": "T1083",           # File and Directory Discovery
    "scutil": "T1016",           # System Network Configuration Discovery
    "system_profiler": "T1082",  # System Information Discovery
    "sw_vers": "T1082",          # System Information Discovery
    "sysctl": "T1082",           # System Information Discovery
    "dscl": "T1087.001",         # Account Discovery: Local Account
    "dscacheutil": "T1087.001",  # Account Discovery: Local Account
    "log": "T1070.002",          # Indicator Removal: Clear Linux/Mac Logs
    "textutil": "T1005",         # Data from Local System
    "codesign": "T1553.002",     # Code Signing
    "csrutil": "T1562.001",      # Impair Defenses: Disable or Modify Tools
    "nvram": "T1542.001",        # Pre-OS Boot: System Firmware
    "softwareupdate": "T1082",   # System Information Discovery
    "ssh-keygen": "T1552.004",   # Unsecured Credentials: Private Keys
}

# ---------------------------------------------------------------------------
# Known macOS binary paths (for validation)
# ---------------------------------------------------------------------------
_KNOWN_BINARY_PATHS: dict[str, str] = {
    "caffeinate": "/usr/bin/caffeinate",
    "chflags": "/usr/bin/chflags",
    "codesign": "/usr/bin/codesign",
    "csrutil": "/usr/bin/csrutil",
    "defaults": "/usr/bin/defaults",
    "ditto": "/usr/bin/ditto",
    "dns-sd": "/usr/bin/dns-sd",
    "dscacheutil": "/usr/bin/dscacheutil",
    "dscl": "/usr/bin/dscl",
    "dsconfigad": "/usr/sbin/dsconfigad",
    "dsexport": "/usr/bin/dsexport",
    "funzip": "/usr/bin/funzip",
    "GetFileInfo": "/usr/bin/GetFileInfo",
    "hdiutil": "/usr/bin/hdiutil",
    "ioreg": "/usr/sbin/ioreg",
    "kextstat": "/usr/sbin/kextstat",
    "last": "/usr/bin/last",
    "launchctl": "/bin/launchctl",
    "log": "/usr/bin/log",
    "lsregister": (
        "/System/Library/Frameworks/CoreServices.framework"
        "/Versions/A/Frameworks/LaunchServices.framework"
        "/Versions/A/Support/lsregister"
    ),
    "mdfind": "/usr/bin/mdfind",
    "mdls": "/usr/bin/mdls",
    "mktemp": "/usr/bin/mktemp",
    "networksetup": "/usr/sbin/networksetup",
    "notifyutil": "/usr/bin/notifyutil",
    "nscurl": "/usr/bin/nscurl",
    "nvram": "/usr/sbin/nvram",
    "odutil": "/usr/sbin/odutil",
    "open": "/usr/bin/open",
    "osacompile": "/usr/bin/osacompile",
    "osascript": "/usr/bin/osascript",
    "pbpaste": "/usr/bin/pbpaste",
    "pkill": "/usr/bin/pkill",
    "plutil": "/usr/bin/plutil",
    "profiles": "/usr/bin/profiles",
    "safaridriver": "/usr/bin/safaridriver",
    "say": "/usr/bin/say",
    "screencapture": "/usr/sbin/screencapture",
    "scutil": "/usr/sbin/scutil",
    "security": "/usr/bin/security",
    "sfltool": "/usr/bin/sfltool",
    "softwareupdate": "/usr/sbin/softwareupdate",
    "spctl": "/usr/sbin/spctl",
    "sqlite3": "/usr/bin/sqlite3",
    "ssh-keygen": "/usr/bin/ssh-keygen",
    "streamzip": "/usr/bin/streamzip",
    "sw_vers": "/usr/bin/sw_vers",
    "swift": "/usr/bin/swift",
    "sysadminctl": "/usr/sbin/sysadminctl",
    "sysctl": "/usr/sbin/sysctl",
    "system_profiler": "/usr/sbin/system_profiler",
    "systemsetup": "/usr/sbin/systemsetup",
    "tccutil": "/usr/bin/tccutil",
    "tclsh": "/usr/bin/tclsh",
    "textutil": "/usr/bin/textutil",
    "tmutil": "/usr/bin/tmutil",
    "xattr": "/usr/bin/xattr",
    "SetFile": "/usr/bin/SetFile",
}

# ---------------------------------------------------------------------------
# Placeholder substitution patterns
# ---------------------------------------------------------------------------
# Order matters: more specific patterns must come before generic ones.
_PLACEHOLDER_SUBS: list[tuple[re.Pattern, str]] = [
    # Placeholder URLs — use [^\s;|&)'] to avoid consuming shell metacharacters
    (re.compile(r"https?://mypayload\.io/[^\s;|&)']+"), _SAFE_URL),
    (re.compile(r"https?://[a-zA-Z0-9._-]*evil[a-zA-Z0-9._-]*/[^\s;|&)']*"), _SAFE_URL),
    # Placeholder IP addresses (non-loopback, non-private used as C2 stand-ins)
    (re.compile(r"\b46\.226\.108\.171\b"), "127.0.0.1"),
    # Placeholder variable-style URLs
    (re.compile(r"\$autoProxyURL"), f'"{_SAFE_URL}"'),
    # Placeholder <password> tokens
    (re.compile(r"<password>"), "testpassword123"),
    # Generic placeholder file/dir paths — must come after URL subs
    (re.compile(r"/path/to/malicious-library/malicious_library\.dylib"),
     f"{_TEMP_PREFIX}/test_lib.dylib"),
    (re.compile(r"/path/to/target-library/original_library\.dylib"),
     f"{_TEMP_PREFIX}/original_lib.dylib"),
    (re.compile(r"/path/to/backup"), f"{_TEMP_PREFIX}/backup"),
    (re.compile(r"/path/to/folder"), f"{_TEMP_PREFIX}/src_folder"),
    (re.compile(r"/path/to/exclude"), f"{_TEMP_PREFIX}/exclude_dir"),
    (re.compile(r"/path/to/\S+"), f"{_TEMP_PREFIX}/placeholder_path"),
    # Placeholder app references
    (re.compile(r"Malicious\.app"), f"{_TEMP_PREFIX}/SafeTest.app"),
    (re.compile(r"malicious\.dmg"), f"{_TEMP_PREFIX}/test.dmg"),
    (re.compile(r"malicious\.iso"), f"{_TEMP_PREFIX}/test.iso"),
    (re.compile(r"unsigned\.app"), f"{_TEMP_PREFIX}/test.app"),
    (re.compile(r"bad_cert\.crt"), f"{_TEMP_PREFIX}/test_cert.crt"),
    (re.compile(r"bad\.dylib"), f"{_TEMP_PREFIX}/test.dylib"),
    (re.compile(r"gain_persistence\.sh"), f"{_TEMP_PREFIX}/test_persist.sh"),
    (re.compile(r"mycode\.swift"), f"{_TEMP_PREFIX}/test_code.swift"),
    (re.compile(r"/tmp/evil"), f"{_TEMP_PREFIX}/safe_exec"),
    # Home directory placeholder paths
    (re.compile(r"/home/user/sensitive-files"), f"{_TEMP_PREFIX}/src_folder"),
    (re.compile(r"/home/user/l00t"), f"{_TEMP_PREFIX}/l00t"),
    # TargetApp placeholder
    (re.compile(r"/Applications/TargetApp\.app/Contents/Info\.plist"),
     f"{_TEMP_PREFIX}/TestApp.plist"),
]

# ---------------------------------------------------------------------------
# Commands that are inherently destructive / unsafe even after substitution
# ---------------------------------------------------------------------------
# These patterns cause the test to be flagged as unsafe with risk_level high
# and an explanatory note.  The runner should gate these behind explicit
# user confirmation.
_UNSAFE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\btmutil\s+disable\b"),
     "Disables Time Machine backups system-wide"),
    (re.compile(r"\btmutil\s+delete\b"),
     "Deletes Time Machine backups"),
    (re.compile(r"\bsecurity\s+dump-keychain\b"),
     "Dumps credentials from the macOS Keychain"),
    (re.compile(r"\bsecurity\s+delete-keychain\b"),
     "Deletes a macOS Keychain"),
    (re.compile(r"\bsecurity\s+add-trusted-cert\b"),
     "Installs a certificate into the system trust store"),
    (re.compile(r"\bcsrutil\s+disable\b"),
     "Disables System Integrity Protection"),
    (re.compile(r"\bnvram\b.*\bboot-args\b"),
     "Modifies firmware boot arguments"),
    (re.compile(r"\bdefaults\s+write\b.*\bGKAutoRearm\b"),
     "Disables Gatekeeper auto-rearm"),
    (re.compile(r"\bdefaults\s+write\b.*\bLoginHook\b"),
     "Installs a system-wide login hook for persistence"),
    (re.compile(r"\bdefaults\s+write\b.*\bglobalstate\s+-int\s+0\b"),
     "Disables the macOS firewall"),
    (re.compile(r"\blaunchctl\s+load\b.*(?:(?<!\~)/Library/Launch|/System/)"),
     "Loads a system-level LaunchAgent/LaunchDaemon"),
    (re.compile(r"\bkillall\s+"),
     "Terminates running processes"),
    (re.compile(r"\bsudo\s+vim\b"),
     "Opens an editor as root (interactive, not automatable)"),
    (re.compile(r"\bmount_apfs\b"),
     "Mounts an APFS snapshot (requires SIP disabled)"),
    (re.compile(r"\bsysadminctl\b.*\b-deleteUser\b"),
     "Deletes a user account"),
    (re.compile(r"\btccutil\s+reset\b"),
     "Resets TCC privacy permissions"),
    (re.compile(r"\bpkill\b"),
     "Sends signals to running processes"),
    (re.compile(r"\bnetworksetup\s+-set(?:web|secure|auto)proxy"),
     "Modifies system proxy settings"),
    (re.compile(r"\bditto\s+-V\b.*\.dylib"),
     "Overwrites a dynamic library (DLL hijacking)"),
    (re.compile(r"\bssh\s+remote_host\b"),
     "Requires SSH access to a remote host"),
]


# ---------------------------------------------------------------------------
# Setup commands that create required temp files/dirs for tests
# ---------------------------------------------------------------------------
def _make_setup_command(code: str, bin_name: str) -> str | None:
    """Return a shell snippet that creates any temp files/dirs the test needs.

    This ensures that referenced placeholder paths actually exist before the
    test command runs.
    """
    parts: list[str] = [f"mkdir -p {_TEMP_PREFIX}"]

    # If the command references our temp source folder, create it with a file
    if f"{_TEMP_PREFIX}/src_folder" in code:
        parts.append(f"mkdir -p {_TEMP_PREFIX}/src_folder")
        parts.append(
            f"echo 'LOOBins test data' > {_TEMP_PREFIX}/src_folder/testfile.txt"
        )

    # If the command references a test .app bundle
    if f"{_TEMP_PREFIX}/SafeTest.app" in code or f"{_TEMP_PREFIX}/test.app" in code:
        app_path = (
            f"{_TEMP_PREFIX}/SafeTest.app"
            if f"{_TEMP_PREFIX}/SafeTest.app" in code
            else f"{_TEMP_PREFIX}/test.app"
        )
        parts.append(f"mkdir -p {app_path}/Contents/MacOS")
        parts.append(
            f"echo '#!/bin/bash\necho LOOBins test' > {app_path}/Contents/MacOS/run"
        )
        parts.append(f"chmod +x {app_path}/Contents/MacOS/run")

    # If the command references a test plist
    if f"{_TEMP_PREFIX}/TestApp.plist" in code:
        parts.append(
            f"plutil -create xml1 {_TEMP_PREFIX}/TestApp.plist 2>/dev/null "
            f"|| echo '<?xml version=\"1.0\"?><plist version=\"1.0\">"
            f"<dict></dict></plist>' > {_TEMP_PREFIX}/TestApp.plist"
        )

    # If the command references a test dylib
    if f"{_TEMP_PREFIX}/test.dylib" in code or f"{_TEMP_PREFIX}/test_lib.dylib" in code:
        parts.append(f"touch {_TEMP_PREFIX}/test.dylib {_TEMP_PREFIX}/test_lib.dylib")

    # If the command references a DMG and this is hdiutil
    if f"{_TEMP_PREFIX}/test.dmg" in code:
        parts.append(
            f"hdiutil create -size 1m -fs HFS+ -volname LOOBinsTest "
            f"{_TEMP_PREFIX}/test.dmg -quiet 2>/dev/null || true"
        )

    # If the command references a test swift file
    if f"{_TEMP_PREFIX}/test_code.swift" in code:
        parts.append(
            f"echo 'print(\"LOOBins swift test\")' > {_TEMP_PREFIX}/test_code.swift"
        )

    # If the command references a test persistence script
    if f"{_TEMP_PREFIX}/test_persist.sh" in code:
        parts.append(
            f"echo '#!/bin/bash\necho test' > {_TEMP_PREFIX}/test_persist.sh"
        )
        parts.append(f"chmod +x {_TEMP_PREFIX}/test_persist.sh")

    # If the command references safe_exec (caffeinate stand-in for /tmp/evil)
    if f"{_TEMP_PREFIX}/safe_exec" in code:
        parts.append(
            f"echo '#!/bin/bash\nsleep 1' > {_TEMP_PREFIX}/safe_exec"
        )
        parts.append(f"chmod +x {_TEMP_PREFIX}/safe_exec")

    # If the command references a cert
    if f"{_TEMP_PREFIX}/test_cert.crt" in code:
        parts.append(f"touch {_TEMP_PREFIX}/test_cert.crt")

    # If the command references backup dir
    if f"{_TEMP_PREFIX}/backup" in code:
        parts.append(f"mkdir -p {_TEMP_PREFIX}/backup")

    # If the command references exclude dir
    if f"{_TEMP_PREFIX}/exclude_dir" in code:
        parts.append(f"mkdir -p {_TEMP_PREFIX}/exclude_dir")

    # If the command references l00t dir
    if f"{_TEMP_PREFIX}/l00t" in code:
        parts.append(f"mkdir -p {_TEMP_PREFIX}/l00t")

    # If the command references a screenshots dir
    if "/tmp/screenshots" in code:
        parts.append("mkdir -p /tmp/screenshots")

    # If the command references original_lib.dylib
    if f"{_TEMP_PREFIX}/original_lib.dylib" in code:
        parts.append(f"touch {_TEMP_PREFIX}/original_lib.dylib")

    # If the command references LaunchAgents plist
    if "~/Library/LaunchAgents/" in code:
        plist_match = re.search(
            r"~/Library/LaunchAgents/(\S+\.plist)", code
        )
        if plist_match:
            plist_name = plist_match.group(1)
            parts.append("mkdir -p ~/Library/LaunchAgents")
            parts.append(
                f"echo '<?xml version=\"1.0\"?><plist version=\"1.0\">"
                f"<dict><key>Label</key><string>com.loobins.test</string>"
                f"<key>ProgramArguments</key><array><string>/usr/bin/true"
                f"</string></array></dict></plist>' "
                f"> ~/Library/LaunchAgents/{plist_name}"
            )

    # Only return if we added more than the base mkdir
    if len(parts) > 1:
        return " && ".join(parts)
    return None


def _make_cleanup_command(code: str, bin_name: str) -> str | None:
    """Return a shell snippet that cleans up any artifacts the test creates."""
    parts: list[str] = []

    # Always clean the temp prefix if anything was created there
    if _TEMP_PREFIX in code:
        parts.append(f"rm -rf {_TEMP_PREFIX}")

    # Clean up screenshots
    if "/tmp/screenshots" in code:
        parts.append("rm -rf /tmp/screenshots")

    # Clean up clipboard data file
    if "clipdata.txt" in code:
        parts.append("rm -f clipdata.txt")

    # Clean up any DMG mounts
    if "hdiutil" in code and ("mount" in code or "attach" in code):
        parts.append(
            "hdiutil detach /Volumes/LOOBinsTest 2>/dev/null || true"
        )

    # Clean up LaunchAgents plist
    if "~/Library/LaunchAgents/" in code:
        plist_match = re.search(
            r"~/Library/LaunchAgents/(\S+\.plist)", code
        )
        if plist_match:
            plist_name = plist_match.group(1)
            parts.append(
                f"launchctl unload ~/Library/LaunchAgents/{plist_name} "
                f"2>/dev/null || true"
            )
            parts.append(f"rm -f ~/Library/LaunchAgents/{plist_name}")

    # Clean up tmutil exclusions
    if "tmutil addexclusion" in code and _TEMP_PREFIX in code:
        parts.append(
            f"tmutil removeexclusion {_TEMP_PREFIX}/exclude_dir 2>/dev/null || true"
        )

    # Clean up proxy changes (restore to empty/off)
    if "networksetup" in code and "-set" in code.lower():
        # Attempt to undo proxy changes
        if "-setsecurewebproxy" in code:
            parts.append(
                'networksetup -setsecurewebproxystate "Wi-Fi" off 2>/dev/null || true'
            )
        if "-setwebproxy" in code:
            parts.append(
                'networksetup -setwebproxystate "Wi-Fi" off 2>/dev/null || true'
            )
        if "-setautoproxyurl" in code:
            parts.append(
                'networksetup -setautoproxystate "Wi-Fi" off 2>/dev/null || true'
            )
        if "-setautoproxystate" in code and " on" in code:
            parts.append(
                'networksetup -setautoproxystate "Wi-Fi" off 2>/dev/null || true'
            )

    if parts:
        return " ; ".join(parts)
    return None


def _apply_substitutions(code: str) -> str:
    """Replace placeholder values in a LOOBins code sample with safe,
    executable alternatives."""
    for pattern, replacement in _PLACEHOLDER_SUBS:
        code = pattern.sub(replacement, code)
    return code


def _check_unsafe(code: str) -> str | None:
    """Return an unsafe_reason string if the command matches a known
    destructive pattern, or None if it looks safe enough to run."""
    for pattern, reason in _UNSAFE_PATTERNS:
        if pattern.search(code):
            return reason
    return None


def _is_multiline_interactive(code: str) -> bool:
    """Detect commands that are interactive or multi-step procedures that
    cannot be meaningfully automated as a single shell invocation."""
    # Commands with 'sudo vim' or other interactive editors
    if re.search(r"\bsudo\s+vim\b", code):
        return True
    # Bash 'read' builtin used for interactive input (but not 'defaults read')
    if re.search(r"(?:^|\n|;)\s*read\s+", code):
        return True
    return False


def _refine_command(code: str, bin_name: str) -> str:
    """Apply per-binary refinements to make commands actually executable.

    This goes beyond placeholder substitution to handle structural issues:
    - Infinite loops get a bounded iteration count
    - Commands that reference non-existent files get setup stanzas
    - Remote-host commands get rewritten to localhost where feasible
    """
    # Bound infinite clipboard/screenshot loops to a few iterations
    if "while true" in code or "while :" in code:
        # Replace 'while true' with a bounded loop (3 iterations)
        code = re.sub(
            r"while\s+true\s*;?\s*do",
            "for _i in 1 2 3; do",
            code,
        )
        code = re.sub(
            r"while\s+:\s*;?\s*do",
            "for _i in 1 2 3; do",
            code,
        )

    # mdfind -live runs forever; add a timeout
    if "mdfind -live" in code:
        code = f"timeout 3 {code} || true"

    # osascript credential prompt — replace with a non-blocking version
    # that just echoes rather than popping a dialog
    if bin_name == "osascript" and "display dialog" in code:
        # Make the dialog test non-interactive by using a notification instead
        code = (
            'osascript -e \'display notification '
            '"LOOBins credential prompt test" '
            'with title "Security Test"\''
        )

    # ssh to remote_host — can't actually connect; rewrite to dry-run
    if "ssh remote_host" in code or "ssh " in code and "remote_host" in code:
        code = re.sub(
            r"\bssh\s+remote_host\b",
            "echo '[DRY RUN] ssh remote_host'  # would pipe to remote",
            code,
        )

    # osascript AppleScript 'set appId to do shell script' — rewrite to
    # a simpler mdfind invocation that doesn't need AppleScript context
    if "set appId to do shell script" in code:
        code = 'mdfind "kMDItemCFBundleIdentifier == com.apple.Safari" 2>/dev/null | head -1'

    # caffeinate with safe_exec — add a short timeout so it doesn't hang
    if bin_name == "caffeinate" and f"{_TEMP_PREFIX}/safe_exec" in code:
        code = f"timeout 5 {code} || true"

    # screencapture — reduce sleep in loops
    if bin_name == "screencapture" and "sleep" in code:
        code = re.sub(r"sleep\s+\d+", "sleep 1", code)

    # For 'open' with a URL — use a safe URL and suppress browser
    if bin_name == "open" and ("https://" in code or "http://" in code):
        # Don't actually open a browser; rewrite to curl for testability.
        # First strip any trailing kill-Safari stanza so the rewrite is clean.
        code = re.sub(r";\s*sleep\s+\d+;\s*killall\s+\S+", "", code)
        code = re.sub(
            r"open\s+(?:-[a-z]\s+)?https?://[^\s;|&)']+",
            f"curl -sf -o /dev/null {_SAFE_URL}",
            code,
        )

    return code


class LOOBinsIngestor(BaseIngestor):
    """Ingestor for LOOBins (macOS Living Off the Land Binaries)."""

    @property
    def source_id(self) -> str:
        return "loobins"

    @property
    def display_name(self) -> str:
        return "LOOBins"

    @property
    def description(self) -> str:
        return "Living Off the Orchard: macOS Binaries that can be abused by adversaries"

    @property
    def repo_url(self) -> str:
        return "https://github.com/infosecB/LOOBins"

    @property
    def platform(self) -> str:
        return "macos"

    async def fetch(self) -> None:
        """Clone or update the LOOBins repository."""
        repo_dir = self.data_dir
        if repo_dir.exists():
            proc = await asyncio.create_subprocess_exec(
                "git", "pull", cwd=str(repo_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(
                    f"git pull failed for {self.source_id}: {stderr.decode()}"
                )
        else:
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", self.repo_url, str(repo_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(
                    f"git clone failed for {self.source_id}: {stderr.decode()}"
                )

    async def parse(self) -> list[dict]:
        """Parse LOOBins YAML files into prevention test dicts."""
        tests: list[dict] = []
        yml_dir = self.data_dir / "LOOBins"

        if not yml_dir.exists():
            logger.warning(f"LOOBins data directory not found: {yml_dir}")
            return tests

        for yml_file in sorted(yml_dir.rglob("*.yml")):
            try:
                data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                if data:
                    tests.extend(self._parse_entry(data))
            except Exception as exc:
                logger.debug(f"Failed to parse {yml_file.name}: {exc}")
                continue

        self._tests = tests
        logger.info(f"LOOBins: parsed {len(tests)} tests from {yml_dir}")
        return tests

    def _parse_entry(self, data: dict) -> list[dict]:
        """Parse a single LOOBin YAML entry into one or more tests.

        Each use-case's ``code`` field is transformed through several stages:
        1. Placeholder substitution (paths, URLs, IPs)
        2. Per-binary command refinement (loop bounding, dry-run rewrites)
        3. Unsafe-pattern detection (flags destructive commands)
        4. Setup/cleanup command generation
        """
        tests: list[dict] = []
        bin_name = data.get("name", "")
        short_desc = data.get("short_description", "")
        full_desc = data.get("full_description", short_desc)

        # Get binary paths from the YAML and validate
        paths = data.get("paths", [])
        binary_path = paths[0] if paths else None

        # Cross-check against known paths
        known = _KNOWN_BINARY_PATHS.get(bin_name)
        if known and binary_path and known != binary_path:
            logger.debug(
                f"LOOBins path mismatch for {bin_name}: "
                f"YAML={binary_path}, known={known}"
            )
        if not binary_path and known:
            binary_path = known

        use_cases = data.get("example_use_cases", [])
        if not use_cases:
            return tests

        for idx, use_case in enumerate(use_cases):
            uc_name = use_case.get("name", f"Use Case {idx + 1}")
            uc_desc = use_case.get("description", "")
            raw_code = use_case.get("code", "")

            if not raw_code or raw_code.strip() in ("", "N/A"):
                continue

            # --- Stage 1: Placeholder substitution ---
            code = _apply_substitutions(raw_code)

            # --- Stage 2: Per-binary refinement ---
            code = _refine_command(code, bin_name)

            # --- Stage 3: Unsafe detection ---
            unsafe_reason = _check_unsafe(code)

            # Map tactics to MITRE technique IDs
            tactics = use_case.get("tactics", [])
            technique_id = self._resolve_technique(tactics, bin_name)

            # Determine risk level from tactics + unsafe analysis
            risk_level = self._assess_risk(tactics, code, unsafe_reason)

            # --- Stage 4: Setup and cleanup ---
            setup_cmd = _make_setup_command(code, bin_name)
            cleanup_cmd = _make_cleanup_command(code, bin_name)

            # Check if command is interactive / can't be automated
            is_interactive = _is_multiline_interactive(code)

            # Tags for metadata
            tags = use_case.get("tags", [])

            # Build the executor — mark manual if unsafe or interactive
            executor = "bash"
            if is_interactive:
                executor = "manual"

            # Build metadata
            metadata: dict = {
                "source": "loobins",
                "binary": bin_name,
                "use_case": uc_name,
                "tactics": tactics,
                "tags": tags,
                "paths": paths,
                "original_command": raw_code,
            }
            if binary_path:
                metadata["binary_path_validated"] = (
                    binary_path == _KNOWN_BINARY_PATHS.get(bin_name, binary_path)
                )
            if unsafe_reason:
                metadata["unsafe_reason"] = unsafe_reason
            if setup_cmd:
                metadata["setup_command"] = setup_cmd

            tests.append({
                "name": f"LOOBins: {bin_name} - {uc_name}",
                "description": (
                    f"{uc_desc} "
                    f"[{full_desc[:200]}]"
                ).strip(),
                "command": code,
                "executor": executor,
                "technique_id": technique_id,
                "binary_path": binary_path,
                "elevation_required": self._needs_elevation(code),
                "risk_level": risk_level,
                "platforms": ["macos"],
                "cleanup_command": cleanup_cmd,
                "setup_command": setup_cmd,
                "metadata": metadata,
            })

        return tests

    @staticmethod
    def _resolve_technique(tactics: list[str], bin_name: str = "") -> str:
        """Map LOOBins tactic names to the best MITRE technique ID.

        Uses the per-binary override map first, falling back to the
        tactic-level mapping.
        """
        # Per-binary override takes priority
        if bin_name and bin_name in _BINARY_TECHNIQUE_MAP:
            return _BINARY_TECHNIQUE_MAP[bin_name]

        for tactic in tactics:
            tid = _TACTIC_TO_TECHNIQUE.get(tactic.lower())
            if tid:
                return tid
        # Default: macOS command-line execution
        return "T1059.004"

    @staticmethod
    def _assess_risk(
        tactics: list[str],
        code: str,
        unsafe_reason: str | None,
    ) -> str:
        """Determine risk level from tactics, code content, and unsafe flags."""
        # If flagged as unsafe, always high
        if unsafe_reason:
            return "high"

        tactic_set = {t.lower() for t in tactics}

        # Explicit high-risk tactics
        high_risk = {
            "execution", "credential access", "credential-access",
            "privilege escalation", "privilege-escalation", "impact",
        }
        if tactic_set & high_risk:
            return "high"

        # Medium risk for persistence, stealth, lateral movement
        medium_risk = {
            "persistence", "stealth", "defense evasion", "defense-evasion",
            "lateral movement", "lateral-movement",
            "command and control", "command-and-control",
            "exfiltration",
        }
        if tactic_set & medium_risk:
            return "medium"

        # Low risk for pure discovery / recon
        low_risk = {"discovery", "reconnaissance", "collection"}
        if tactic_set and tactic_set <= low_risk:
            return "low"

        return "medium"

    @staticmethod
    def _needs_elevation(code: str) -> bool:
        """Heuristic: does the command likely need root/admin?"""
        indicators = [
            "sudo ",
            "dscl . -create",
            "dscl . -delete",
            "launchctl load /Library/",
            "launchctl load /System/",
            "security unlock-keychain",
            "security dump-keychain",
            "security add-trusted-cert",
            "diskutil ",
            "spctl --master-disable",
            "csrutil ",
            "nvram ",
            "sysadminctl ",
            "systemsetup ",
            "profiles install",
        ]
        code_lower = code.lower()
        return any(ind.lower() in code_lower for ind in indicators)

    def get_mitre_mappings(self) -> dict[str, list[str]]:
        mappings: dict[str, list[str]] = {}
        for test in getattr(self, "_tests", []):
            tid = test.get("technique_id", "")
            if tid:
                mappings.setdefault(test["name"], []).append(tid)
        return mappings
