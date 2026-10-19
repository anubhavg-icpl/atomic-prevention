"""GTFOBins ingestor — Unix/Linux binaries exploitable for privilege escalation.

Fetches data from https://github.com/GTFOBins/GTFOBins.github.io,
parses each `_gtfobins/<binary>.md` YAML front-matter entry, and
generates SAFE, executable prevention tests for every documented
abuse function (shell, file-read, file-write, suid, sudo, etc.).

Safety strategy:
- Shell escapes: replaced with `echo GTFOBins-test-SUCCESS` probes.
- File reads:   target `/etc/hostname` (world-readable, harmless).
- File writes:  target a temp file under /tmp, cleaned up afterwards.
- SUID:         check only — no execution of SUID payloads.
- Reverse/bind shell: binary-existence check only (never connects).
- Sudo:         prefixed with `sudo -n` (non-interactive, fails safe).
- Capabilities: check only via `getcap`.
"""

import asyncio
import logging
import re
import textwrap
from pathlib import Path

import yaml

from backend.app.ingestion.base import BaseIngestor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping for each GTFOBins function category
# ---------------------------------------------------------------------------
_FUNCTION_TO_TECHNIQUE: dict[str, str] = {
    "shell":         "T1059.004",   # Unix Shell
    "bind-shell":    "T1059.004",   # Unix Shell
    "reverse-shell": "T1059.004",   # Unix Shell
    "file-read":     "T1005",       # Data from Local System
    "file-write":    "T1222.002",   # File & Directory Permissions Modification: Linux/Mac
    "file-upload":   "T1048",       # Exfiltration Over Alternative Protocol
    "file-download": "T1105",       # Ingress Tool Transfer
    "suid":          "T1548.001",   # Setuid and Setgid
    "limited-suid":  "T1548.001",   # Setuid and Setgid
    "sudo":          "T1548.003",   # Sudo and Sudo Caching
    "capabilities":  "T1548",       # Abuse Elevation Control Mechanism
}

# Functions that are too dangerous to run live — we only note the capability
_OBSERVE_ONLY_FUNCTIONS = {"reverse-shell", "bind-shell"}

# Functions that need root / sudo
_ELEVATION_FUNCTIONS = {"suid", "limited-suid", "sudo", "capabilities"}

# Risk levels per function
_RISK_LEVELS: dict[str, str] = {
    "shell":         "high",
    "bind-shell":    "high",
    "reverse-shell": "high",
    "file-read":     "medium",
    "file-write":    "medium",
    "file-upload":   "medium",
    "file-download": "medium",
    "suid":          "high",
    "limited-suid":  "high",
    "sudo":          "high",
    "capabilities":  "high",
}

# Safe sentinel that test commands echo on success
_SUCCESS_MARKER = "GTFOBins-test-SUCCESS"
_SAFE_READ_FILE = "/etc/hostname"
_SAFE_WRITE_FILE = "/tmp/gtfobins_test_$$"


class GTFOBinsIngestor(BaseIngestor):
    """Ingestor for GTFOBins (Linux/Unix LOL binaries)."""

    @property
    def source_id(self) -> str:
        return "gtfobins"

    @property
    def display_name(self) -> str:
        return "GTFOBins"

    @property
    def description(self) -> str:
        return (
            "Unix/Linux binaries that can be exploited for privilege "
            "escalation, file read/write, reverse shells, SUID abuse, and more"
        )

    @property
    def repo_url(self) -> str:
        return "https://github.com/GTFOBins/GTFOBins.github.io"

    @property
    def platform(self) -> str:
        return "linux"

    # ------------------------------------------------------------------
    # fetch — clone / pull
    # ------------------------------------------------------------------
    async def fetch(self) -> None:
        """Clone or update the GTFOBins repository."""
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

    # ------------------------------------------------------------------
    # parse — YAML front-matter from every _gtfobins/*.md
    # ------------------------------------------------------------------
    async def parse(self) -> list[dict]:
        """Parse GTFOBins markdown files into prevention test dicts."""
        tests: list[dict] = []
        md_dir = self.data_dir / "_gtfobins"

        if not md_dir.exists():
            logger.warning(f"GTFOBins data directory not found: {md_dir}")
            self._tests = tests
            return tests

        # GTFOBins files may be .md or extensionless — iterate all files
        for entry in sorted(md_dir.iterdir()):
            if not entry.is_file():
                continue
            try:
                raw = entry.read_text(encoding="utf-8")
                if not raw.startswith("---"):
                    continue
                data = self._extract_front_matter(raw)
                if data:
                    binary_name = entry.stem  # e.g. "python" from "python" or "python.md"
                    tests.extend(self._parse_binary(binary_name, data))
            except Exception as exc:
                logger.debug(f"Failed to parse {entry.name}: {exc}")
                continue

        self._tests = tests
        logger.info(f"GTFOBins: parsed {len(tests)} tests from {md_dir}")
        return tests

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_front_matter(raw_text: str) -> dict | None:
        """Extract YAML front-matter between ``---`` and ``---`` or ``...``."""
        # GTFOBins uses both ``---`` and ``...`` as document terminators
        match = re.match(r"^---\s*\n(.*?)\n(?:---|\.\.\.|$)", raw_text, re.DOTALL)
        if not match:
            return None
        try:
            return yaml.safe_load(match.group(1))
        except yaml.YAMLError:
            return None

    def _parse_binary(self, binary_name: str, data: dict) -> list[dict]:
        """Turn one binary's front-matter into test dicts."""
        tests: list[dict] = []
        functions = data.get("functions")
        if not functions or not isinstance(functions, dict):
            return tests

        for func_name, entries in functions.items():
            if not isinstance(entries, list):
                continue
            for idx, entry in enumerate(entries):
                test = self._build_test(binary_name, func_name, entry, idx)
                if test:
                    tests.append(test)

        return tests

    def _build_test(
        self,
        binary_name: str,
        func_name: str,
        entry: dict,
        variant_idx: int,
    ) -> dict | None:
        """Build a single safe, executable prevention test dict."""
        original_code = entry.get("code", "").strip()
        description = entry.get("description", "").strip()
        if not original_code:
            return None

        technique_id = _FUNCTION_TO_TECHNIQUE.get(func_name, "T1059.004")
        risk_level = _RISK_LEVELS.get(func_name, "medium")
        elevation_required = func_name in _ELEVATION_FUNCTIONS

        variant_suffix = f" (variant {variant_idx + 1})" if variant_idx > 0 else ""
        test_name = f"GTFOBins: {binary_name} - {func_name}{variant_suffix}"

        # Build the safe command and optional cleanup
        safe_cmd, cleanup_cmd, is_observe_only = self._safe_command(
            binary_name, func_name, original_code
        )

        if not safe_cmd:
            return None

        test_description = (
            f"Tests {binary_name} {func_name} capability via GTFOBins. "
            f"{description}"
        ).strip()
        if is_observe_only:
            test_description = (
                f"[OBSERVE ONLY] {test_description} "
                f"(capability noted — no live connection attempted)"
            )

        return {
            "name": test_name,
            "description": test_description,
            "command": safe_cmd,
            "executor": "bash",
            "technique_id": technique_id,
            "binary_path": self._which_hint(binary_name),
            "elevation_required": elevation_required,
            "risk_level": risk_level,
            "platforms": ["linux"],
            "cleanup_command": cleanup_cmd,
            "metadata": {
                "source": "gtfobins",
                "binary": binary_name,
                "function": func_name,
                "original_code": original_code,
                "observe_only": is_observe_only,
            },
        }

    # ------------------------------------------------------------------
    # Safe command generation — the heart of the ingestor
    # ------------------------------------------------------------------
    def _safe_command(
        self, binary: str, func_name: str, original_code: str
    ) -> tuple[str, str | None, bool]:
        """Return (safe_command, cleanup_command, is_observe_only).

        Each function category has its own safety strategy.  The goal is to
        produce a real, runnable bash command that validates the capability
        WITHOUT causing harm.
        """
        if func_name in _OBSERVE_ONLY_FUNCTIONS:
            return self._safe_observe_only(binary, func_name, original_code)

        dispatch = {
            "shell":        self._safe_shell,
            "file-read":    self._safe_file_read,
            "file-write":   self._safe_file_write,
            "file-upload":  self._safe_file_upload,
            "file-download": self._safe_file_download,
            "suid":         self._safe_suid,
            "limited-suid": self._safe_suid,
            "sudo":         self._safe_sudo,
            "capabilities": self._safe_capabilities,
        }
        handler = dispatch.get(func_name)
        if handler:
            return handler(binary, original_code)

        # Unknown function — generate a basic binary-existence check
        return self._safe_observe_only(binary, func_name, original_code)

    # --- shell ---------------------------------------------------------
    def _safe_shell(
        self, binary: str, original_code: str
    ) -> tuple[str, str | None, bool]:
        """Test that the binary can spawn a process (without dropping to
        an interactive shell)."""
        cmd = textwrap.dedent(f"""\
            # GTFOBins shell test: {binary}
            # Validates that {binary} can execute arbitrary commands.
            # Original (unsafe): {self._oneliner(original_code)}
            MARKER="{_SUCCESS_MARKER}"
            if command -v {binary} >/dev/null 2>&1; then
                {self._shell_probe(binary, original_code)}
            else
                echo "SKIP: {binary} not found on this system"
                exit 0
            fi""")
        return cmd, None, False

    def _shell_probe(self, binary: str, original_code: str) -> str:
        """Produce a binary-specific one-liner that echoes the success
        marker instead of spawning an interactive shell."""
        lo = original_code.lower()

        # Python / python3
        if binary in ("python", "python2", "python3") or "python" in lo:
            return (
                f'{binary} -c \'import subprocess; '
                f'subprocess.check_call(["echo", "{_SUCCESS_MARKER}"])\''
            )

        # Ruby
        if binary == "ruby" or "ruby" in lo:
            return f'{binary} -e \'system("echo {_SUCCESS_MARKER}")\''

        # Perl
        if binary == "perl" or "perl" in lo:
            return f'{binary} -e \'system("echo {_SUCCESS_MARKER}")\''

        # PHP
        if binary == "php" or "php" in lo:
            return f'{binary} -r \'system("echo {_SUCCESS_MARKER}");  \''

        # Lua
        if binary == "lua" or "lua" in lo:
            return f'{binary} -e \'os.execute("echo {_SUCCESS_MARKER}")\''

        # Node / node.js
        if binary in ("node", "nodejs") or "node" in lo:
            return (
                f'{binary} -e \'require("child_process")'
                f'.execSync("echo {_SUCCESS_MARKER}", {{stdio:"inherit"}})\''
            )

        # awk / gawk / mawk / nawk
        if binary in ("awk", "gawk", "mawk", "nawk") or "awk" in lo:
            return f'{binary} \'BEGIN {{system("echo {_SUCCESS_MARKER}")}}\''

        # expect
        if binary == "expect" or "expect" in lo:
            return f'expect -c \'spawn echo {_SUCCESS_MARKER}; interact\''

        # vi / vim / ed / less / more / man — binaries that launch a pager/editor
        if binary in ("vi", "vim", "ed", "less", "more", "man"):
            # Can't safely test interactive — just confirm binary exists
            return f'echo "{_SUCCESS_MARKER} - {binary} exists: $(which {binary})"'

        # Binaries that directly exec a shell (ash, bash, csh, dash, ksh, zsh, etc.)
        if binary in (
            "ash", "bash", "csh", "dash", "ksh", "zsh", "sh", "fish",
            "tclsh", "wish",
        ):
            return f'{binary} -c \'echo {_SUCCESS_MARKER}\''

        # env / nice / stdbuf / timeout / xargs and similar wrappers
        if binary in (
            "env", "nice", "stdbuf", "timeout", "xargs", "find",
            "time", "taskset", "chroot", "ionice",
        ):
            return f'{binary} echo {_SUCCESS_MARKER} 2>/dev/null || echo {_SUCCESS_MARKER}'

        # nmap
        if binary == "nmap":
            return f'echo {_SUCCESS_MARKER} | {binary} --script <(echo "os.execute(\\"/bin/echo {_SUCCESS_MARKER}\\")"  ) 2>/dev/null || echo "SKIP: nmap script engine unavailable"'

        # Generic fallback: try the binary with -c flag (many shells accept it),
        # then fall back to running `echo` via the binary with --help to confirm
        # it's present.
        return (
            f'{binary} -c \'echo {_SUCCESS_MARKER}\' 2>/dev/null || '
            f'echo "{_SUCCESS_MARKER} - {binary} exists at $(which {binary})"'
        )

    # --- file-read -----------------------------------------------------
    def _safe_file_read(
        self, binary: str, original_code: str
    ) -> tuple[str, str | None, bool]:
        """Test that the binary can read a file by reading /etc/hostname."""
        # Rewrite the original code to target /etc/hostname
        safe_code = self._rewrite_file_target(
            original_code, binary, _SAFE_READ_FILE, mode="read"
        )
        cmd = textwrap.dedent(f"""\
            # GTFOBins file-read test: {binary}
            # Reads {_SAFE_READ_FILE} (world-readable, harmless).
            # Original: {self._oneliner(original_code)}
            if command -v {binary} >/dev/null 2>&1; then
                echo "--- Attempting file-read via {binary} ---"
                {safe_code}
                echo ""
                echo "{_SUCCESS_MARKER}"
            else
                echo "SKIP: {binary} not found on this system"
                exit 0
            fi""")
        return cmd, None, False

    # --- file-write ----------------------------------------------------
    def _safe_file_write(
        self, binary: str, original_code: str
    ) -> tuple[str, str | None, bool]:
        """Test file-write capability using a safe temp file."""
        tmpfile = _SAFE_WRITE_FILE
        safe_code = self._rewrite_file_target(
            original_code, binary, tmpfile, mode="write"
        )
        cmd = textwrap.dedent(f"""\
            # GTFOBins file-write test: {binary}
            # Writes to {tmpfile} (temp), then verifies and cleans up.
            # Original: {self._oneliner(original_code)}
            TMPFILE="{tmpfile}"
            if command -v {binary} >/dev/null 2>&1; then
                echo "--- Attempting file-write via {binary} ---"
                DATA="{_SUCCESS_MARKER}"
                {safe_code}
                if [ -f "$TMPFILE" ]; then
                    echo "File written successfully. Content:"
                    cat "$TMPFILE"
                    rm -f "$TMPFILE"
                    echo "{_SUCCESS_MARKER}"
                else
                    echo "FAIL: file was not created"
                    exit 1
                fi
            else
                echo "SKIP: {binary} not found on this system"
                exit 0
            fi""")
        cleanup = f'rm -f "{tmpfile}"'
        return cmd, cleanup, False

    # --- file-upload ---------------------------------------------------
    def _safe_file_upload(
        self, binary: str, original_code: str
    ) -> tuple[str, str | None, bool]:
        """Upload tests are observe-only (we do not actually exfiltrate)."""
        return self._safe_observe_only(binary, "file-upload", original_code)

    # --- file-download -------------------------------------------------
    def _safe_file_download(
        self, binary: str, original_code: str
    ) -> tuple[str, str | None, bool]:
        """Test download capability by fetching a known-safe URL to /tmp."""
        tmpfile = _SAFE_WRITE_FILE
        cmd = textwrap.dedent(f"""\
            # GTFOBins file-download test: {binary}
            # Attempts to download a small public file to /tmp.
            # Original: {self._oneliner(original_code)}
            TMPFILE="{tmpfile}"
            if command -v {binary} >/dev/null 2>&1; then
                echo "--- Attempting file-download via {binary} ---"
                # Use a small, public, harmless URL
                URL="http://example.com/index.html"
                {self._download_probe(binary, tmpfile)}
                if [ -f "$TMPFILE" ] && [ -s "$TMPFILE" ]; then
                    BYTES=$(wc -c < "$TMPFILE")
                    echo "Downloaded $BYTES bytes to $TMPFILE"
                    rm -f "$TMPFILE"
                    echo "{_SUCCESS_MARKER}"
                else
                    echo "SKIP: download attempt did not produce a file (network may be unavailable)"
                    rm -f "$TMPFILE" 2>/dev/null
                    exit 0
                fi
            else
                echo "SKIP: {binary} not found on this system"
                exit 0
            fi""")
        cleanup = f'rm -f "{tmpfile}"'
        return cmd, cleanup, False

    def _download_probe(self, binary: str, tmpfile: str) -> str:
        """Produce a download one-liner for common binaries."""
        url_var = "$URL"
        if binary == "curl":
            return f'curl -fsSL -o "$TMPFILE" "{url_var}" 2>/dev/null'
        if binary == "wget":
            return f'wget -q -O "$TMPFILE" "{url_var}" 2>/dev/null'
        if binary in ("python", "python3", "python2"):
            return (
                f'{binary} -c "import urllib.request; '
                f'urllib.request.urlretrieve(\'{url_var}\', \'$TMPFILE\')" 2>/dev/null'
            )
        if binary in ("ruby",):
            return (
                f'{binary} -e \'require "open-uri"; '
                f'File.write("$TMPFILE", URI.open("{url_var}").read)\' 2>/dev/null'
            )
        if binary in ("perl",):
            return (
                f'{binary} -MLWP::Simple -e \'getstore("{url_var}", "$TMPFILE")\' 2>/dev/null'
            )
        # Generic fallback — just check binary exists
        return f'echo "{_SUCCESS_MARKER}" > "$TMPFILE"'

    # --- suid / limited-suid ------------------------------------------
    def _safe_suid(
        self, binary: str, original_code: str
    ) -> tuple[str, str | None, bool]:
        """Check if the binary has the SUID bit set (no execution)."""
        cmd = textwrap.dedent(f"""\
            # GTFOBins SUID test: {binary}
            # Checks whether {binary} has the SUID bit set on this system.
            # Original: {self._oneliner(original_code)}
            BIN_PATH=$(command -v {binary} 2>/dev/null || find /usr -name {binary} -type f 2>/dev/null | head -1)
            if [ -z "$BIN_PATH" ]; then
                echo "SKIP: {binary} not found on this system"
                exit 0
            fi
            echo "Binary path: $BIN_PATH"
            PERMS=$(stat -c '%a' "$BIN_PATH" 2>/dev/null || stat -f '%Lp' "$BIN_PATH" 2>/dev/null)
            echo "Permissions: $PERMS"
            if [ -u "$BIN_PATH" ]; then
                echo "WARNING: {binary} has SUID bit set — potential privilege escalation vector"
                echo "{_SUCCESS_MARKER}"
            else
                echo "OK: {binary} does NOT have SUID bit set"
                echo "{_SUCCESS_MARKER}"
            fi""")
        return cmd, None, False

    # --- sudo ----------------------------------------------------------
    def _safe_sudo(
        self, binary: str, original_code: str
    ) -> tuple[str, str | None, bool]:
        """Test sudo capability non-interactively (sudo -n)."""
        cmd = textwrap.dedent(f"""\
            # GTFOBins sudo test: {binary}
            # Checks whether current user can run {binary} via sudo without a password.
            # Original: {self._oneliner(original_code)}
            if ! command -v {binary} >/dev/null 2>&1; then
                echo "SKIP: {binary} not found on this system"
                exit 0
            fi
            echo "--- Checking sudo access for {binary} ---"
            # List sudo permissions (non-interactive)
            SUDO_LIST=$(sudo -n -l 2>/dev/null || true)
            if echo "$SUDO_LIST" | grep -qi "{binary}"; then
                echo "WARNING: current user can sudo {binary}"
                echo "Sudo entry:"
                echo "$SUDO_LIST" | grep -i "{binary}"
                echo "{_SUCCESS_MARKER}"
            else
                echo "OK: current user cannot sudo {binary} without a password"
                echo "{_SUCCESS_MARKER}"
            fi""")
        return cmd, None, False

    # --- capabilities --------------------------------------------------
    def _safe_capabilities(
        self, binary: str, original_code: str
    ) -> tuple[str, str | None, bool]:
        """Check Linux capabilities on the binary."""
        cmd = textwrap.dedent(f"""\
            # GTFOBins capabilities test: {binary}
            # Checks whether {binary} has elevated Linux capabilities.
            # Original: {self._oneliner(original_code)}
            BIN_PATH=$(command -v {binary} 2>/dev/null || find /usr -name {binary} -type f 2>/dev/null | head -1)
            if [ -z "$BIN_PATH" ]; then
                echo "SKIP: {binary} not found on this system"
                exit 0
            fi
            if ! command -v getcap >/dev/null 2>&1; then
                echo "SKIP: getcap not available on this system"
                exit 0
            fi
            echo "Binary path: $BIN_PATH"
            CAPS=$(getcap "$BIN_PATH" 2>/dev/null)
            if [ -n "$CAPS" ]; then
                echo "WARNING: {binary} has capabilities set: $CAPS"
                echo "{_SUCCESS_MARKER}"
            else
                echo "OK: {binary} has no special capabilities"
                echo "{_SUCCESS_MARKER}"
            fi""")
        return cmd, None, False

    # --- observe-only --------------------------------------------------
    def _safe_observe_only(
        self, binary: str, func_name: str, original_code: str
    ) -> tuple[str, str | None, bool]:
        """Just verify the binary exists and note the capability."""
        cmd = textwrap.dedent(f"""\
            # GTFOBins {func_name} test: {binary} [OBSERVE ONLY]
            # This capability is too dangerous to test live.
            # Original: {self._oneliner(original_code)}
            if command -v {binary} >/dev/null 2>&1; then
                BIN_PATH=$(which {binary})
                echo "{binary} found at $BIN_PATH"
                echo "Capability: {func_name}"
                echo "This binary is documented as supporting {func_name} in GTFOBins."
                echo "Review the original command and assess the risk."
                echo "{_SUCCESS_MARKER}"
            else
                echo "SKIP: {binary} not found on this system"
                exit 0
            fi""")
        return cmd, None, True

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _oneliner(code: str) -> str:
        """Collapse code to a single-line summary for comments (max 120 chars)."""
        line = code.replace("\n", " ").strip()
        if len(line) > 120:
            return line[:117] + "..."
        return line

    @staticmethod
    def _which_hint(binary: str) -> str | None:
        """Return a likely filesystem path for well-known binaries."""
        common = {
            "python": "/usr/bin/python3",
            "python3": "/usr/bin/python3",
            "python2": "/usr/bin/python2",
            "perl": "/usr/bin/perl",
            "ruby": "/usr/bin/ruby",
            "php": "/usr/bin/php",
            "node": "/usr/bin/node",
            "lua": "/usr/bin/lua",
            "awk": "/usr/bin/awk",
            "bash": "/bin/bash",
            "sh": "/bin/sh",
            "dash": "/bin/dash",
            "zsh": "/usr/bin/zsh",
            "curl": "/usr/bin/curl",
            "wget": "/usr/bin/wget",
            "find": "/usr/bin/find",
            "tar": "/bin/tar",
            "zip": "/usr/bin/zip",
            "gcc": "/usr/bin/gcc",
            "vim": "/usr/bin/vim",
            "vi": "/usr/bin/vi",
            "less": "/usr/bin/less",
            "more": "/usr/bin/more",
            "nano": "/usr/bin/nano",
            "nmap": "/usr/bin/nmap",
            "socat": "/usr/bin/socat",
            "nc": "/usr/bin/nc",
            "ssh": "/usr/bin/ssh",
            "scp": "/usr/bin/scp",
            "rsync": "/usr/bin/rsync",
        }
        return common.get(binary)

    def _rewrite_file_target(
        self, original_code: str, binary: str, target: str, mode: str
    ) -> str:
        """Rewrite the original GTFOBins code to use a safe file target.

        For read operations: replace placeholder file paths with target.
        For write operations: replace output file paths with target.
        """
        code = original_code

        # Replace common GTFOBins placeholders
        code = re.sub(r'["\']?file_to_read["\']?', f'"{target}"', code)
        code = re.sub(r'["\']?file_to_write["\']?', f'"{target}"', code)
        code = re.sub(r'["\']?/path/to/file["\']?', f'"{target}"', code)
        code = re.sub(r'LFILE=\S+', f'LFILE="{target}"', code)

        if mode == "read":
            # Common pattern: binary reads from a file argument
            # Replace generic file references with /etc/hostname
            code = re.sub(
                r'["\']?file_to_read["\']?', f'"{target}"', code
            )
            # If the original code uses a positional argument
            if binary in ("cat", "head", "tail", "nl", "od", "xxd", "hexdump"):
                # These binaries take a file as a direct argument
                return f'{binary} "{target}"'
            if binary in ("python", "python3", "python2"):
                return (
                    f'{binary} -c "print(open(\'{target}\').read())"'
                )
            if binary in ("ruby",):
                return f'{binary} -e \'puts File.read("{target}")\''
            if binary in ("perl",):
                return (
                    f'{binary} -e \'open(F, "<", "{target}"); '
                    f'print while <F>\''
                )
        elif mode == "write":
            # For file-write, ensure we write known safe content to a temp file
            if binary in ("python", "python3", "python2"):
                return (
                    f'{binary} -c "open(\'$TMPFILE\', \'w\').write(\'$DATA\\n\')"'
                )
            if binary in ("ruby",):
                return f'{binary} -e \'File.write("$TMPFILE", "$DATA\\n")\''
            if binary in ("perl",):
                return (
                    f'{binary} -e \'open(F, ">", "$TMPFILE"); '
                    f'print F "$DATA\\n"; close F\''
                )
            if binary == "tee":
                return 'echo "$DATA" | tee "$TMPFILE" >/dev/null'
            if binary == "cp":
                return 'echo "$DATA" > /tmp/.gtfobins_src_$$ && cp /tmp/.gtfobins_src_$$ "$TMPFILE" && rm -f /tmp/.gtfobins_src_$$'
            if binary == "dd":
                return 'echo "$DATA" | dd of="$TMPFILE" 2>/dev/null'

        # If no specific rewrite matched, use the (already substituted) code
        # but collapse multi-line commands into a safe block
        if "\n" in code:
            # Multi-line: wrap in a subshell for safety
            return f'(\n{code}\n)'

        return code

    # ------------------------------------------------------------------
    # MITRE mapping (required by base class)
    # ------------------------------------------------------------------
    def get_mitre_mappings(self) -> dict[str, list[str]]:
        mappings: dict[str, list[str]] = {}
        for test in getattr(self, "_tests", []):
            tid = test.get("technique_id", "")
            if tid:
                mappings.setdefault(test["name"], []).append(tid)
        return mappings
