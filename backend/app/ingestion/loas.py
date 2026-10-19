"""LOAS ingestor — Living Off Apple Systems (Living Off the Orchard: AppleScript).

Fetches macOS offensive technique data from https://github.com/cyberbuff/loas,
parses each YAML technique file into prevention tests, and generates executable
test commands in multiple execution modes:

  1. osascript CLI — Runs AppleScript/JXA directly via `osascript`
  2. Swift compiled — Compiles a Swift wrapper that embeds the AppleScript via
     NSAppleScript, then executes the binary (tests Gatekeeper/code-signing)
  3. Applet mode — Compiles an .app bundle via `osacompile` (tests Gatekeeper
     quarantine, notarization checks)

Each LOAS technique maps to a MITRE ATT&CK technique ID (derived from the YAML
directory structure, e.g. yaml/T1082/ -> T1082). Tests validate whether macOS
security controls (TCC, Gatekeeper, XProtect, Endpoint Security, SIP) prevent
or allow the technique.

This ingestor produces real, executable, self-contained bash commands that the
Atomic Prevention agent can run on macOS to validate prevention posture.
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
# MITRE ATT&CK technique metadata — enriched descriptions and risk levels
# derived from the technique IDs that LOAS covers.
# ---------------------------------------------------------------------------
_TECHNIQUE_META: dict[str, dict] = {
    "T1005": {"tactic": "Collection", "risk": "high",
              "name": "Data from Local System"},
    "T1010": {"tactic": "Discovery", "risk": "low",
              "name": "Application Window Discovery"},
    "T1016.001": {"tactic": "Discovery", "risk": "low",
                  "name": "Internet Connection Discovery"},
    "T1018": {"tactic": "Discovery", "risk": "low",
              "name": "Remote System Discovery"},
    "T1033": {"tactic": "Discovery", "risk": "low",
              "name": "System Owner/User Discovery"},
    "T1056.002": {"tactic": "Credential Access", "risk": "high",
                  "name": "GUI Input Capture"},
    "T1057": {"tactic": "Discovery", "risk": "medium",
              "name": "Process Discovery"},
    "T1059.002": {"tactic": "Execution", "risk": "high",
                  "name": "AppleScript"},
    "T1059.004": {"tactic": "Execution", "risk": "high",
                  "name": "Unix Shell"},
    "T1070.002": {"tactic": "Defense Evasion", "risk": "high",
                  "name": "Clear Linux or Mac System Logs"},
    "T1070.009": {"tactic": "Defense Evasion", "risk": "medium",
                  "name": "Clear Persistence"},
    "T1082": {"tactic": "Discovery", "risk": "low",
              "name": "System Information Discovery"},
    "T1083": {"tactic": "Discovery", "risk": "medium",
              "name": "File and Directory Discovery"},
    "T1087.001": {"tactic": "Discovery", "risk": "medium",
                  "name": "Local Account Discovery"},
    "T1113": {"tactic": "Collection", "risk": "high",
              "name": "Screen Capture"},
    "T1115": {"tactic": "Collection", "risk": "medium",
              "name": "Clipboard Data"},
    "T1120": {"tactic": "Discovery", "risk": "low",
              "name": "Peripheral Device Discovery"},
    "T1123": {"tactic": "Collection", "risk": "high",
              "name": "Audio Capture"},
    "T1124": {"tactic": "Discovery", "risk": "low",
              "name": "System Time Discovery"},
    "T1217": {"tactic": "Discovery", "risk": "medium",
              "name": "Browser Information Discovery"},
    "T1489": {"tactic": "Impact", "risk": "high",
              "name": "Service Stop"},
    "T1491.001": {"tactic": "Impact", "risk": "medium",
                  "name": "Internal Defacement"},
    "T1518.001": {"tactic": "Discovery", "risk": "low",
                  "name": "Security Software Discovery"},
    "T1529": {"tactic": "Impact", "risk": "high",
              "name": "System Shutdown/Reboot"},
    "T1539": {"tactic": "Credential Access", "risk": "high",
              "name": "Steal Web Session Cookie"},
    "T1547.015": {"tactic": "Persistence", "risk": "high",
                  "name": "Login Items"},
    "T1552.003": {"tactic": "Credential Access", "risk": "high",
                  "name": "Bash History"},
    "T1564.003": {"tactic": "Defense Evasion", "risk": "medium",
                  "name": "Hidden Window"},
    "T1614.001": {"tactic": "Discovery", "risk": "low",
                  "name": "System Language Discovery"},
}

# Tactics that represent high-risk activity on macOS
_HIGH_RISK_TACTICS = {
    "Execution", "Credential Access", "Persistence", "Impact",
    "Collection",
}

# macOS security controls that each tactic category tests
_SECURITY_CONTROL_MAP: dict[str, str] = {
    "Execution": "TCC (Transparency Consent & Control), Gatekeeper, XProtect",
    "Credential Access": "TCC, Keychain Access controls, Password AutoFill protections",
    "Collection": "TCC (Screen Recording, Microphone, Accessibility), Privacy preferences",
    "Persistence": "TCC (Login Items), SIP (System Integrity Protection)",
    "Impact": "TCC (System Events), SIP, Endpoint Security framework",
    "Defense Evasion": "SIP, Endpoint Security framework, TCC",
    "Discovery": "TCC (Automation), Endpoint Security telemetry",
}


class LOASIngestor(BaseIngestor):
    """Ingestor for LOAS (Living Off Apple Systems).

    Clones the LOAS repository, parses YAML technique definitions, and
    generates executable macOS prevention tests in three execution modes:
    osascript direct, Swift-compiled binary, and osacompile applet.
    """

    @property
    def source_id(self) -> str:
        return "loas"

    @property
    def display_name(self) -> str:
        return "LOAS"

    @property
    def description(self) -> str:
        return (
            "Living Off Apple Systems: macOS offensive techniques using "
            "AppleScript/JXA with multiple execution methods (osascript, "
            "Swift-compiled, applets) mapped to MITRE ATT&CK"
        )

    @property
    def repo_url(self) -> str:
        return "https://github.com/cyberbuff/loas"

    @property
    def platform(self) -> str:
        return "macos"

    # ------------------------------------------------------------------
    # Fetch: clone or update the LOAS repository
    # ------------------------------------------------------------------
    async def fetch(self) -> None:
        """Clone or update the LOAS repository."""
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
    # Parse: walk yaml/ directories, produce prevention tests
    # ------------------------------------------------------------------
    async def parse(self) -> list[dict]:
        """Parse LOAS YAML files into prevention test dicts.

        For each LOAS technique test, we generate up to three execution
        variants so playbooks can test different macOS security surfaces:

        1. osascript CLI — tests TCC and Automation privacy controls
        2. Swift compiled binary — tests Gatekeeper, code-signing enforcement
        3. osacompile applet (.app) — tests Gatekeeper quarantine/notarization

        The agent picks the appropriate variant (or runs all three) depending
        on the playbook configuration.
        """
        tests: list[dict] = []
        yaml_dir = self.data_dir / "yaml"

        if not yaml_dir.exists():
            logger.warning("LOAS yaml directory not found: %s", yaml_dir)
            return tests

        # Walk technique directories (T1082, T1059.002, etc.)
        for technique_dir in sorted(yaml_dir.iterdir()):
            if not technique_dir.is_dir():
                continue
            technique_id = technique_dir.name
            if not technique_id.startswith("T"):
                continue

            # Each technique directory contains one YAML file
            for yml_file in sorted(technique_dir.glob("*.yaml")):
                try:
                    raw = yml_file.read_text(encoding="utf-8")
                    data = yaml.safe_load(raw)
                    if not data:
                        continue
                    tests.extend(
                        self._parse_technique(data, technique_id)
                    )
                except Exception as exc:
                    logger.debug(
                        "LOAS: failed to parse %s: %s", yml_file.name, exc
                    )
                    continue

            # Also check for .yml extension
            for yml_file in sorted(technique_dir.glob("*.yml")):
                try:
                    raw = yml_file.read_text(encoding="utf-8")
                    data = yaml.safe_load(raw)
                    if not data:
                        continue
                    tests.extend(
                        self._parse_technique(data, technique_id)
                    )
                except Exception as exc:
                    logger.debug(
                        "LOAS: failed to parse %s: %s", yml_file.name, exc
                    )
                    continue

        self._tests = tests
        logger.info("LOAS: parsed %d tests from %s", len(tests), yaml_dir)
        return tests

    # ------------------------------------------------------------------
    # Internal: parse a single YAML technique file
    # ------------------------------------------------------------------
    def _parse_technique(
        self, data: dict, technique_id: str
    ) -> list[dict]:
        """Parse a single LOAS YAML technique file into prevention tests.

        Generates multiple execution variants for each test entry.
        """
        tests: list[dict] = []
        technique_name = data.get("name", technique_id)
        test_entries = data.get("tests", [])

        if not test_entries:
            return tests

        meta = _TECHNIQUE_META.get(technique_id, {})
        tactic = meta.get("tactic", "Execution")
        base_risk = meta.get("risk", "medium")

        for entry in test_entries:
            test_name = entry.get("name", "")
            guid = entry.get("guid", "")
            language = entry.get("language", "AppleScript")
            description = entry.get("description", "")
            command = entry.get("command", "")
            tcc_required = entry.get("tcc_required", False)
            elevation_required = entry.get("elevation_required", False)
            args = entry.get("args", {}) or {}
            references = entry.get("references", []) or []

            if not command or not command.strip():
                continue

            # Substitute argument placeholders with defaults
            resolved_command = self._resolve_args(command, args)

            # Determine risk level — elevation or TCC-sensitive tests are
            # higher risk because they exercise deeper OS security controls
            risk_level = base_risk
            if elevation_required:
                risk_level = "high"
            elif tcc_required and risk_level == "low":
                risk_level = "medium"

            # Determine which macOS security controls this test exercises
            security_controls = _SECURITY_CONTROL_MAP.get(
                tactic, "macOS Endpoint Security"
            )

            # Build metadata common to all variants
            common_meta = {
                "source": "loas",
                "guid": guid,
                "language": language,
                "technique_name": technique_name,
                "tactic": tactic,
                "tcc_required": tcc_required,
                "references": references,
                "original_args": args,
                "security_controls_tested": security_controls,
            }

            # ----- Variant 1: osascript CLI execution -----
            # This is the primary execution method — runs the AppleScript/JXA
            # directly via osascript. Tests TCC, Automation privacy, and basic
            # Endpoint Security detection.
            osascript_cmd = self._build_osascript_command(
                resolved_command, language, test_name, technique_id,
                tcc_required, elevation_required, args,
            )
            osascript_cleanup = self._build_cleanup_command(
                technique_id, test_name, "osascript",
            )
            tests.append({
                "name": f"LOAS: {test_name} [osascript]",
                "description": (
                    f"[{technique_name}] {description} "
                    f"| Execution: osascript CLI | "
                    f"Security controls tested: {security_controls}"
                ),
                "command": osascript_cmd,
                "executor": "bash",
                "technique_id": technique_id,
                "binary_path": "/usr/bin/osascript",
                "elevation_required": elevation_required,
                "risk_level": risk_level,
                "platforms": ["macos"],
                "cleanup_command": osascript_cleanup,
                "metadata": {
                    **common_meta,
                    "execution_mode": "osascript",
                },
            })

            # ----- Variant 2: Swift-compiled binary -----
            # Compiles a Swift program that embeds the AppleScript via
            # NSAppleScript and runs it as a native binary. This tests
            # Gatekeeper code-signing enforcement and ad-hoc signature
            # detection. The binary is unsigned (ad-hoc) which should
            # trigger Gatekeeper on a properly configured system.
            swift_cmd = self._build_swift_command(
                resolved_command, language, test_name, technique_id,
                tcc_required, elevation_required,
            )
            swift_cleanup = self._build_cleanup_command(
                technique_id, test_name, "swift",
            )
            tests.append({
                "name": f"LOAS: {test_name} [swift-binary]",
                "description": (
                    f"[{technique_name}] {description} "
                    f"| Execution: Swift-compiled binary (tests Gatekeeper "
                    f"code-signing enforcement) | "
                    f"Security controls tested: Gatekeeper, {security_controls}"
                ),
                "command": swift_cmd,
                "executor": "bash",
                "technique_id": technique_id,
                "binary_path": None,
                "elevation_required": elevation_required,
                "risk_level": "high",  # compiled binary always high risk
                "platforms": ["macos"],
                "cleanup_command": swift_cleanup,
                "metadata": {
                    **common_meta,
                    "execution_mode": "swift_binary",
                },
            })

            # ----- Variant 3: osacompile applet (.app bundle) -----
            # Compiles the script into a macOS .app bundle using osacompile.
            # This tests Gatekeeper quarantine attribute enforcement and
            # notarization checks. The applet will have a quarantine flag
            # set which should trigger Gatekeeper on first launch.
            # Only generate for AppleScript (osacompile does not support
            # raw JXA in -l JavaScript mode for applets reliably).
            if language.lower() in ("applescript", ""):
                applet_cmd = self._build_applet_command(
                    resolved_command, test_name, technique_id,
                    tcc_required,
                )
                applet_cleanup = self._build_cleanup_command(
                    technique_id, test_name, "applet",
                )
                tests.append({
                    "name": f"LOAS: {test_name} [applet]",
                    "description": (
                        f"[{technique_name}] {description} "
                        f"| Execution: osacompile .app bundle (tests "
                        f"Gatekeeper quarantine & notarization) | "
                        f"Security controls tested: Gatekeeper, XProtect, "
                        f"{security_controls}"
                    ),
                    "command": applet_cmd,
                    "executor": "bash",
                    "technique_id": technique_id,
                    "binary_path": None,
                    "elevation_required": elevation_required,
                    "risk_level": "high",
                    "platforms": ["macos"],
                    "cleanup_command": applet_cleanup,
                    "metadata": {
                        **common_meta,
                        "execution_mode": "applet",
                    },
                })

        return tests

    # ------------------------------------------------------------------
    # Command builders
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_args(command: str, args: dict) -> str:
        """Substitute #{argName} placeholders with default argument values."""
        result = command
        for arg_name, default_value in args.items():
            placeholder = f"#{{{arg_name}}}"
            result = result.replace(placeholder, str(default_value))
        return result

    @staticmethod
    def _escape_for_shell(text: str) -> str:
        """Escape a string for safe embedding in a single-quoted shell string.

        Single quotes within the text are replaced with the sequence '\\''
        which ends the single quote, inserts an escaped single quote, and
        reopens the single quote.
        """
        return text.replace("'", "'\\''")

    def _build_osascript_command(
        self,
        script: str,
        language: str,
        test_name: str,
        technique_id: str,
        tcc_required: bool,
        elevation_required: bool,
        args: dict,
    ) -> str:
        """Build a bash command that runs the script via osascript.

        The command is self-contained and includes:
        - A banner explaining what the test does
        - The osascript invocation with proper language flag
        - Exit code checking to determine BLOCKED vs ALLOWED
        - TCC / permission error detection
        """
        lang_flag = "JavaScript" if language.lower() == "javascript" else "AppleScript"

        # For multi-line scripts, write to a temp file and execute
        # This is more reliable than chaining -e flags for complex scripts
        escaped_script = self._escape_for_shell(script)

        # Build the full test command
        cmd = textwrap.dedent(f"""\
            #!/bin/bash
            # === Atomic Prevention LOAS Prevention Test ===
            # Test: {test_name}
            # Technique: {technique_id}
            # Language: {lang_flag}
            # TCC Required: {tcc_required}
            # Elevation Required: {elevation_required}
            # Security Surface: osascript CLI execution
            # ==========================================

            WORK_DIR="${{TMPDIR:-/tmp}}/atomic-prevention-loas/{technique_id}"
            mkdir -p "$WORK_DIR"

            SCRIPT_FILE="$WORK_DIR/{self._safe_filename(test_name)}.{self._script_ext(lang_flag)}"

            cat > "$SCRIPT_FILE" << 'LOAS_SCRIPT_EOF'
            {script}
            LOAS_SCRIPT_EOF

            echo "[*] LOAS Test: {test_name}"
            echo "[*] Technique: {technique_id} ({lang_flag})"
            echo "[*] Executing via osascript..."
            echo ""

            # Execute the script via osascript
            OUTPUT=$(osascript -l {lang_flag} "$SCRIPT_FILE" 2>&1)
            EXIT_CODE=$?

            echo "[*] osascript exit code: $EXIT_CODE"
            echo "[*] Output: $OUTPUT"
            echo ""

            # Analyze the result to determine if security controls intervened
            if [ $EXIT_CODE -ne 0 ]; then
                # Check for TCC denial patterns
                if echo "$OUTPUT" | grep -qi -e "not allowed" -e "not permitted" \\
                    -e "access denied" -e "assistive access" \\
                    -e "System Events got an error" -e "Application isn't running" \\
                    -e "execution error" -e "not allowed assistive" \\
                    -e "osascript is not allowed" -e "not authorized" \\
                    -e "requires user consent" -e "tccutil" \\
                    -e "operation not permitted" -e "sandbox" \\
                    -e "deny mach-lookup"; then
                    echo "[RESULT] BLOCKED - macOS security controls prevented this technique"
                    echo "[DETAIL] TCC/Privacy controls denied access"
                    exit 0
                fi
                # Check for Endpoint Security / policy blocks
                if echo "$OUTPUT" | grep -qi -e "blocked" -e "quarantine" \\
                    -e "malware" -e "XProtect" -e "Gatekeeper" \\
                    -e "not trusted" -e "security policy"; then
                    echo "[RESULT] BLOCKED - Endpoint security prevented execution"
                    exit 0
                fi
                echo "[RESULT] ERROR - Script failed but not due to security controls"
                echo "[DETAIL] Exit code: $EXIT_CODE"
                exit 1
            else
                echo "[RESULT] ALLOWED - Technique executed successfully"
                echo "[DETAIL] macOS security controls did NOT prevent this technique"
                echo "[ACTION] Review TCC/Privacy settings and endpoint security policies"
                exit 0
            fi""")

        return cmd

    def _build_swift_command(
        self,
        script: str,
        language: str,
        test_name: str,
        technique_id: str,
        tcc_required: bool,
        elevation_required: bool,
    ) -> str:
        """Build a bash command that compiles a Swift wrapper and executes it.

        This variant tests whether Gatekeeper and code-signing enforcement
        prevent an unsigned/ad-hoc signed binary from executing AppleScript.
        The Swift binary uses NSAppleScript to run the embedded script.
        """
        # Escape the AppleScript for embedding in a Swift string literal
        swift_escaped_script = (
            script
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
        )

        safe_name = self._safe_filename(test_name)

        if language.lower() == "javascript":
            # For JXA, use OSAKit's OSALanguage to run JavaScript
            swift_source = textwrap.dedent(f'''\
                import Foundation
                import OSAKit

                let script = "{swift_escaped_script}"
                let lang = OSALanguage(forName: "JavaScript")
                let osa = OSAScript(source: script, language: lang!)
                var errorInfo: NSDictionary?
                let result = osa.executeAndReturnError(&errorInfo)
                if let error = errorInfo {{
                    fputs("Error: \\\\(error)\\n", stderr)
                    exit(1)
                }}
                if let val = result?.stringValue {{
                    print(val)
                }}''')
        else:
            # For AppleScript, use NSAppleScript
            swift_source = textwrap.dedent(f'''\
                import Foundation

                let script = "{swift_escaped_script}"
                let appleScript = NSAppleScript(source: script)
                var errorInfo: NSDictionary?
                let result = appleScript?.executeAndReturnError(&errorInfo)
                if let error = errorInfo {{
                    let errMsg = error[NSAppleScript.errorMessage] as? String ?? "Unknown error"
                    fputs("Error: \\\\(errMsg)\\n", stderr)
                    exit(1)
                }}
                if let val = result?.stringValue {{
                    print(val)
                }}''')

        escaped_swift = self._escape_for_shell(swift_source)

        cmd = textwrap.dedent(f"""\
            #!/bin/bash
            # === Atomic Prevention LOAS Prevention Test (Swift Binary) ===
            # Test: {test_name}
            # Technique: {technique_id}
            # Execution: Swift-compiled binary (unsigned/ad-hoc)
            # Security Surface: Gatekeeper, code-signing, Endpoint Security
            # ==========================================================

            WORK_DIR="${{TMPDIR:-/tmp}}/atomic-prevention-loas/{technique_id}"
            mkdir -p "$WORK_DIR"

            SWIFT_FILE="$WORK_DIR/{safe_name}_swift.swift"
            BINARY="$WORK_DIR/{safe_name}_swift_bin"

            echo "[*] LOAS Test: {test_name} [Swift Binary]"
            echo "[*] Technique: {technique_id}"
            echo "[*] Writing Swift source..."

            cat > "$SWIFT_FILE" << 'LOAS_SWIFT_EOF'
            {swift_source}
            LOAS_SWIFT_EOF

            # Compile the Swift wrapper
            echo "[*] Compiling Swift binary (ad-hoc signed)..."
            COMPILE_OUTPUT=$(swiftc -o "$BINARY" "$SWIFT_FILE" -framework Foundation 2>&1)
            COMPILE_EXIT=$?

            if [ $COMPILE_EXIT -ne 0 ]; then
                echo "[*] Swift compilation failed: $COMPILE_OUTPUT"
                # Check if swiftc is available
                if ! command -v swiftc &>/dev/null; then
                    echo "[RESULT] SKIPPED - Xcode Command Line Tools not installed (swiftc not found)"
                    echo "[ACTION] Install with: xcode-select --install"
                    exit 0
                fi
                echo "[RESULT] ERROR - Swift compilation failed"
                exit 1
            fi

            echo "[*] Binary compiled: $BINARY"
            echo "[*] Binary size: $(stat -f%z "$BINARY" 2>/dev/null || echo unknown) bytes"

            # Set the quarantine attribute to simulate a downloaded binary
            # This triggers Gatekeeper checks on execution
            xattr -w com.apple.quarantine "0083;$(printf '%08x' $(date +%s));Atomic Prevention;$(uuidgen)" "$BINARY" 2>/dev/null

            echo "[*] Quarantine attribute set (triggers Gatekeeper)"
            echo "[*] Executing compiled binary..."
            echo ""

            # Execute the compiled binary
            OUTPUT=$("$BINARY" 2>&1)
            EXIT_CODE=$?

            echo "[*] Binary exit code: $EXIT_CODE"
            echo "[*] Output: $OUTPUT"
            echo ""

            if [ $EXIT_CODE -ne 0 ]; then
                if echo "$OUTPUT" | grep -qi -e "not allowed" -e "not permitted" \\
                    -e "access denied" -e "execution error" \\
                    -e "not authorized" -e "sandbox" \\
                    -e "killed" -e "abort" -e "quarantine"; then
                    echo "[RESULT] BLOCKED - macOS security controls prevented the compiled binary"
                    echo "[DETAIL] Gatekeeper/code-signing/TCC enforcement active"
                    exit 0
                fi
                # Check if the process was killed by Endpoint Security
                if [ $EXIT_CODE -eq 137 ] || [ $EXIT_CODE -eq 126 ] || [ $EXIT_CODE -eq 9 ]; then
                    echo "[RESULT] BLOCKED - Process killed by Endpoint Security or Gatekeeper"
                    exit 0
                fi
                echo "[RESULT] ERROR - Binary execution failed (not a security block)"
                exit 1
            else
                echo "[RESULT] ALLOWED - Unsigned binary executed AppleScript successfully"
                echo "[DETAIL] Gatekeeper did NOT prevent unsigned binary execution"
                echo "[ACTION] Review Gatekeeper settings (spctl --status) and code-signing policies"
                exit 0
            fi""")

        return cmd

    def _build_applet_command(
        self,
        script: str,
        test_name: str,
        technique_id: str,
        tcc_required: bool,
    ) -> str:
        """Build a bash command that compiles an .app bundle via osacompile.

        This variant creates a standalone macOS application from the AppleScript
        and attempts to run it. It tests:
        - Gatekeeper quarantine attribute enforcement
        - Notarization requirements
        - XProtect scanning of .app bundles
        - TCC consent for the applet's bundle identifier
        """
        safe_name = self._safe_filename(test_name)

        cmd = textwrap.dedent(f"""\
            #!/bin/bash
            # === Atomic Prevention LOAS Prevention Test (Applet) ===
            # Test: {test_name}
            # Technique: {technique_id}
            # Execution: osacompile .app bundle
            # Security Surface: Gatekeeper quarantine, notarization, XProtect
            # =====================================================

            WORK_DIR="${{TMPDIR:-/tmp}}/atomic-prevention-loas/{technique_id}"
            mkdir -p "$WORK_DIR"

            SCRIPT_FILE="$WORK_DIR/{safe_name}_applet.applescript"
            APP_BUNDLE="$WORK_DIR/{safe_name}.app"

            echo "[*] LOAS Test: {test_name} [Applet]"
            echo "[*] Technique: {technique_id}"
            echo "[*] Writing AppleScript source..."

            cat > "$SCRIPT_FILE" << 'LOAS_APPLET_EOF'
            {script}
            LOAS_APPLET_EOF

            # Remove any prior build
            rm -rf "$APP_BUNDLE"

            # Compile into an .app bundle
            echo "[*] Compiling .app bundle via osacompile..."
            COMPILE_OUTPUT=$(osacompile -o "$APP_BUNDLE" "$SCRIPT_FILE" 2>&1)
            COMPILE_EXIT=$?

            if [ $COMPILE_EXIT -ne 0 ]; then
                echo "[*] osacompile failed: $COMPILE_OUTPUT"
                echo "[RESULT] ERROR - Failed to compile applet"
                exit 1
            fi

            echo "[*] App bundle created: $APP_BUNDLE"

            # Set quarantine attribute to simulate a downloaded .app
            xattr -w com.apple.quarantine "0083;$(printf '%08x' $(date +%s));Atomic Prevention;$(uuidgen)" "$APP_BUNDLE" 2>/dev/null

            # Also quarantine the inner binary
            INNER_BIN="$APP_BUNDLE/Contents/MacOS/applet"
            if [ -f "$INNER_BIN" ]; then
                xattr -w com.apple.quarantine "0083;$(printf '%08x' $(date +%s));Atomic Prevention;$(uuidgen)" "$INNER_BIN" 2>/dev/null
            fi

            echo "[*] Quarantine attribute set (triggers Gatekeeper)"
            echo "[*] Launching applet..."
            echo ""

            # Attempt to open the applet — this triggers Gatekeeper
            # Use 'open' command which goes through LaunchServices (real Gatekeeper path)
            OUTPUT=$(open -W -a "$APP_BUNDLE" 2>&1)
            EXIT_CODE=$?

            echo "[*] Applet exit code: $EXIT_CODE"
            echo "[*] Output: $OUTPUT"
            echo ""

            # Also check if Gatekeeper or spctl would block it
            echo "[*] Checking Gatekeeper assessment..."
            SPCTL_OUTPUT=$(spctl --assess --type execute "$APP_BUNDLE" 2>&1)
            SPCTL_EXIT=$?

            echo "[*] spctl result: $SPCTL_OUTPUT (exit: $SPCTL_EXIT)"

            if [ $SPCTL_EXIT -ne 0 ] || [ $EXIT_CODE -ne 0 ]; then
                if echo "$OUTPUT $SPCTL_OUTPUT" | grep -qi -e "not allowed" \\
                    -e "rejected" -e "quarantine" -e "Gatekeeper" \\
                    -e "unidentified developer" -e "damaged" \\
                    -e "not opened" -e "can't be opened" \\
                    -e "cannot be opened" -e "malicious software" \\
                    -e "not from an identified" -e "security policy" \\
                    -e "from an unidentified developer" \\
                    -e "Apple cannot check it"; then
                    echo "[RESULT] BLOCKED - Gatekeeper prevented the unsigned applet"
                    echo "[DETAIL] Quarantine enforcement and/or notarization check active"
                    exit 0
                fi
                if echo "$SPCTL_OUTPUT" | grep -qi "rejected"; then
                    echo "[RESULT] BLOCKED - spctl rejected the applet"
                    exit 0
                fi
                echo "[RESULT] ERROR - Applet failed but not clearly a security block"
                exit 1
            else
                echo "[RESULT] ALLOWED - Unsigned .app bundle executed successfully"
                echo "[DETAIL] Gatekeeper did NOT block the quarantined applet"
                echo "[ACTION] Check Gatekeeper status: spctl --status"
                echo "[ACTION] Verify quarantine enforcement: defaults read com.apple.LaunchServices LSQuarantine"
                exit 0
            fi""")

        return cmd

    def _build_cleanup_command(
        self,
        technique_id: str,
        test_name: str,
        mode: str,
    ) -> str:
        """Build a cleanup command that removes all test artifacts."""
        safe_name = self._safe_filename(test_name)
        work_dir = f"${{TMPDIR:-/tmp}}/atomic-prevention-loas/{technique_id}"

        if mode == "osascript":
            return (
                f'rm -f "{work_dir}/{safe_name}.scpt" '
                f'"{work_dir}/{safe_name}.js" 2>/dev/null; '
                f'echo "[*] Cleaned up osascript artifacts"'
            )
        elif mode == "swift":
            return (
                f'rm -f "{work_dir}/{safe_name}_swift.swift" '
                f'"{work_dir}/{safe_name}_swift_bin" 2>/dev/null; '
                f'echo "[*] Cleaned up Swift binary artifacts"'
            )
        elif mode == "applet":
            return (
                f'rm -rf "{work_dir}/{safe_name}.app" '
                f'"{work_dir}/{safe_name}_applet.applescript" 2>/dev/null; '
                f'echo "[*] Cleaned up applet artifacts"'
            )
        else:
            return (
                f'rm -rf "{work_dir}" 2>/dev/null; '
                f'echo "[*] Cleaned up LOAS test artifacts"'
            )

    # ------------------------------------------------------------------
    # MITRE mapping
    # ------------------------------------------------------------------
    def get_mitre_mappings(self) -> dict[str, list[str]]:
        """Return mapping of test names to MITRE technique IDs."""
        mappings: dict[str, list[str]] = {}
        for test in getattr(self, "_tests", []):
            tid = test.get("technique_id", "")
            if tid:
                mappings.setdefault(test["name"], []).append(tid)
        return mappings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_filename(name: str) -> str:
        """Convert a test name into a safe filename component."""
        # Replace unsafe characters with underscores
        safe = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)
        # Collapse multiple underscores
        safe = re.sub(r"_+", "_", safe)
        # Trim to a reasonable length
        return safe[:80].strip("_").lower()

    @staticmethod
    def _script_ext(language: str) -> str:
        """Return the file extension for a script language."""
        if language.lower() == "javascript":
            return "js"
        return "scpt"
