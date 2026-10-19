"""LOLAPI ingestor — Living Off The Land API abuse catalog.

Fetches API-level abuse data from https://github.com/TheMagicClaw/LOLAPI,
which catalogs legitimate system APIs weaponized for attack across Windows,
cloud, and browser platforms.  Each YAML entry describes an API with one or
more abuse_scenarios containing code snippets and MITRE ATT&CK technique IDs.

Unlike LOLBAS (which tracks binaries), LOLAPI focuses on the API surface —
.NET methods, COM objects, native Win32 calls, cloud metadata endpoints,
browser extension APIs, and script engine interfaces — giving defenders
visibility into the *programmatic* LOL attack surface.
"""

import asyncio
import logging
from pathlib import Path

import yaml

from backend.app.ingestion.base import BaseIngestor

logger = logging.getLogger(__name__)

# Map LOLAPI categories to the platform(s) they affect.
_CATEGORY_PLATFORMS: dict[str, list[str]] = {
    "windows-dotnet-api": ["windows"],
    "windows-com-api": ["windows"],
    "windows-com": ["windows"],
    "windows-api": ["windows"],
    "windows-native-api": ["windows"],
    "script-engine": ["windows"],
    "script-engine-api": ["windows"],
    "cloud-metadata": ["linux", "windows"],  # Cloud VMs run both
    "browser-extension": ["windows", "linux", "macos"],  # Cross-platform
}

# Map LOLAPI subcategories to a MITRE technique fallback when the
# abuse_scenario itself does not carry a technique_id.
_SUBCATEGORY_TECHNIQUE_FALLBACK: dict[str, str] = {
    "process-execution": "T1106",       # Native API
    "process-injection": "T1055",       # Process Injection
    "code-execution": "T1059",          # Command and Scripting Interpreter
    "script-execution": "T1059",        # Command and Scripting Interpreter
    "shell-execution": "T1059",         # Command and Scripting Interpreter
    "module-loading": "T1129",          # Shared Modules
    "memory-access": "T1055.001",       # DLL Injection
    "network-communication": "T1071",   # Application Layer Protocol
    "network-interception": "T1557",    # Adversary-in-the-Middle
    "command-and-control": "T1071",     # Application Layer Protocol
    "lateral-movement": "T1021",        # Remote Services
    "persistence": "T1547",             # Boot or Logon Autostart Execution
    "evasion": "T1027",                 # Obfuscated Files or Information
    "data-exfiltration": "T1041",       # Exfiltration Over C2 Channel
    "token-theft": "T1528",             # Steal Application Access Token
    "authentication": "T1078",          # Valid Accounts
    "registry-manipulation": "T1112",   # Modify Registry
    "registry-access": "T1012",         # Query Registry
    "log-manipulation": "T1070",        # Indicator Removal
    "file-operations": "T1005",         # Data from Local System
    "hooking": "T1056",                 # Input Capture
    "api-resolution": "T1106",          # Native API
    "inter-process-communication": "T1559",  # Inter-Process Communication
    "resource-retrieval": "T1105",      # Ingress Tool Transfer
}

# Severity string -> risk_level mapping for prevention tests.
_SEVERITY_TO_RISK: dict[str, str] = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


class LOLAPIIngestor(BaseIngestor):
    """Ingestor for LOLAPI (Living Off The Land API abuse catalog)."""

    @property
    def source_id(self) -> str:
        return "lolapi"

    @property
    def display_name(self) -> str:
        return "LOLAPI"

    @property
    def description(self) -> str:
        return (
            "Living Off The Land APIs — catalog of legitimate system APIs "
            "weaponized for attack across Windows, cloud, and browser platforms"
        )

    @property
    def repo_url(self) -> str:
        return "https://github.com/TheMagicClaw/LOLAPI"

    @property
    def platform(self) -> str:
        return "multi"

    # ------------------------------------------------------------------
    # fetch — clone or pull the repository
    # ------------------------------------------------------------------

    async def fetch(self) -> None:
        """Clone or update the LOLAPI repository."""
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
    # parse — turn YAML entries into prevention test dicts
    # ------------------------------------------------------------------

    async def parse(self) -> list[dict]:
        """Parse LOLAPI YAML files into prevention test dicts."""
        tests: list[dict] = []
        yml_dir = self.data_dir / "yaml"

        if not yml_dir.exists():
            logger.warning("LOLAPI yaml directory not found: %s", yml_dir)
            return tests

        for yml_file in sorted(yml_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                if data:
                    tests.extend(self._parse_entry(data))
            except Exception as exc:
                logger.debug("Failed to parse %s: %s", yml_file.name, exc)
                continue

        self._tests = tests
        logger.info("LOLAPI: parsed %d prevention tests from %s", len(tests), yml_dir)
        return tests

    # ------------------------------------------------------------------
    # _parse_entry — one YAML file -> N prevention test dicts
    # ------------------------------------------------------------------

    def _parse_entry(self, data: dict) -> list[dict]:
        """Convert a single LOLAPI YAML entry into prevention test dicts."""
        tests: list[dict] = []
        api_name: str = data.get("name", "")
        category: str = data.get("category", "")
        subcategory: str = data.get("subcategory", "")

        api_info: dict = data.get("api", {})
        namespace: str = api_info.get("namespace", "")
        api_class: str = api_info.get("class", "")
        api_method: str = api_info.get("method", "")
        api_language: str = api_info.get("language", "")
        api_doc_url: str = api_info.get("documentation", "")

        risk_data: dict = data.get("risk", {})
        severity: str = risk_data.get("severity", "medium")
        risk_level: str = _SEVERITY_TO_RISK.get(severity, "medium")
        prevalence: str = risk_data.get("prevalence", "")
        ease_of_abuse: str = risk_data.get("ease_of_abuse", "")
        likelihood: int = risk_data.get("likelihood_in_real_attacks", 0)

        platforms = _CATEGORY_PLATFORMS.get(category, ["windows"])

        # References at the entry level
        refs: dict = data.get("references", {})
        entry_technique_ids: list[str] = refs.get("techniques", [])
        tools: list[str] = refs.get("tools", [])
        threat_actors: list[str] = refs.get("threat_actors", [])

        # Detection and mitigation summaries
        detections: list[dict] = data.get("detection", [])
        mitigations: list[dict] = data.get("mitigation", [])

        detection_summary = "; ".join(
            f"{d.get('vendor', '?')}: {d.get('notes', '')}"
            for d in detections if d.get("notes")
        )
        mitigation_summary = "; ".join(
            d.get("description", "")
            for d in mitigations if d.get("description")
        )

        abuse_scenarios: list[dict] = data.get("abuse_scenarios", [])
        if not abuse_scenarios:
            return tests

        for idx, scenario in enumerate(abuse_scenarios):
            scenario_name: str = scenario.get("name", f"Scenario {idx + 1}")
            scenario_desc: str = scenario.get("description", "")
            code_snippet: str = scenario.get("code_snippet", "")

            if not code_snippet or code_snippet.strip() in ("", "N/A"):
                continue

            # Technique from scenario, entry-level references, or subcategory fallback
            technique_id = (
                scenario.get("technique_id", "")
                or (entry_technique_ids[0] if entry_technique_ids else "")
                or _SUBCATEGORY_TECHNIQUE_FALLBACK.get(subcategory, "T1106")
            )

            detection_difficulty: str = scenario.get("detection_difficulty", "medium")
            common_in_campaigns: bool = scenario.get("common_in_campaigns", False)
            evasion_techniques: list[str] = scenario.get("evasion_techniques", [])

            # Determine executor based on API language
            executor = self._resolve_executor(api_language, code_snippet)

            # Bump risk for entries that are common in campaigns or critical
            effective_risk = risk_level
            if common_in_campaigns and risk_level != "high":
                effective_risk = "high" if risk_level == "medium" else "medium"

            test_name = f"LOLAPI: {api_name} - {scenario_name}"
            test_desc = (
                f"{scenario_desc} "
                f"[API: {namespace}"
                f"{'.' + api_class if api_class else ''}"
                f"{'.' + api_method if api_method else ''}"
                f" | Detection difficulty: {detection_difficulty}]"
            ).strip()

            tests.append({
                "name": test_name,
                "description": test_desc,
                "command": code_snippet,
                "executor": executor,
                "technique_id": technique_id,
                "binary_path": None,
                "elevation_required": self._needs_elevation(
                    code_snippet, subcategory, category
                ),
                "risk_level": effective_risk,
                "platforms": platforms,
                "cleanup_command": None,
                "metadata": {
                    "source": "lolapi",
                    "api_name": api_name,
                    "category": category,
                    "subcategory": subcategory,
                    "namespace": namespace,
                    "class": api_class,
                    "method": api_method,
                    "language": api_language,
                    "documentation_url": api_doc_url,
                    "severity": severity,
                    "prevalence": prevalence,
                    "ease_of_abuse": ease_of_abuse,
                    "likelihood_in_real_attacks": likelihood,
                    "detection_difficulty": detection_difficulty,
                    "common_in_campaigns": common_in_campaigns,
                    "evasion_techniques": evasion_techniques,
                    "tools": tools,
                    "threat_actors": threat_actors,
                    "detection_summary": detection_summary,
                    "mitigation_summary": mitigation_summary,
                    "tags": data.get("tags", []),
                    "lolapi_id": data.get("id", ""),
                    "verified": data.get("verified", False),
                },
            })

        return tests

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_executor(language: str, code: str) -> str:
        """Pick the best executor based on API language and code content."""
        lang_lower = language.lower()
        code_lower = code.lower()

        if "powershell" in lang_lower or "powershell" in code_lower:
            return "powershell"
        if "javascript" in lang_lower:
            return "manual"  # Browser JS can't be run as a shell command
        if "http" in lang_lower or code_lower.startswith("curl "):
            return "bash"
        if "bash" in lang_lower or "shell" in lang_lower:
            return "bash"
        if "python" in lang_lower:
            return "bash"
        if "vbscript" in lang_lower:
            return "cmd"
        # .NET / C# / C/C++ — these are code samples, not runnable commands
        if any(kw in lang_lower for kw in ("c#", ".net", "c/c++")):
            return "manual"

        return "manual"

    @staticmethod
    def _needs_elevation(code: str, subcategory: str, category: str) -> bool:
        """Heuristic: does this abuse likely require elevated privileges?"""
        # Subcategories that typically need elevation
        elevated_subcats = {
            "process-injection", "memory-access", "hooking",
            "log-manipulation", "registry-manipulation",
        }
        if subcategory in elevated_subcats:
            return True

        # Native API calls almost always need admin/SYSTEM
        if category == "windows-native-api":
            return True

        # Code-level indicators
        indicators = [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtCreateThreadEx", "OpenProcess", "SeDebugPrivilege",
            "AdjustTokenPrivileges", "sudo ", "runas ",
        ]
        return any(ind in code for ind in indicators)

    # ------------------------------------------------------------------
    # MITRE mappings
    # ------------------------------------------------------------------

    def get_mitre_mappings(self) -> dict[str, list[str]]:
        """Return mapping of test names to MITRE technique IDs."""
        mappings: dict[str, list[str]] = {}
        for test in getattr(self, "_tests", []):
            tid = test.get("technique_id", "")
            if tid:
                mappings.setdefault(test["name"], []).append(tid)
        return mappings
