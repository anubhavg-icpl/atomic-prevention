import asyncio
import re

import yaml

from backend.app.ingestion.base import BaseIngestor


_COMPLEX_PREREQ_PATTERNS = (
    "Install-Module", "Install-Package", "pip install", "pip3 install",
    "choco install", "winget install", "apt-get install", "brew install",
    "gem install", "npm install", "cargo install", "terraform apply",
    "msiexec", "Add-WindowsCapability", "Install-WindowsFeature",
    "Enable-WindowsOptionalFeature", "cannot be met automatically",
    "must be installed manually",
)
_ASSET_ACQUISITION_PATTERNS = (
    "invoke-webrequest", "iwr ", "curl ", "wget ", "downloadfile(",
    "start-bitstransfer", "invoke-fetchfromzip", "git clone",
)
_INPUT_PATTERN = re.compile(r"#\{([^}]+)\}")
_ATOMICS_PATH_PATTERN = re.compile(
    r"\$\{PathToAtomicsFolder\}|\$PathToAtomicsFolder|PathToAtomicsFolder",
    re.IGNORECASE,
)
_POWERSHELL_TEMP_PATTERN = re.compile(r"\$(?:\{)?env:TEMP(?:\})?", re.IGNORECASE)
_CMD_TEMP_PATTERN = re.compile(r"%(?:TEMP|TMP)%", re.IGNORECASE)
_SHELL_TEMP_PATTERN = re.compile(r"\$\{TMPDIR:-/tmp\}|\$\{TMPDIR\}|\$TMPDIR")


class AtomicRedTeamIngestor(BaseIngestor):
    """Ingest Atomic Red Team while preserving execution prerequisites.

    Runnable tests have all default inputs resolved, use executor-appropriate
    working-directory syntax, and retain dependency checks for the agents.
    Tests that need operator input, interactive package installation, or
    unstaged Atomic assets remain visible in the catalog but are excluded from
    generated playbooks until they can be executed safely and deterministically.
    """

    @property
    def source_id(self) -> str:
        return "atomic-red-team"

    @property
    def display_name(self) -> str:
        return "Atomic Red Team"

    @property
    def description(self) -> str:
        return "Small, portable detection tests mapped to MITRE ATT&CK (repurposed for prevention)"

    @property
    def repo_url(self) -> str:
        return "https://github.com/redcanaryco/atomic-red-team"

    @property
    def platform(self) -> str:
        return "multi"

    async def fetch(self) -> None:
        repo_dir = self.data_dir
        if repo_dir.exists():
            proc = await asyncio.create_subprocess_exec(
                "git", "pull", "--ff-only", cwd=str(repo_dir),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        else:
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", self.repo_url, str(repo_dir),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"git fetch failed for {self.source_id}: {stderr.decode()}")

    async def parse(self) -> list[dict]:
        tests: list[dict] = []
        atomics_dir = self.data_dir / "atomics"
        if not atomics_dir.exists():
            self._tests = tests
            return tests

        for technique_dir in sorted(atomics_dir.iterdir()):
            if not technique_dir.is_dir() or not technique_dir.name.startswith("T"):
                continue
            yml_file = technique_dir / f"{technique_dir.name}.yaml"
            if not yml_file.exists():
                yml_file = technique_dir / f"{technique_dir.name}.yml"
            if not yml_file.exists():
                continue
            try:
                data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                if data:
                    tests.extend(self._parse_atomic(data))
            except (OSError, UnicodeError, yaml.YAMLError):
                continue

        self._tests = tests
        return tests

    @staticmethod
    def _input_values(input_args: dict) -> tuple[dict[str, str], set[str]]:
        """Resolve nested defaults to a fixed point and track required inputs."""
        values: dict[str, str] = {}
        required: set[str] = set()

        for name, definition in input_args.items():
            default = definition.get("default") if isinstance(definition, dict) else None
            if default is None:
                # Atomic commonly uses a null default for an intentionally empty
                # optional argument. Other null defaults require operator input.
                if name.lower().startswith("optional_"):
                    values[name] = ""
                else:
                    required.add(name)
            else:
                values[name] = str(default)

        for _ in range(len(values) + 1):
            changed = False
            for name, value in list(values.items()):
                resolved = _INPUT_PATTERN.sub(
                    lambda match: values.get(match.group(1), match.group(0)), value
                )
                if resolved != value:
                    values[name] = resolved
                    changed = True
            if not changed:
                break

        return values, required

    @staticmethod
    def _resolve_variables(text: str | None, values: dict[str, str]) -> str:
        if not text:
            return ""
        resolved = str(text)
        for _ in range(len(values) + 1):
            updated = _INPUT_PATTERN.sub(
                lambda match: values.get(match.group(1), match.group(0)), resolved
            )
            if updated == resolved:
                break
            resolved = updated
        return resolved

    @staticmethod
    def _resolve_paths(text: str, executor: str) -> str:
        if not text:
            return ""
        executor = executor.lower()
        if executor in ("bash", "sh", "zsh"):
            root = "${TMPDIR:-/tmp}/AtomicPrevention/atomics"
        elif executor in ("command_prompt", "cmd"):
            root = r"%TEMP%\AtomicPrevention\atomics"
        else:
            root = r"$env:TEMP\AtomicPrevention\atomics"
        resolved = _ATOMICS_PATH_PATTERN.sub(lambda _: root, text)
        if executor in ("bash", "sh", "zsh"):
            resolved = _POWERSHELL_TEMP_PATTERN.sub(lambda _: "${TMPDIR:-/tmp}", resolved)
            resolved = _CMD_TEMP_PATTERN.sub(lambda _: "${TMPDIR:-/tmp}", resolved)
        elif executor in ("command_prompt", "cmd"):
            resolved = _POWERSHELL_TEMP_PATTERN.sub(lambda _: "%TEMP%", resolved)
            resolved = _SHELL_TEMP_PATTERN.sub(lambda _: "%TEMP%", resolved)
        else:
            resolved = _CMD_TEMP_PATTERN.sub(lambda _: r"$env:TEMP", resolved)
            resolved = _SHELL_TEMP_PATTERN.sub(lambda _: r"$env:TEMP", resolved)
        return resolved

    def _parse_atomic(self, data: dict) -> list[dict]:
        tests: list[dict] = []
        technique_id = data.get("attack_technique", "")
        display_name = data.get("display_name", "")

        for atomic in data.get("atomic_tests", []):
            executor = atomic.get("executor") or {}
            executor_name = executor.get("name", "manual")
            command = executor.get("command", "")
            if executor_name == "manual" or not command:
                continue

            input_args = atomic.get("input_arguments") or {}
            values, required_inputs = self._input_values(input_args)
            resolved_command = self._resolve_variables(command, values)
            resolved_cleanup = self._resolve_variables(executor.get("cleanup_command"), values)

            dependencies = atomic.get("dependencies") or []
            dependency_executor = atomic.get("dependency_executor_name") or executor_name
            prerequisites: list[dict] = []
            complex_prereqs = False

            for dependency in dependencies:
                check = self._resolve_variables(dependency.get("prereq_command"), values)
                setup = self._resolve_variables(dependency.get("get_prereq_command"), values)
                check = self._resolve_paths(check, dependency_executor)
                setup = self._resolve_paths(setup, dependency_executor)
                if any(pattern.lower() in setup.lower() for pattern in _COMPLEX_PREREQ_PATTERNS):
                    complex_prereqs = True
                prerequisites.append({
                    "description": dependency.get("description", ""),
                    "executor": dependency_executor,
                    "check_command": check,
                    "get_command": setup,
                })

            unresolved = set(_INPUT_PATTERN.findall(resolved_command + "\n" + resolved_cleanup))
            for prerequisite in prerequisites:
                unresolved.update(_INPUT_PATTERN.findall(
                    prerequisite["check_command"] + "\n" + prerequisite["get_command"]
                ))
            unresolved.update(required_inputs)

            command_needs_assets = bool(_ATOMICS_PATH_PATTERN.search(resolved_command))
            cleanup_needs_assets = bool(_ATOMICS_PATH_PATTERN.search(resolved_cleanup))
            setup_text = "\n".join(p["get_command"].lower() for p in prerequisites)
            has_asset_acquisition = any(
                pattern in setup_text for pattern in _ASSET_ACQUISITION_PATTERNS
            )
            missing_asset_setup = (command_needs_assets or cleanup_needs_assets) and not has_asset_acquisition

            resolved_command = self._resolve_paths(resolved_command, executor_name)
            resolved_cleanup = self._resolve_paths(resolved_cleanup, executor_name)

            readiness_reasons: list[str] = []
            if unresolved:
                readiness_reasons.append(
                    "Requires input values: " + ", ".join(sorted(unresolved))
                )
            if complex_prereqs:
                readiness_reasons.append("Requires interactive or complex prerequisite setup")
            if missing_asset_setup:
                readiness_reasons.append("References Atomic Red Team assets without an acquisition step")

            executor_map = {
                "command_prompt": "cmd",
                "powershell": "powershell",
                "bash": "bash",
                "sh": "bash",
                "zsh": "zsh",
            }
            mapped_executor = executor_map.get(executor_name, executor_name)
            elevation = bool(executor.get("elevation_required", atomic.get("elevation_required", False)))

            tests.append({
                "name": f"ART: {atomic.get('name', '')}",
                "description": f"[{display_name}] {atomic.get('description', '')}",
                "command": resolved_command,
                "executor": mapped_executor,
                "technique_id": technique_id,
                "binary_path": None,
                "elevation_required": elevation,
                "risk_level": "high" if elevation else "medium",
                "platforms": atomic.get("supported_platforms", []),
                "cleanup_command": resolved_cleanup or None,
                "metadata": {
                    "auto_generated_guid": atomic.get("auto_generated_guid", ""),
                    "display_name": display_name,
                    "input_arguments": input_args,
                    "required_inputs": sorted(unresolved),
                    "prerequisites": prerequisites,
                    "has_prereqs": bool(prerequisites),
                    "prereq_count": len(prerequisites),
                    "complex_prereqs": complex_prereqs,
                    "missing_asset_setup": missing_asset_setup,
                    "runnable": not readiness_reasons,
                    "readiness_reasons": readiness_reasons,
                },
            })

        return tests

    def get_mitre_mappings(self) -> dict[str, list[str]]:
        mappings: dict[str, list[str]] = {}
        for test in getattr(self, "_tests", []):
            if test.get("technique_id"):
                mappings.setdefault(test["name"], []).append(test["technique_id"])
        return mappings
