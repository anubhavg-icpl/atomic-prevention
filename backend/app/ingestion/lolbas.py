import asyncio
import glob
from pathlib import Path

import yaml

from backend.app.ingestion.base import BaseIngestor


class LOLBASIngestor(BaseIngestor):

    @property
    def source_id(self) -> str:
        return "lolbas"

    @property
    def display_name(self) -> str:
        return "LOLBAS"

    @property
    def description(self) -> str:
        return "Living Off The Land Binaries, Scripts, and Libraries"

    @property
    def repo_url(self) -> str:
        return "https://github.com/LOLBAS-Project/LOLBAS"

    @property
    def platform(self) -> str:
        return "windows"

    async def fetch(self) -> None:
        repo_dir = self.data_dir
        if repo_dir.exists():
            proc = await asyncio.create_subprocess_exec(
                "git", "pull", cwd=str(repo_dir),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"git pull failed for {self.source_id}: {stderr.decode()}")
        else:
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", self.repo_url, str(repo_dir),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"git clone failed for {self.source_id}: {stderr.decode()}")

    async def parse(self) -> list[dict]:
        tests = []
        yml_dirs = [
            self.data_dir / "yml" / "OSBinaries",
            self.data_dir / "yml" / "OSLibraries",
            self.data_dir / "yml" / "OSScripts",
            self.data_dir / "yml" / "OtherMSBinaries",
        ]

        for yml_dir in yml_dirs:
            if not yml_dir.exists():
                continue
            for yml_file in yml_dir.rglob("*.yml"):
                try:
                    data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                    if not data:
                        continue
                    tests.extend(self._parse_entry(data))
                except Exception:
                    continue

        self._tests = tests
        return tests

    def _parse_entry(self, data: dict) -> list[dict]:
        tests = []
        name = data.get("Name", "")
        description = data.get("Description", "")
        binary_path = None

        # Extract full path from the entry
        paths = data.get("Full_Path", [])
        if paths and isinstance(paths, list):
            for p in paths:
                path_val = p.get("Path") if isinstance(p, dict) else p
                if path_val and path_val != "N/A":
                    binary_path = path_val
                    break

        commands = data.get("Commands", [])
        if not commands:
            return tests

        for cmd_entry in commands:
            if not isinstance(cmd_entry, dict):
                continue

            command = cmd_entry.get("Command", "")
            if not command or command == "N/A":
                continue

            technique_id = cmd_entry.get("MitreID", "")
            usecase = cmd_entry.get("Usecase", "")
            category = cmd_entry.get("Category", "")

            # Determine executor
            executor = "cmd"
            cmd_lower = command.lower()
            if cmd_lower.startswith("powershell") or "invoke-" in cmd_lower:
                executor = "powershell"

            # Determine risk level based on category
            risk_map = {
                "Execute": "high",
                "Download": "medium",
                "AWL Bypass": "high",
                "ADS": "medium",
                "Encode": "low",
                "Decode": "low",
                "Copy": "low",
                "Compile": "medium",
                "Credentials": "high",
                "Dump": "high",
                "Reconnaissance": "low",
                "Upload": "medium",
            }
            risk_level = risk_map.get(category, "medium")

            tests.append({
                "name": f"{name} - {usecase}" if usecase else name,
                "description": f"{description} ({category})" if category else description,
                "command": command,
                "executor": executor,
                "technique_id": technique_id,
                "binary_path": binary_path,
                "elevation_required": False,
                "risk_level": risk_level,
                "platforms": ["windows"],
                "cleanup_command": None,
                "metadata": {
                    "category": category,
                    "usecase": usecase,
                    "source_file": name,
                },
            })

        return tests

    def get_mitre_mappings(self) -> dict[str, list[str]]:
        mappings = {}
        for test in getattr(self, "_tests", []):
            tid = test.get("technique_id", "")
            if tid:
                mappings.setdefault(test["name"], []).append(tid)
        return mappings
