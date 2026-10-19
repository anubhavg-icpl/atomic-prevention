"""Sysinternals prevention-testing ingestor -- download, stage, rename & run.

Catalogs the most commonly abused Sysinternals tools and generates four
prevention test variants per tool:

  1. **Download from live.sysinternals.com** -- tests ingress-tool-transfer
     controls (T1105).
  2. **Place in a random directory and execute** -- tests whether execution
     from non-standard paths is blocked.
  3. **Rename and execute** -- tests masquerading detection (T1036.005).
  4. **Execute from UNC path** -- tests whether direct execution from the
     Sysinternals Live share (``\\\\live.sysinternals.com\\tools``) is blocked.

All data is fully hardcoded.  ``fetch()`` is a no-op; the tools are
downloaded at test execution time, not at sync time.

Platform: **Windows only**.
"""

import logging
from typing import Any

from backend.app.ingestion.base import BaseIngestor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hardcoded catalog of Sysinternals tools
# ---------------------------------------------------------------------------
# Fields per entry:
#   id              - unique slug
#   name            - human-readable tool name
#   description     - what the tool does / why adversaries use it
#   filename        - primary binary filename (64-bit preferred)
#   alt_filename    - 32-bit or alternative filename (optional)
#   technique_id    - primary MITRE ATT&CK technique
#   technique_ids   - all mapped MITRE techniques (including download/rename)
#   safe_flag       - CLI flag that produces help / version output without harm
#   renamed_as      - masquerading filename for rename test
#   elevation_required - whether admin privileges are needed
#   risk_level      - "low" | "medium" | "high"

_SYSINTERNALS_CATALOG: list[dict[str, Any]] = [
    # ==================================================================
    # 1. PsExec
    # ==================================================================
    {
        "id": "psexec",
        "name": "PsExec",
        "description": (
            "PsExec is a lightweight telnet-replacement that lets you execute "
            "processes on remote systems. Adversaries abuse it for lateral "
            "movement and remote code execution."
        ),
        "filename": "PsExec64.exe",
        "alt_filename": "PsExec.exe",
        "technique_id": "T1569.002",
        "technique_ids": ["T1569.002", "T1021.002"],
        "safe_flag": "-accepteula -nobanner /?",
        "renamed_as": "svchost_update.exe",
        "elevation_required": True,
        "risk_level": "high",
    },
    # ==================================================================
    # 2. ProcDump
    # ==================================================================
    {
        "id": "procdump",
        "name": "ProcDump",
        "description": (
            "ProcDump is a process dumping utility. Adversaries use it to "
            "dump LSASS memory for credential theft."
        ),
        "filename": "procdump64.exe",
        "alt_filename": "procdump.exe",
        "technique_id": "T1003.001",
        "technique_ids": ["T1003.001"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "debugger_helper.exe",
        "elevation_required": True,
        "risk_level": "high",
    },
    # ==================================================================
    # 3. AccessChk
    # ==================================================================
    {
        "id": "accesschk",
        "name": "AccessChk",
        "description": (
            "AccessChk enumerates effective permissions on files, registry "
            "keys, services, and other objects. Adversaries use it to "
            "discover privilege-escalation opportunities."
        ),
        "filename": "accesschk64.exe",
        "alt_filename": "accesschk.exe",
        "technique_id": "T1069",
        "technique_ids": ["T1069", "T1083"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "perms_audit.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 4. Autoruns
    # ==================================================================
    {
        "id": "autoruns",
        "name": "Autoruns",
        "description": (
            "Autoruns shows programs configured to run during system boot or "
            "login. Adversaries use it to enumerate and discover persistence "
            "mechanisms on a target."
        ),
        "filename": "Autoruns64.exe",
        "alt_filename": "Autoruns.exe",
        "technique_id": "T1518.001",
        "technique_ids": ["T1518.001"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "startup_check.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 5. ProcMon (Process Monitor)
    # ==================================================================
    {
        "id": "procmon",
        "name": "ProcMon",
        "description": (
            "Process Monitor shows real-time file, registry, and process "
            "activity. Adversaries may use it to understand defensive tools "
            "running on a host."
        ),
        "filename": "Procmon64.exe",
        "alt_filename": "Procmon.exe",
        "technique_id": "T1057",
        "technique_ids": ["T1057"],
        "safe_flag": "-accepteula /Terminate",
        "renamed_as": "perfmon_helper.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 6. PsService
    # ==================================================================
    {
        "id": "psservice",
        "name": "PsService",
        "description": (
            "PsService is a command-line service viewer and controller. "
            "Adversaries use it to enumerate services and discover "
            "security-related services that may be disabled."
        ),
        "filename": "PsService64.exe",
        "alt_filename": "PsService.exe",
        "technique_id": "T1007",
        "technique_ids": ["T1007"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "svc_query.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 7. PsInfo
    # ==================================================================
    {
        "id": "psinfo",
        "name": "PsInfo",
        "description": (
            "PsInfo gathers system information including installed software, "
            "hotfixes, and hardware. Adversaries use it for host "
            "reconnaissance."
        ),
        "filename": "PsInfo64.exe",
        "alt_filename": "PsInfo.exe",
        "technique_id": "T1082",
        "technique_ids": ["T1082"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "hw_inventory.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 8. PsList
    # ==================================================================
    {
        "id": "pslist",
        "name": "PsList",
        "description": (
            "PsList displays detailed information about running processes. "
            "Adversaries use it for process discovery."
        ),
        "filename": "PsList64.exe",
        "alt_filename": "PsList.exe",
        "technique_id": "T1057",
        "technique_ids": ["T1057"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "tasklist_helper.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 9. PsLoggedOn
    # ==================================================================
    {
        "id": "psloggedon",
        "name": "PsLoggedOn",
        "description": (
            "PsLoggedOn shows who is logged on locally and via resource "
            "sharing. Adversaries use it to discover active user sessions."
        ),
        "filename": "PsLoggedon64.exe",
        "alt_filename": "PsLoggedon.exe",
        "technique_id": "T1033",
        "technique_ids": ["T1033"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "session_check.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 10. ADExplorer
    # ==================================================================
    {
        "id": "adexplorer",
        "name": "ADExplorer",
        "description": (
            "ADExplorer is an Active Directory viewer and editor. Adversaries "
            "use it to enumerate AD objects, users, groups, and trusts."
        ),
        "filename": "ADExplorer64.exe",
        "alt_filename": "ADExplorer.exe",
        "technique_id": "T1018",
        "technique_ids": ["T1018", "T1087.002"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "ldap_browser.exe",
        "elevation_required": False,
        "risk_level": "high",
    },
    # ==================================================================
    # 11. Handle
    # ==================================================================
    {
        "id": "handle",
        "name": "Handle",
        "description": (
            "Handle displays information about open handles for any process. "
            "Adversaries use it to discover files and resources locked by "
            "security tools."
        ),
        "filename": "handle64.exe",
        "alt_filename": "handle.exe",
        "technique_id": "T1057",
        "technique_ids": ["T1057"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "resource_mon.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 12. SDelete
    # ==================================================================
    {
        "id": "sdelete",
        "name": "SDelete",
        "description": (
            "SDelete securely deletes files by overwriting their contents. "
            "Adversaries use it to destroy evidence and cover tracks."
        ),
        "filename": "sdelete64.exe",
        "alt_filename": "sdelete.exe",
        "technique_id": "T1070.004",
        "technique_ids": ["T1070.004"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "disk_cleanup.exe",
        "elevation_required": False,
        "risk_level": "high",
    },
    # ==================================================================
    # 13. Strings
    # ==================================================================
    {
        "id": "strings",
        "name": "Strings",
        "description": (
            "Strings extracts printable strings from binary files. Adversaries "
            "use it to inspect files for credentials, keys, or sensitive data."
        ),
        "filename": "strings64.exe",
        "alt_filename": "strings.exe",
        "technique_id": "T1005",
        "technique_ids": ["T1005"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "text_extract.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 14. TCPView
    # ==================================================================
    {
        "id": "tcpview",
        "name": "TCPView",
        "description": (
            "TCPView shows detailed listings of all TCP and UDP endpoints. "
            "Adversaries use it for network connection discovery."
        ),
        "filename": "Tcpview64.exe",
        "alt_filename": "Tcpview.exe",
        "technique_id": "T1049",
        "technique_ids": ["T1049"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "netstat_gui.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 15. ShellRunas
    # ==================================================================
    {
        "id": "shellrunas",
        "name": "ShellRunas",
        "description": (
            "ShellRunas launches programs as a different user via a shell "
            "context menu. Adversaries use it as an alternative to runas.exe "
            "for access token manipulation."
        ),
        "filename": "ShellRunas.exe",
        "alt_filename": None,
        "technique_id": "T1134",
        "technique_ids": ["T1134"],
        "safe_flag": "/? ",
        "renamed_as": "run_elevated.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 16. PipeList
    # ==================================================================
    {
        "id": "pipelist",
        "name": "PipeList",
        "description": (
            "PipeList displays the named pipes on a system. Adversaries "
            "use it to discover inter-process communication channels that "
            "may be exploitable for lateral movement."
        ),
        "filename": "pipelist64.exe",
        "alt_filename": "pipelist.exe",
        "technique_id": "T1570",
        "technique_ids": ["T1570"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "ipc_enum.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 17. LogonSessions
    # ==================================================================
    {
        "id": "logonsessions",
        "name": "LogonSessions",
        "description": (
            "LogonSessions lists the currently active logon sessions. "
            "Adversaries use it to enumerate local and domain accounts."
        ),
        "filename": "logonsessions64.exe",
        "alt_filename": "logonsessions.exe",
        "technique_id": "T1087.001",
        "technique_ids": ["T1087.001"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "session_enum.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 18. du (Disk Usage)
    # ==================================================================
    {
        "id": "du",
        "name": "du",
        "description": (
            "du reports the disk space usage for a directory tree. Adversaries "
            "use it to survey disk contents and locate large data stores for "
            "exfiltration."
        ),
        "filename": "du64.exe",
        "alt_filename": "du.exe",
        "technique_id": "T1083",
        "technique_ids": ["T1083"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "space_check.exe",
        "elevation_required": False,
        "risk_level": "medium",
    },
    # ==================================================================
    # 19. Sysmon
    # ==================================================================
    {
        "id": "sysmon",
        "name": "Sysmon",
        "description": (
            "Sysmon is a system monitoring service. Testing whether an "
            "adversary can install or tamper with Sysmon validates defense "
            "integrity controls."
        ),
        "filename": "Sysmon64.exe",
        "alt_filename": "Sysmon.exe",
        "technique_id": "T1562.001",
        "technique_ids": ["T1562.001"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "monitor_svc.exe",
        "elevation_required": True,
        "risk_level": "high",
    },
    # ==================================================================
    # 20. LiveKd
    # ==================================================================
    {
        "id": "livekd",
        "name": "LiveKd",
        "description": (
            "LiveKd runs the Kd/WinDbg kernel debuggers on a live system. "
            "Adversaries may use it for kernel-level inspection and "
            "privilege escalation research."
        ),
        "filename": "livekd64.exe",
        "alt_filename": "livekd.exe",
        "technique_id": "T1068",
        "technique_ids": ["T1068"],
        "safe_flag": "-accepteula /?",
        "renamed_as": "kernel_diag.exe",
        "elevation_required": True,
        "risk_level": "high",
    },
]


# ---------------------------------------------------------------------------
# Helper: build the four test variants for a single tool
# ---------------------------------------------------------------------------

def _build_variants(tool: dict[str, Any]) -> list[dict[str, Any]]:
    """Return four test variant dicts for the given Sysinternals tool."""

    filename = tool["filename"]
    safe_flag = tool["safe_flag"]
    renamed_as = tool["renamed_as"]
    elevation = tool["elevation_required"]
    risk = tool["risk_level"]
    base_tids = list(tool["technique_ids"])

    variants: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Variant 1: Download from live.sysinternals.com and execute
    # ------------------------------------------------------------------
    dl_cmd = (
        f"$toolUrl = 'https://live.sysinternals.com/tools/{filename}'; "
        f"$outPath = Join-Path $env:TEMP '{filename}'; "
        "try { "
        "Invoke-WebRequest -Uri $toolUrl -OutFile $outPath -UseBasicParsing -ErrorAction Stop; "
        "if (Test-Path $outPath) { "
        "$hash = (Get-FileHash $outPath -Algorithm SHA256).Hash; "
        f"Write-Host \"Downloaded: $outPath (SHA256: $hash)\"; "
        f"& $outPath {safe_flag} 2>&1 | Out-Null; "
        f"Write-Host 'ALLOWED: {filename} downloaded from live.sysinternals.com and executed from TEMP' "
        "} else { "
        f"Write-Host 'BLOCKED: {filename} download prevented' "
        "} "
        "} catch { "
        f"Write-Host 'BLOCKED:' $_.Exception.Message "
        "}"
    )
    dl_cleanup = (
        f"Remove-Item -Path (Join-Path $env:TEMP '{filename}') -Force -ErrorAction SilentlyContinue"
    )
    variants.append({
        "variant_name": "Download from live.sysinternals.com",
        "executor": "powershell",
        "elevation": elevation,
        "risk_level": risk,
        "command": dl_cmd,
        "cleanup": dl_cleanup,
        "description": (
            f"Downloads {filename} from https://live.sysinternals.com/tools/ "
            f"and executes it from %TEMP%. Tests ingress tool transfer controls "
            f"and whether execution of freshly downloaded Sysinternals binaries "
            f"is detected or blocked."
        ),
        "extra_technique_ids": ["T1105"],
    })

    # ------------------------------------------------------------------
    # Variant 2: Place in a random directory and execute
    # ------------------------------------------------------------------
    stage_cmd = (
        "$randomDir = Join-Path $env:USERPROFILE "
        "('Desktop\\' + [System.IO.Path]::GetRandomFileName()); "
        "New-Item -ItemType Directory -Path $randomDir -Force | Out-Null; "
        f"$toolUrl = 'https://live.sysinternals.com/tools/{filename}'; "
        f"$toolPath = Join-Path $randomDir '{filename}'; "
        "try { "
        "Invoke-WebRequest -Uri $toolUrl -OutFile $toolPath -UseBasicParsing -ErrorAction Stop; "
        "if (Test-Path $toolPath) { "
        f"& $toolPath {safe_flag} 2>&1 | Out-Null; "
        f"Write-Host \"ALLOWED: {filename} executed from random location: $randomDir\" "
        "} else { "
        f"Write-Host 'BLOCKED: {filename} could not be staged to random directory' "
        "} "
        "} catch { "
        f"Write-Host 'BLOCKED:' $_.Exception.Message "
        "}"
    )
    stage_cleanup = (
        "$randomDir = Get-ChildItem -Path (Join-Path $env:USERPROFILE 'Desktop') "
        "-Directory -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Name -match '^[a-z0-9]{8}\\.[a-z0-9]{3}$' }; "
        "foreach ($d in $randomDir) { Remove-Item $d.FullName -Recurse -Force -ErrorAction SilentlyContinue }"
    )
    variants.append({
        "variant_name": "Stage in random directory",
        "executor": "powershell",
        "elevation": elevation,
        "risk_level": risk,
        "command": stage_cmd,
        "cleanup": stage_cleanup,
        "description": (
            f"Downloads {filename} and copies it to a randomly named directory on "
            f"the Desktop, then executes it. Simulates adversary staging in a "
            f"non-standard location."
        ),
        "extra_technique_ids": ["T1105"],
    })

    # ------------------------------------------------------------------
    # Variant 3: Rename and execute (masquerading)
    # ------------------------------------------------------------------
    rename_cmd = (
        f"$toolUrl = 'https://live.sysinternals.com/tools/{filename}'; "
        f"$renamedPath = Join-Path $env:TEMP '{renamed_as}'; "
        "try { "
        "Invoke-WebRequest -Uri $toolUrl -OutFile $renamedPath -UseBasicParsing -ErrorAction Stop; "
        "if (Test-Path $renamedPath) { "
        f"& $renamedPath {safe_flag} 2>&1 | Out-Null; "
        f"Write-Host 'ALLOWED: {filename} renamed to {renamed_as} and executed successfully' "
        "} else { "
        f"Write-Host 'BLOCKED: Renamed {filename} could not be written to disk' "
        "} "
        "} catch { "
        f"Write-Host 'BLOCKED:' $_.Exception.Message "
        "}"
    )
    rename_cleanup = (
        f"Remove-Item -Path (Join-Path $env:TEMP '{renamed_as}') -Force -ErrorAction SilentlyContinue"
    )
    variants.append({
        "variant_name": "Rename and execute (masquerading)",
        "executor": "powershell",
        "elevation": elevation,
        "risk_level": risk,
        "command": rename_cmd,
        "cleanup": rename_cleanup,
        "description": (
            f"Downloads {filename} and saves it as {renamed_as} in %TEMP%, "
            f"then executes the renamed binary. Tests whether security controls "
            f"detect Sysinternals tools by hash/signature even when the filename "
            f"is changed (masquerading)."
        ),
        "extra_technique_ids": ["T1036.005"],
    })

    # ------------------------------------------------------------------
    # Variant 4: Execute from UNC path (Sysinternals Live share)
    # ------------------------------------------------------------------
    unc_cmd = (
        f"$uncPath = '\\\\live.sysinternals.com\\tools\\{filename}'; "
        "try { "
        f"& $uncPath {safe_flag} 2>&1 | Out-Null; "
        f"Write-Host 'ALLOWED: {filename} executed directly from Sysinternals Live UNC share' "
        "} catch { "
        f"Write-Host 'BLOCKED:' $_.Exception.Message "
        "}"
    )
    variants.append({
        "variant_name": "Execute from UNC path",
        "executor": "powershell",
        "elevation": elevation,
        "risk_level": risk,
        "command": unc_cmd,
        "cleanup": "# No cleanup needed -- no file written to disk",
        "description": (
            f"Executes {filename} directly from the Sysinternals Live UNC share "
            f"(\\\\live.sysinternals.com\\tools). Tests whether WebDAV-based "
            f"remote execution is blocked by network or endpoint controls."
        ),
        "extra_technique_ids": ["T1105"],
    })

    return variants


# ---------------------------------------------------------------------------
# MITRE technique name lookup
# ---------------------------------------------------------------------------

_TECHNIQUE_NAMES: dict[str, str] = {
    "T1569.002": "System Services: Service Execution",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1069": "Permission Groups Discovery",
    "T1083": "File and Directory Discovery",
    "T1518.001": "Software Discovery: Security Software Discovery",
    "T1057": "Process Discovery",
    "T1007": "System Service Discovery",
    "T1082": "System Information Discovery",
    "T1033": "System Owner/User Discovery",
    "T1018": "Remote System Discovery",
    "T1087.002": "Account Discovery: Domain Account",
    "T1087.001": "Account Discovery: Local Account",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1005": "Data from Local System",
    "T1049": "System Network Connections Discovery",
    "T1134": "Access Token Manipulation",
    "T1570": "Lateral Tool Transfer",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1068": "Exploitation for Privilege Escalation",
    "T1105": "Ingress Tool Transfer",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
}


# ---------------------------------------------------------------------------
# Ingestor class
# ---------------------------------------------------------------------------

class SysinternalsIngestor(BaseIngestor):
    """Ingestor for Sysinternals prevention tests -- hardcoded catalog.

    Generates four test variants per tool (download, stage, rename, UNC)
    covering 20 commonly abused Sysinternals utilities.  All data is
    embedded directly in this module; ``fetch()`` is a no-op.
    """

    @property
    def source_id(self) -> str:
        return "sysinternals"

    @property
    def display_name(self) -> str:
        return "Sysinternals"

    @property
    def description(self) -> str:
        return (
            "Prevention tests for Sysinternals tools commonly abused by "
            "adversaries. Downloads each tool from live.sysinternals.com, "
            "stages it in random directories, renames it to masquerade as "
            "a legitimate binary, and executes from UNC paths -- testing "
            "whether security controls detect or block each scenario."
        )

    @property
    def repo_url(self) -> str:
        return "https://live.sysinternals.com/"

    @property
    def platform(self) -> str:
        return "windows"

    # ------------------------------------------------------------------
    # Fetch: no-op -- tools are downloaded at test execution time
    # ------------------------------------------------------------------
    async def fetch(self) -> None:
        """No-op. Sysinternals tools are downloaded at test execution time."""
        pass

    # ------------------------------------------------------------------
    # Parse: build prevention tests from the hardcoded catalog
    # ------------------------------------------------------------------
    async def parse(self) -> list[dict]:
        """Build prevention test dicts from the hardcoded Sysinternals catalog."""
        tests: list[dict] = []

        for tool in _SYSINTERNALS_CATALOG:
            tool_id = tool["id"]
            tool_name = tool["name"]
            tool_desc = tool["description"]
            technique_id = tool["technique_id"]
            base_tids = list(tool["technique_ids"])

            for variant in _build_variants(tool):
                variant_name = variant["variant_name"]
                test_name = f"Sysinternals: {tool_name} - {variant_name}"

                # Merge base technique IDs with variant-specific extras
                extra_tids = variant.get("extra_technique_ids", [])
                all_tids = list(dict.fromkeys(base_tids + extra_tids))

                tests.append({
                    "name": test_name,
                    "description": (
                        f"{variant['description']} "
                        f"[{tool_desc[:300]}]"
                    ).strip(),
                    "command": variant["command"],
                    "executor": variant["executor"],
                    "technique_id": technique_id,
                    "technique_ids": all_tids,
                    "binary_path": None,
                    "elevation_required": variant["elevation"],
                    "risk_level": variant["risk_level"],
                    "platforms": ["windows"],
                    "cleanup_command": variant["cleanup"],
                    "metadata": {
                        "source": "sysinternals",
                        "tool_id": tool_id,
                        "tool_name": tool_name,
                        "filename": tool["filename"],
                        "variant": variant_name,
                        "download_url": f"https://live.sysinternals.com/tools/{tool['filename']}",
                        "mitre_techniques": {
                            tid: _TECHNIQUE_NAMES.get(tid, tid)
                            for tid in all_tids
                        },
                    },
                    "guidance": {
                        "what_this_tests": (
                            f"Attempts to {variant_name.lower()} the Sysinternals tool "
                            f"{tool_name} ({tool['filename']}) and checks whether "
                            f"security controls detect or block the operation."
                        ),
                        "if_blocked": (
                            f"Your security controls blocked {tool_name} "
                            f"({variant_name.lower()}). This attack vector is covered."
                        ),
                        "if_allowed": (
                            f"ALLOWED: {tool_name} was successfully used via "
                            f"{variant_name.lower()}. Review your EDR/endpoint "
                            f"policies to detect or prevent Sysinternals tool abuse."
                        ),
                        "mitre_reference": (
                            f"https://attack.mitre.org/techniques/"
                            f"{technique_id.replace('.', '/')}/"
                        ),
                    },
                })

        logger.info(
            "Sysinternals: built %d prevention tests from %d tools",
            len(tests),
            len(_SYSINTERNALS_CATALOG),
        )
        self._tests = tests
        return tests

    # ------------------------------------------------------------------
    # MITRE mappings
    # ------------------------------------------------------------------
    def get_mitre_mappings(self) -> dict[str, list[str]]:
        """Return mapping of test names to MITRE technique IDs."""
        mappings: dict[str, list[str]] = {}
        for test in getattr(self, "_tests", []):
            name = test.get("name", "")
            tids = test.get("technique_ids", [])
            if not tids:
                tid = test.get("technique_id", "")
                tids = [tid] if tid else []
            if tids:
                mappings.setdefault(name, []).extend(tids)
        return mappings
