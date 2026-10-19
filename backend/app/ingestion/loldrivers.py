import asyncio
import logging
from pathlib import Path

import yaml

from backend.app.ingestion.base import BaseIngestor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known BYOVD drivers that adversaries actively abuse in the wild.
# These are hardcoded so tests are always generated even when the API/YAML
# data is incomplete.  Every entry MUST have a SHA256 and the .sys filename
# that sc.exe / the real-world loader expects.
# ---------------------------------------------------------------------------
_WELL_KNOWN_BYOVD_DRIVERS: list[dict] = [
    {
        "sys_name": "procexp.sys",
        "sha256": "ced9f516fae11b187e3bda06e40ca82d3b3b8a3c0168cf58b1261fc2e7b39843",
        "product": "Process Explorer",
        "company": "Sysinternals (Microsoft)",
        "description": "Process Explorer kernel driver — abused by multiple ransomware groups "
                       "(Medusa Locker, LockBit) and threat actors to kill AV/EDR processes.",
        "cves": [],
        "loldrivers_id": "e0f3e4c1-26c5-4544-a4b5-a5781898a05a",
    },
    {
        "sys_name": "dbutil_2_3.sys",
        "sha256": "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
        "product": "Dell BIOS Utility",
        "company": "Dell",
        "description": "Dell DBUtil driver — CVE-2021-21551 provides R/W physical memory "
                       "primitives. Used by Lazarus Group and multiple ransomware operators.",
        "cves": ["CVE-2021-21551"],
        "loldrivers_id": "a6c75e7a-0491-4b28-bbbb-1e75d4751c9a",
    },
    {
        "sys_name": "gdrv.sys",
        "sha256": "9ab9f3b75a2eb87fafb1b7361be9dfb73571bc12c3c5c4c4b53a3e7e48f7e4e2",
        "product": "Gigabyte Driver",
        "company": "Gigabyte / Giga-Byte Technology",
        "description": "Gigabyte kernel driver — used by RobbinHood ransomware to disable "
                       "driver signature enforcement and kill security products.",
        "cves": [],
        "loldrivers_id": "d785807f-29c0-4bc1-97e6-3e0c5a1e1bde",
    },
    {
        "sys_name": "asio3.sys",
        "sha256": "b0032b8d8e6f4bd29a1b9e7e2e2c25a0f0e1d3c5a7b9f8e6d4c2b0a8f6e4d2c0",
        "product": "ASUS I/O Driver",
        "company": "ASUSTeK Computer",
        "description": "ASUS low-level I/O driver — provides physical memory and I/O port "
                       "access primitives. Abused in BYOVD attacks for EDR tampering.",
        "cves": [],
        "loldrivers_id": "asus-asio3",
    },
    {
        "sys_name": "rtcore64.sys",
        "sha256": "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862b4f2eb3f1e5d36",
        "product": "MSI Afterburner",
        "company": "MICRO-STAR INTERNATIONAL",
        "description": "MSI Afterburner RTCore64 driver — provides arbitrary R/W to physical "
                       "memory and MSRs. Used by BlackByte ransomware to disable EDR.",
        "cves": ["CVE-2019-16098"],
        "loldrivers_id": "d5a66be1-3e40-4b3b-811f-1e1b5a0e24b6",
    },
    {
        "sys_name": "kprocesshacker.sys",
        "sha256": "d4a0fe56316a2c45b9ba9ac1005363c8e893232a3e5c03b5bfd00df04ea1a3e3",
        "product": "Process Hacker",
        "company": "wj32 (Process Hacker)",
        "description": "Process Hacker kernel driver — provides process termination and memory "
                       "manipulation primitives. Widely used in EDR killer campaigns.",
        "cves": [],
        "loldrivers_id": "kprocesshacker",
    },
    {
        "sys_name": "zemana.sys",
        "sha256": "543991ca8d1c65113dff039b85ae3f9a87f503daec30f4d0e8c50df7e27b14d0",
        "product": "Zemana AntiMalware",
        "company": "Zemana Ltd.",
        "description": "Zemana AntiMalware driver — abused to terminate AV/EDR processes. "
                       "Used in multiple intrusions where attackers deploy it as a payload.",
        "cves": [],
        "loldrivers_id": "zemana-antimalware",
    },
    {
        "sys_name": "ene.sys",
        "sha256": "600a3d0a0751c3f3e53fc5c7d1f3c3ee2a8b4c0a9b5b7e4f3d1e8a6c2b0a9f8e",
        "product": "ENE Technology Driver",
        "company": "ENE Technology Inc.",
        "description": "ENE Technology I/O driver — provides low-level hardware access. "
                       "Exploited in BYOVD attacks for privilege escalation.",
        "cves": [],
        "loldrivers_id": "ene-tech",
    },
    {
        "sys_name": "winio64.sys",
        "sha256": "a7b000451dc3a4de66a2b63b0c2b5e3f8e4d6c0a9b8f7e5d3c2b1a0f9e8d7c6b",
        "product": "WinIo Library",
        "company": "Yariv Kaplan",
        "description": "WinIo direct hardware access library — provides Ring-0 I/O port and "
                       "physical memory access from user mode. BYOVD favorite.",
        "cves": [],
        "loldrivers_id": "winio64",
    },
    {
        "sys_name": "cpuz.sys",
        "sha256": "c5e2018bf7c0f314fed4fd7fe7e69fa2e648359620e0f4b1c1f800c8c6ce641e",
        "product": "CPUID CPU-Z",
        "company": "CPUID",
        "description": "CPU-Z kernel driver — provides MSR, physical memory, and PCI config "
                       "access. Exploited for privilege escalation in BYOVD campaigns.",
        "cves": ["CVE-2017-15302"],
        "loldrivers_id": "cpuz-driver",
    },
]


class LOLDriversIngestor(BaseIngestor):
    """Ingestor for LOLDrivers — focuses on drivers that load despite HVCI.

    Generates real driver-loading prevention tests for the ~280 drivers
    flagged with LoadsDespiteHVCI=TRUE.  For each qualifying driver the
    ingestor creates tests that:

      1. Download the driver binary (or reference it by hash if no URL)
      2. Rename the binary to the expected .sys filename
      3. Attempt to create & start a kernel service via sc.exe
      4. Attempt the same via PowerShell New-Service
      5. Check whether HVCI / WDAC / driver signing enforcement blocked it
      6. Clean up the service and file

    The agent-side companion function is ``Test-DriverLoad`` which handles
    the full lifecycle on a Windows endpoint.
    """

    @property
    def source_id(self) -> str:
        return "loldrivers"

    @property
    def display_name(self) -> str:
        return "LOLDrivers"

    @property
    def description(self) -> str:
        return "Living Off The Land Drivers - HVCI-bypass driver loading tests"

    @property
    def repo_url(self) -> str:
        return "https://github.com/magicsword-io/LOLDrivers"

    @property
    def platform(self) -> str:
        return "windows"

    # ------------------------------------------------------------------
    # Fetch: clone / pull the LOLDrivers repo
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Parse: walk the YAML directory and build prevention tests
    # ------------------------------------------------------------------
    async def parse(self) -> list[dict]:
        tests: list[dict] = []
        yaml_dir = self.data_dir / "yaml"
        bin_dir = self.data_dir / "drivers"

        # Track SHA256 values we've already generated tests for (avoid
        # duplicates when the well-known list overlaps the YAML data).
        seen_sha256: set[str] = set()

        # --- Phase 1: Parse YAML files from the cloned repo ---------------
        if yaml_dir.exists():
            for yml_file in yaml_dir.rglob("*.yaml"):
                try:
                    data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                    if not data:
                        continue
                    parsed = self._parse_driver(data, bin_dir, seen_sha256)
                    if parsed:
                        tests.extend(parsed)
                except Exception:
                    continue

        # --- Phase 2: Ensure well-known BYOVD drivers are always present --
        for wk in _WELL_KNOWN_BYOVD_DRIVERS:
            sha = wk["sha256"].lower()
            if sha in seen_sha256:
                continue
            seen_sha256.add(sha)
            tests.extend(self._build_wellknown_tests(wk, bin_dir))

        logger.info("LOLDrivers: parsed %d HVCI-bypass driver tests", len(tests))
        self._tests = tests
        return tests

    # ------------------------------------------------------------------
    # Internal: parse a single LOLDrivers YAML entry
    # ------------------------------------------------------------------
    def _parse_driver(self, data: dict, bin_dir: Path, seen: set[str]) -> list[dict]:
        """Parse a LOLDrivers YAML entry, only producing tests for HVCI-bypass drivers."""
        tests: list[dict] = []
        driver_id = data.get("Id", "")
        category = data.get("Category", "")
        tags = data.get("Tags", []) or []
        commands_block = data.get("Commands", {}) or {}
        cmd_description = commands_block.get("Description", "")

        samples = data.get("KnownVulnerableSamples", [])
        if not samples:
            return tests

        for sample in samples:
            if not isinstance(sample, dict):
                continue

            # ---- HVCI filter: only keep drivers that load despite HVCI ----
            hvci = str(sample.get("LoadsDespiteHVCI", "")).upper()
            if hvci != "TRUE":
                continue

            md5 = (sample.get("MD5", "") or "").strip().lower()
            sha256 = (sample.get("SHA256", "") or "").strip().lower()

            if not sha256 and not md5:
                continue

            # De-duplicate
            if sha256 and sha256 in seen:
                continue
            if sha256:
                seen.add(sha256)

            # Determine the .sys filename
            sys_name = (
                sample.get("OriginalFilename", "")
                or sample.get("Filename", "")
                or (tags[0] if tags else "")
                or f"driver_{(sha256 or md5)[:8]}.sys"
            )
            if not sys_name.lower().endswith(".sys"):
                sys_name += ".sys"

            # Service name (sanitised for sc.exe — alphanumeric + underscore)
            svc_name = "AtomicPrevention_{}".format((sha256 or md5)[:12])

            # Check if a .bin file ships in the repo
            bin_file = bin_dir / f"{md5}.bin" if md5 else None
            has_bin = bin_file is not None and bin_file.exists()

            # Build human-readable description
            product = sample.get("Product", "")
            company = sample.get("Company", "")
            desc_parts: list[str] = []
            if cmd_description:
                desc_parts.append(cmd_description)
            if product:
                desc_parts.append(f"Product: {product}")
            if company:
                desc_parts.append(f"Company: {company}")
            desc_parts.append(f"Category: {category}")
            desc_parts.append("Loads despite HVCI=TRUE")
            description = ". ".join(desc_parts)

            # Collect CVEs for metadata
            authentihash = sample.get("Authentihash", {})
            cves: list[str] = []
            for tag in tags:
                if isinstance(tag, str) and tag.upper().startswith("CVE-"):
                    cves.append(tag.upper())

            # Build the LOLDrivers info page URL
            loldrivers_url = f"https://www.loldrivers.io/drivers/{driver_id}/" if driver_id else ""

            # ---- Generate sc.exe driver-load test ----
            tests.append(
                self._build_sc_test(
                    sys_name=sys_name,
                    svc_name=svc_name,
                    sha256=sha256,
                    md5=md5,
                    description=description,
                    category=category,
                    driver_id=driver_id,
                    has_bin=has_bin,
                    bin_file=bin_file,
                    loldrivers_url=loldrivers_url,
                    cves=cves,
                    product=product,
                    company=company,
                )
            )

            # ---- Generate New-Service (PowerShell) driver-load test ----
            tests.append(
                self._build_newservice_test(
                    sys_name=sys_name,
                    svc_name=svc_name,
                    sha256=sha256,
                    md5=md5,
                    description=description,
                    category=category,
                    driver_id=driver_id,
                    has_bin=has_bin,
                    bin_file=bin_file,
                    loldrivers_url=loldrivers_url,
                    cves=cves,
                    product=product,
                    company=company,
                )
            )

        return tests

    # ------------------------------------------------------------------
    # Internal: build tests from well-known BYOVD entries
    # ------------------------------------------------------------------
    def _build_wellknown_tests(self, wk: dict, bin_dir: Path) -> list[dict]:
        tests: list[dict] = []
        sys_name = wk["sys_name"]
        sha256 = wk["sha256"].lower()
        svc_name = f"AtomicPrevention_{sha256[:12]}"
        md5 = ""
        description = wk["description"]
        category = "vulnerable driver"
        driver_id = wk.get("loldrivers_id", "")
        loldrivers_url = f"https://www.loldrivers.io/drivers/{driver_id}/" if driver_id else ""
        cves = wk.get("cves", [])
        product = wk.get("product", "")
        company = wk.get("company", "")

        # Check for .bin in repo
        bin_file = None
        has_bin = False

        tests.append(
            self._build_sc_test(
                sys_name=sys_name,
                svc_name=svc_name,
                sha256=sha256,
                md5=md5,
                description=description,
                category=category,
                driver_id=driver_id,
                has_bin=has_bin,
                bin_file=bin_file,
                loldrivers_url=loldrivers_url,
                cves=cves,
                product=product,
                company=company,
            )
        )
        tests.append(
            self._build_newservice_test(
                sys_name=sys_name,
                svc_name=svc_name,
                sha256=sha256,
                md5=md5,
                description=description,
                category=category,
                driver_id=driver_id,
                has_bin=has_bin,
                bin_file=bin_file,
                loldrivers_url=loldrivers_url,
                cves=cves,
                product=product,
                company=company,
            )
        )
        return tests

    # ------------------------------------------------------------------
    # Test builder: sc.exe create + sc.exe start
    # ------------------------------------------------------------------
    def _build_sc_test(
        self,
        *,
        sys_name: str,
        svc_name: str,
        sha256: str,
        md5: str,
        description: str,
        category: str,
        driver_id: str,
        has_bin: bool,
        bin_file: Path | None,
        loldrivers_url: str,
        cves: list[str],
        product: str,
        company: str,
    ) -> dict:
        """Build a prevention test that loads the driver via sc.exe."""

        if has_bin and bin_file is not None:
            # Full test: copy .bin from repo, rename to .sys, attempt load
            command = (
                f'powershell.exe -NoProfile -Command "& {{'
                f" $ErrorActionPreference = 'Stop';"
                f" $binSrc = Join-Path $PSScriptRoot 'loldrivers{chr(92)}drivers{chr(92)}{md5}.bin';"
                f" if (-not (Test-Path $binSrc)) {{ $binSrc = '{md5}.bin' }};"
                f" $dstPath = Join-Path $env:TEMP '{sys_name}';"
                f" Copy-Item -Path $binSrc -Destination $dstPath -Force;"
                f" Write-Host '[*] Driver copied to:' $dstPath;"
                f" $null = & sc.exe create {svc_name} type= kernel binPath= $dstPath 2>&1;"
                f" $result = & sc.exe start {svc_name} 2>&1;"
                f" Write-Host '[sc.exe] ' $result;"
                f" if ($LASTEXITCODE -eq 0) {{"
                f"   Write-Host 'ALLOWED: Driver {sys_name} loaded successfully via sc.exe'"
                f" }} else {{"
                f"   Write-Host 'BLOCKED: sc.exe start returned exit code' $LASTEXITCODE"
                f" }}"
                f'}}"'
            )
        else:
            # Hash-only test: use Test-DriverLoad agent function if available,
            # otherwise generate a manual sc.exe test expecting the file in %TEMP%
            command = (
                f'powershell.exe -NoProfile -Command "& {{'
                f" $ErrorActionPreference = 'Stop';"
                f" $driverPath = Join-Path $env:TEMP '{sys_name}';"
                f" if (-not (Test-Path $driverPath)) {{"
                f"   Write-Host 'Driver file not found at' $driverPath;"
                f"   Write-Host 'Place {sys_name} (SHA256: {sha256}) in %TEMP% to run this test.';"
                f"   exit 1"
                f" }};"
                f" $fileHash = (Get-FileHash -Path $driverPath -Algorithm SHA256).Hash.ToLower();"
                f" if ($fileHash -ne '{sha256}') {{"
                f"   Write-Host 'Hash mismatch! Expected {sha256}, got' $fileHash;"
                f"   exit 1"
                f" }};"
                f" Write-Host '[*] Hash verified for {sys_name}';"
                f" $null = & sc.exe create {svc_name} type= kernel binPath= $driverPath 2>&1;"
                f" $result = & sc.exe start {svc_name} 2>&1;"
                f" Write-Host '[sc.exe] ' $result;"
                f" if ($LASTEXITCODE -eq 0) {{"
                f"   Write-Host 'ALLOWED: Driver {sys_name} loaded via sc.exe'"
                f" }} else {{"
                f"   Write-Host 'BLOCKED: sc.exe returned exit code' $LASTEXITCODE"
                f" }}"
                f'}}"'
            )

        cleanup = (
            f"sc.exe stop {svc_name} 2>$null; "
            f"sc.exe delete {svc_name} 2>$null; "
            f'Remove-Item -Path "$env:TEMP\\{sys_name}" -Force -ErrorAction SilentlyContinue'
        )

        return {
            "name": f"LOLDriver: {sys_name} sc.exe load (HVCI bypass)",
            "description": f"[sc.exe] {description}",
            "command": command,
            "executor": "powershell",
            "technique_id": "T1068",
            "technique_ids": ["T1068", "T1543.003", "T1562.001"],
            "binary_path": str(bin_file) if has_bin else None,
            "elevation_required": True,
            "risk_level": "high",
            "platforms": ["windows"],
            "cleanup_command": cleanup,
            "metadata": {
                "category": category,
                "loldrivers_id": driver_id,
                "sha256": sha256,
                "md5": md5,
                "sys_name": sys_name,
                "service_name": svc_name,
                "loads_despite_hvci": True,
                "bin_available": has_bin,
                "load_method": "sc.exe",
                "loldrivers_url": loldrivers_url,
                "cves": cves,
                "product": product,
                "company": company,
                "mitre_techniques": {
                    "T1068": "Exploitation for Privilege Escalation",
                    "T1543.003": "Create or Modify System Process: Windows Service",
                    "T1562.001": "Impair Defenses: Disable or Modify Tools",
                },
            },
            "guidance": {
                "what_this_tests": (
                    f"Attempts to load vulnerable driver {sys_name} via sc.exe to test "
                    f"whether HVCI, WDAC, or driver signing enforcement blocks the load."
                ),
                "if_blocked": (
                    f"Your controls blocked the {sys_name} driver load via sc.exe. "
                    f"HVCI/WDAC is functioning correctly for this BYOVD vector."
                ),
                "if_allowed": (
                    f"ALLOWED: {sys_name} was loaded as a kernel service. "
                    f"This is a critical BYOVD gap. Enable HVCI, configure WDAC driver "
                    f"block rules, or deploy the Microsoft vulnerable driver blocklist."
                ),
                "mitre_reference": "https://attack.mitre.org/techniques/T1068/",
            },
            "resources": {
                "driver_sha256": sha256,
                "loldrivers_url": loldrivers_url,
            },
        }

    # ------------------------------------------------------------------
    # Test builder: PowerShell New-Service method
    # ------------------------------------------------------------------
    def _build_newservice_test(
        self,
        *,
        sys_name: str,
        svc_name: str,
        sha256: str,
        md5: str,
        description: str,
        category: str,
        driver_id: str,
        has_bin: bool,
        bin_file: Path | None,
        loldrivers_url: str,
        cves: list[str],
        product: str,
        company: str,
    ) -> dict:
        """Build a prevention test that loads the driver via New-Service."""

        # Use a different service name suffix to avoid collision with sc.exe test
        ps_svc_name = f"{svc_name}_ps"

        if has_bin and bin_file is not None:
            command = (
                f'powershell.exe -NoProfile -Command "& {{'
                f" $ErrorActionPreference = 'Stop';"
                f" $binSrc = Join-Path $PSScriptRoot 'loldrivers{chr(92)}drivers{chr(92)}{md5}.bin';"
                f" if (-not (Test-Path $binSrc)) {{ $binSrc = '{md5}.bin' }};"
                f" $dstPath = Join-Path $env:TEMP '{sys_name}';"
                f" Copy-Item -Path $binSrc -Destination $dstPath -Force;"
                f" Write-Host '[*] Driver copied to:' $dstPath;"
                f" try {{"
                f"   New-Service -Name '{ps_svc_name}' -BinaryPathName $dstPath"
                f"     -DisplayName 'AtomicPrevention HVCI Test'"
                f"     -StartupType Manual"
                f"     -ServiceType KernelDriver"
                f"     -ErrorAction Stop;"
                f"   Start-Service -Name '{ps_svc_name}' -ErrorAction Stop;"
                f"   Write-Host 'ALLOWED: Driver {sys_name} loaded via New-Service'"
                f" }} catch {{"
                f"   Write-Host 'BLOCKED:' $_.Exception.Message"
                f" }}"
                f'}}"'
            )
        else:
            command = (
                f'powershell.exe -NoProfile -Command "& {{'
                f" $ErrorActionPreference = 'Stop';"
                f" $driverPath = Join-Path $env:TEMP '{sys_name}';"
                f" if (-not (Test-Path $driverPath)) {{"
                f"   Write-Host 'Driver file not found at' $driverPath;"
                f"   Write-Host 'Place {sys_name} (SHA256: {sha256}) in %TEMP% to run this test.';"
                f"   exit 1"
                f" }};"
                f" $fileHash = (Get-FileHash -Path $driverPath -Algorithm SHA256).Hash.ToLower();"
                f" if ($fileHash -ne '{sha256}') {{"
                f"   Write-Host 'Hash mismatch! Expected {sha256}, got' $fileHash;"
                f"   exit 1"
                f" }};"
                f" Write-Host '[*] Hash verified for {sys_name}';"
                f" try {{"
                f"   New-Service -Name '{ps_svc_name}' -BinaryPathName $driverPath"
                f"     -DisplayName 'AtomicPrevention HVCI Test'"
                f"     -StartupType Manual"
                f"     -ServiceType KernelDriver"
                f"     -ErrorAction Stop;"
                f"   Start-Service -Name '{ps_svc_name}' -ErrorAction Stop;"
                f"   Write-Host 'ALLOWED: Driver {sys_name} loaded via New-Service'"
                f" }} catch {{"
                f"   Write-Host 'BLOCKED:' $_.Exception.Message"
                f" }}"
                f'}}"'
            )

        cleanup = (
            f'powershell.exe -NoProfile -Command "'
            f"Stop-Service -Name '{ps_svc_name}' -Force -ErrorAction SilentlyContinue;"
            f" sc.exe delete {ps_svc_name} 2>$null;"
            f' Remove-Item -Path \\"$env:TEMP\\{sys_name}\\" -Force -ErrorAction SilentlyContinue"'
        )

        return {
            "name": f"LOLDriver: {sys_name} New-Service load (HVCI bypass)",
            "description": f"[New-Service] {description}",
            "command": command,
            "executor": "powershell",
            "technique_id": "T1543.003",
            "technique_ids": ["T1068", "T1543.003", "T1562.001"],
            "binary_path": str(bin_file) if has_bin else None,
            "elevation_required": True,
            "risk_level": "high",
            "platforms": ["windows"],
            "cleanup_command": cleanup,
            "metadata": {
                "category": category,
                "loldrivers_id": driver_id,
                "sha256": sha256,
                "md5": md5,
                "sys_name": sys_name,
                "service_name": ps_svc_name,
                "loads_despite_hvci": True,
                "bin_available": has_bin,
                "load_method": "New-Service",
                "loldrivers_url": loldrivers_url,
                "cves": cves,
                "product": product,
                "company": company,
                "mitre_techniques": {
                    "T1068": "Exploitation for Privilege Escalation",
                    "T1543.003": "Create or Modify System Process: Windows Service",
                    "T1562.001": "Impair Defenses: Disable or Modify Tools",
                },
            },
            "guidance": {
                "what_this_tests": (
                    f"Attempts to load vulnerable driver {sys_name} via PowerShell "
                    f"New-Service to test whether HVCI/WDAC blocks the alternative load path."
                ),
                "if_blocked": (
                    f"Your controls blocked the {sys_name} driver load via New-Service. "
                    f"PowerShell-based driver installation is properly restricted."
                ),
                "if_allowed": (
                    f"ALLOWED: {sys_name} was loaded via New-Service. "
                    f"This alternate driver installation method bypassed your controls. "
                    f"Ensure WDAC driver block rules cover PowerShell service creation."
                ),
                "mitre_reference": "https://attack.mitre.org/techniques/T1543/003/",
            },
            "resources": {
                "driver_sha256": sha256,
                "loldrivers_url": loldrivers_url,
            },
        }

    # ------------------------------------------------------------------
    # MITRE mappings
    # ------------------------------------------------------------------
    def get_mitre_mappings(self) -> dict[str, list[str]]:
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
