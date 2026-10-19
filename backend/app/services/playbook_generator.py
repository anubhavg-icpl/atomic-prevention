import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.mitre import get_mitre_client, TACTIC_ORDER
from backend.app.models.adversary import AdversaryGroup
from backend.app.models.playbook import Playbook
from backend.app.models.technique import Technique
from backend.app.models.test_case import PreventionTest


def _sanitize_url(url: str) -> str | None:
    """Validate and sanitize a URL for safe use in PowerShell commands."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None
        # Reject characters that could break PowerShell string literals
        if re.search(r"['\";`$(){}\[\]]", url):
            return None
        return url
    except Exception:
        return None


class PlaybookGenerator:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate(
        self,
        adversary_group_id: str | None = None,
        adversary_group_name: str | None = None,
        technique_ids: list[str] | None = None,
        name: str | None = None,
        platforms: list[str] | None = None,
        custom_payloads: list[dict] | None = None,
    ) -> Playbook | None:
        """Generate a playbook from adversary group or technique list."""
        mitre = await get_mitre_client()
        group_name = adversary_group_name
        group_id = adversary_group_id

        # Resolve techniques from adversary group
        if adversary_group_id and not technique_ids:
            technique_ids = mitre.get_group_techniques(adversary_group_id)
            group = mitre.get_group(adversary_group_id)
            if group:
                group_name = group.get("name", group_name)

        # If we have a group name but no ID, try to find it
        if adversary_group_name and not adversary_group_id:
            result = await self.db.execute(
                select(AdversaryGroup).where(
                    AdversaryGroup.name.ilike(f"%{adversary_group_name}%")
                )
            )
            group = result.scalar_one_or_none()
            if group:
                group_id = group.id
                technique_ids = group.technique_ids or []

        if not technique_ids:
            return None

        # Also include parent techniques (T1059 for T1059.001)
        expanded_ids = set(technique_ids)
        for tid in technique_ids:
            if "." in tid:
                expanded_ids.add(tid.split(".")[0])

        # Find matching tests
        query = select(PreventionTest).where(
            PreventionTest.technique_id.in_(list(expanded_ids))
        )
        result = await self.db.execute(query)
        tests = result.scalars().all()

        # Catalog-only tests may require operator inputs, interactive package
        # installation, or assets that Atomic Prevention cannot acquire safely.
        # Never put those into a default executable playbook.
        tests = [
            test for test in tests
            if (test.metadata_ or {}).get("runnable", True)
        ]

        # Filter by platform if specified
        if platforms:
            tests = [
                t for t in tests
                if any(p in (t.platforms or []) for p in platforms)
            ]

        if not tests:
            return None

        # Sort tests by kill chain order
        tests.sort(key=lambda t: mitre.get_tactic_order(t.technique_id))

        # Build playbook name
        if not name:
            if group_name:
                name = f"{group_name} Prevention Playbook"
            else:
                name = f"Custom Prevention Playbook ({len(tests)} tests)"

        # Store custom payloads in metadata for export
        custom_payload_data = custom_payloads or []

        # Create the playbook
        playbook = Playbook(
            id=str(uuid.uuid4()),
            name=name,
            description=f"Prevention validation playbook with {len(tests)} tests across {len(set(t.technique_id for t in tests))} techniques.",
            adversary_group_id=group_id,
            adversary_group_name=group_name,
            technique_ids=list(set(t.technique_id for t in tests)),
            test_ids=[t.id for t in tests],
            metadata_={
                "platforms": platforms or [],
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "custom_payloads": custom_payload_data,
            },
            created_at=datetime.now(timezone.utc),
        )

        self.db.add(playbook)
        await self.db.commit()
        await self.db.refresh(playbook)

        return playbook

    async def export_for_agent(self, playbook_id: str) -> dict | None:
        """Export playbook as JSON suitable for the PowerShell agent."""
        result = await self.db.execute(
            select(Playbook).where(Playbook.id == playbook_id)
        )
        playbook = result.scalar_one_or_none()
        if not playbook:
            return None

        # Fetch all tests
        test_ids = playbook.test_ids or []
        if not test_ids:
            return None

        tests_result = await self.db.execute(
            select(PreventionTest).where(PreventionTest.id.in_(test_ids))
        )
        tests = tests_result.scalars().all()

        mitre = await get_mitre_client()
        tests.sort(key=lambda t: mitre.get_tactic_order(t.technique_id))

        # Build rich test entries with guidance, downloads, and context
        enriched_tests = []
        for t in tests:
            tech_info = mitre.get_technique(t.technique_id) or {}
            meta = t.metadata_ or {}

            test_entry = {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "technique_id": t.technique_id,
                "technique_name": tech_info.get("name", ""),
                "technique_url": tech_info.get("url", ""),
                "tactic": tech_info.get("tactics", []),
                "source": t.source,
                "command": t.command,
                "executor": t.executor,
                "cleanup_command": t.cleanup_command,
                "elevation_required": t.elevation_required,
                "risk_level": t.risk_level,
                "platforms": t.platforms or [],
                "binary_path": t.binary_path,
                "prerequisites": meta.get("prerequisites", []),
                "runnable": meta.get("runnable", True),
                # Guidance: what this test does and what a block means
                "guidance": {
                    "what_this_tests": self._build_test_explanation(t, tech_info),
                    "if_blocked": "Your preventative controls successfully stopped this technique. This is the desired outcome.",
                    "if_allowed": self._build_remediation(t, tech_info),
                    "mitre_reference": tech_info.get("url", ""),
                },
            }

            # Add download/resource links based on source
            if t.source == "loldrivers":
                sha256 = meta.get("sha256", "")
                if sha256:
                    test_entry["resources"] = {
                        "driver_sha256": sha256,
                        "loldrivers_url": f"https://www.loldrivers.io/drivers/{sha256[:12]}/",
                        "download_note": "The agent will attempt to locate or download the driver sample for testing.",
                    }
            elif t.source == "lolbas":
                test_entry["resources"] = {
                    "lolbas_url": f"https://lolbas-project.github.io/lolbas/{meta.get('source_file', '')}/",
                    "category": meta.get("category", ""),
                }
            elif t.source == "atomic-red-team":
                guid = meta.get("auto_generated_guid", "")
                test_entry["resources"] = {
                    "atomic_guid": guid,
                    "atomic_url": f"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{t.technique_id}/{t.technique_id}.md",
                }
            elif t.source == "lolrmm":
                test_entry["resources"] = {
                    "rmm_tool": meta.get("rmm_tool", ""),
                    "website": meta.get("website", ""),
                }
            elif t.source == "loas":
                loas_guid = meta.get("guid", "")
                exec_mode = meta.get("execution_mode", "osascript")
                test_entry["resources"] = {
                    "loas_guid": loas_guid,
                    "loas_url": "https://github.com/cyberbuff/loas",
                    "loas_docs": f"https://loas.dev",
                    "execution_mode": exec_mode,
                    "language": meta.get("language", "AppleScript"),
                    "tcc_required": meta.get("tcc_required", False),
                    "security_controls_tested": meta.get("security_controls_tested", ""),
                    "references": meta.get("references", []),
                }

            enriched_tests.append(test_entry)

        # Add custom payloads from metadata
        custom_payloads = (playbook.metadata_ or {}).get("custom_payloads", [])
        for i, cp in enumerate(custom_payloads):
            url = cp.get("url", "")
            cmd = cp.get("command", "")
            cp_name = cp.get("name", f"Custom Payload {i+1}")
            executor = cp.get("executor", "powershell")
            technique_id = cp.get("technique_id", "T0000")

            if url and not cmd:
                safe_url = _sanitize_url(url)
                if not safe_url:
                    continue  # skip unsafe URLs
                filename = safe_url.split("/")[-1] or "payload.exe"
                cmd = f'powershell.exe -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $p = Join-Path $env:TEMP \'{filename}\'; Invoke-WebRequest -Uri \'{safe_url}\' -OutFile $p; Start-Process -FilePath $p -PassThru"'
                executor = "powershell"

            if cmd:
                enriched_tests.append({
                    "id": f"custom-{i}",
                    "name": cp_name,
                    "description": f"Custom payload: {url or cmd[:100]}",
                    "technique_id": technique_id,
                    "technique_name": "Custom Test",
                    "technique_url": "",
                    "tactic": ["custom"],
                    "source": "custom",
                    "command": cmd,
                    "executor": executor,
                    "cleanup_command": None,
                    "elevation_required": False,
                    "risk_level": "high",
                    "platforms": ["windows"],
                    "binary_path": None,
                    "guidance": {
                        "what_this_tests": f"Tests whether your controls block this custom payload: {cp_name}",
                        "if_blocked": "Your controls blocked the custom payload.",
                        "if_allowed": f"ALLOWED: Custom payload '{cp_name}' was not blocked. Review your application control policies.",
                        "mitre_reference": "",
                    },
                    "resources": {
                        "payload_url": url,
                        "custom": True,
                    },
                })

        return {
            "atomic_prevention_version": "0.1.0",
            "playbook": {
                "id": playbook.id,
                "name": playbook.name,
                "description": playbook.description,
                "adversary_group": playbook.adversary_group_name,
                "adversary_group_id": playbook.adversary_group_id,
                "created_at": playbook.created_at.isoformat() if playbook.created_at else None,
                "total_tests": len(enriched_tests),
                "total_techniques": len(set(t.technique_id for t in tests)),
            },
            "tests": enriched_tests,
            "config": {
                "timeout_seconds": 5,
                "prerequisite_timeout_seconds": 120,
                "results_endpoint": "/api/results/submit",
                "auto_download_resources": True,
            },
        }

    def _build_test_explanation(self, test: PreventionTest, tech_info: dict) -> str:
        """Build a human-readable explanation of what this test validates."""
        source = test.source
        technique_name = tech_info.get("name", test.technique_id)
        tactics = tech_info.get("tactics", [])
        tactic_str = ", ".join(tactics) if tactics else "unknown tactic"

        explanations = {
            "lolbas": f"Tests whether the system prevents {technique_name} via a living-off-the-land binary. This binary ships with Windows and can be abused for {tactic_str}. Your application control or EDR should block unauthorized use.",
            "loldrivers": f"Tests whether the system prevents loading a known vulnerable or malicious driver ({technique_name}). Driver-level attacks can bypass most security controls. WDAC/HVCI driver block rules should prevent this.",
            "lolrmm": f"Tests whether the system prevents execution of a Remote Monitoring and Management tool. Adversaries abuse legitimate RMM tools for {tactic_str}. Application control policies should restrict unauthorized RMM software.",
            "atomic-red-team": f"Atomic Red Team test for {technique_name} ({tactic_str}). This executes a known adversary technique to verify your endpoint controls block it.",
            "loas": f"LOAS (Living Off Apple Systems) test for {technique_name} ({tactic_str}). Executes a macOS-specific offensive technique using AppleScript/JXA to validate whether macOS security controls (TCC, Gatekeeper, XProtect, Endpoint Security) prevent it.",
        }
        return explanations.get(source, f"Tests prevention of {technique_name} ({tactic_str}).")

    def _build_remediation(self, test: PreventionTest, tech_info: dict) -> str:
        """Build remediation guidance when a test is not blocked."""
        source = test.source
        technique_name = tech_info.get("name", test.technique_id)

        remediations = {
            "lolbas": f"ALLOWED: {technique_name} was not blocked. Consider adding an application control rule (AppLocker/WDAC) to restrict this binary. Review your policy for gaps in LOL binary coverage.",
            "loldrivers": f"ALLOWED: The vulnerable driver was loaded successfully. Enable HVCI (Hypervisor-Protected Code Integrity) and add this driver hash to your WDAC driver block list. See https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules",
            "lolrmm": f"ALLOWED: The RMM tool was accessible. Add this application to your block list in your application control policy. Consider network-level controls to block RMM tool communications.",
            "atomic-red-team": f"ALLOWED: {technique_name} was not prevented. Review the MITRE ATT&CK page for mitigation recommendations: {tech_info.get('url', '')}",
            "loas": f"ALLOWED: {technique_name} was not prevented by macOS security controls. Review: (1) TCC/Privacy settings in System Settings > Privacy & Security, (2) Gatekeeper status via 'spctl --status', (3) Endpoint Security framework configuration, (4) Consider restricting osascript and AppleScript execution via MDM profiles or endpoint security policies. See https://loas.dev for technique details.",
        }
        return remediations.get(source, f"ALLOWED: {technique_name} was not blocked. Review your endpoint prevention policies.")
