"""MITRE ATT&CK integration using mitreattack-python.

Fetches techniques, tactics, and adversary groups from the ATT&CK STIX data
and caches locally to avoid repeated downloads.
"""

import json
import logging
from pathlib import Path

from backend.app.core.config import settings

logger = logging.getLogger(__name__)

# ATT&CK tactic kill chain order for playbook ordering (v19+)
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Mapping from pre-v19 tactic names to v19 names for backwards compatibility
_TACTIC_MIGRATION = {
    "defense-evasion": "stealth",
}


class MitreAttackClient:
    """Client for MITRE ATT&CK data access."""

    def __init__(self):
        self._techniques: dict = {}
        self._groups: dict = {}
        self._group_techniques: dict[str, list[str]] = {}
        self._loaded = False

    # Bump this when tactic schema changes to invalidate cached data
    CACHE_VERSION = "v19"

    async def load(self) -> None:
        """Load ATT&CK data. Uses cached file if available, otherwise fetches from STIX."""
        cache_file = settings.mitre_cache_dir / "attack_data.json"

        if cache_file.exists():
            data = json.loads(cache_file.read_text())
            if data.get("cache_version") == self.CACHE_VERSION:
                self._techniques = data.get("techniques", {})
                self._groups = data.get("groups", {})
                self._group_techniques = data.get("group_techniques", {})
                self._loaded = True
                return
            else:
                logger.info("Cache version mismatch, re-fetching ATT&CK data for v19")
                cache_file.unlink()
                stix_path = settings.mitre_cache_dir / "enterprise-attack.json"
                if stix_path.exists():
                    stix_path.unlink()

        await self._fetch_and_cache()

    async def _fetch_and_cache(self) -> None:
        """Fetch ATT&CK data from STIX/TAXII and cache it."""
        try:
            import httpx
            from mitreattack.stix20 import MitreAttackData

            # Download Enterprise ATT&CK STIX JSON from the official MITRE repo
            stix_path = settings.mitre_cache_dir / "enterprise-attack.json"
            if not stix_path.exists():
                stix_url = (
                    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
                    "/master/enterprise-attack/enterprise-attack.json"
                )
                logger.info(f"Downloading MITRE ATT&CK STIX data from {stix_url}")
                async with httpx.AsyncClient(timeout=120.0) as client:
                    resp = await client.get(stix_url)
                    resp.raise_for_status()
                    stix_path.parent.mkdir(parents=True, exist_ok=True)
                    stix_path.write_bytes(resp.content)
                    logger.info(
                        f"Downloaded enterprise-attack.json ({len(resp.content)} bytes)"
                    )

            attack_data = MitreAttackData(str(stix_path))

            # Extract techniques
            techniques = attack_data.get_techniques(remove_revoked_deprecated=True)
            for tech in techniques:
                tech_id = None
                for ref in tech.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id")
                        break

                if not tech_id:
                    continue

                tactics = []
                for phase in tech.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactics.append(phase["phase_name"])

                platforms = tech.get("x_mitre_platforms", [])

                self._techniques[tech_id] = {
                    "id": tech_id,
                    "name": tech.get("name", ""),
                    "description": tech.get("description", "")[:500],
                    "tactics": tactics,
                    "platforms": [p.lower() for p in platforms],
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                }

            # Extract groups
            groups = attack_data.get_groups(remove_revoked_deprecated=True)
            for group in groups:
                group_id = None
                for ref in group.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        group_id = ref.get("external_id")
                        break

                if not group_id:
                    continue

                self._groups[group_id] = {
                    "id": group_id,
                    "name": group.get("name", ""),
                    "description": group.get("description", "")[:500],
                    "aliases": group.get("aliases", []),
                    "url": f"https://attack.mitre.org/groups/{group_id}/",
                }

                # Get techniques used by this group
                tech_ids = []
                try:
                    group_techs = attack_data.get_techniques_used_by_group(group["id"])
                    for item in group_techs:
                        # mitreattack-python returns list of dicts with
                        # {'object': AttackPattern, 'relationships': [...]}
                        obj = item
                        if isinstance(item, dict) and "object" in item:
                            obj = item["object"]
                        elif isinstance(item, (list, tuple)):
                            obj = item[-1] if len(item) > 1 else item[0]

                        # Extract external_id from the STIX object
                        refs = getattr(obj, "external_references", None)
                        if refs is None and hasattr(obj, "get"):
                            refs = obj.get("external_references", [])
                        if not refs:
                            continue
                        for ref in refs:
                            src = getattr(ref, "source_name", None) or (ref.get("source_name") if isinstance(ref, dict) else None)
                            ext_id = getattr(ref, "external_id", None) or (ref.get("external_id") if isinstance(ref, dict) else None)
                            if src == "mitre-attack" and ext_id and ext_id.startswith("T"):
                                tech_ids.append(ext_id)
                except Exception as e:
                    logger.warning(f"Failed to get techniques for group {group_id}: {e}")

                # Merge with hardcoded fallback mappings if available
                if not tech_ids:
                    fallback_techs = self._get_fallback_group_techniques(group_id)
                    if fallback_techs:
                        tech_ids = fallback_techs
                self._group_techniques[group_id] = tech_ids

        except ImportError:
            logger.info("mitreattack-python not installed or unavailable, using fallback dataset")
            await self._load_fallback()
        except Exception as e:
            logger.warning(f"Failed to fetch ATT&CK STIX data, using fallback: {e}")
            await self._load_fallback()

        # Cache the data
        self._save_cache()
        self._loaded = True

    async def _load_fallback(self) -> None:
        """Load a minimal hardcoded dataset for when STIX download fails."""
        # Common LOL-related techniques
        lol_techniques = {
            "T1218": {"id": "T1218", "name": "System Binary Proxy Execution", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries.", "url": "https://attack.mitre.org/techniques/T1218/"},
            "T1218.001": {"id": "T1218.001", "name": "Compiled HTML File", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code.", "url": "https://attack.mitre.org/techniques/T1218/001/"},
            "T1218.002": {"id": "T1218.002", "name": "Control Panel", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may abuse control.exe to proxy execution of malicious payloads.", "url": "https://attack.mitre.org/techniques/T1218/002/"},
            "T1218.003": {"id": "T1218.003", "name": "CMSTP", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may abuse CMSTP to proxy execution of malicious code.", "url": "https://attack.mitre.org/techniques/T1218/003/"},
            "T1218.004": {"id": "T1218.004", "name": "InstallUtil", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility.", "url": "https://attack.mitre.org/techniques/T1218/004/"},
            "T1218.005": {"id": "T1218.005", "name": "Mshta", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript.", "url": "https://attack.mitre.org/techniques/T1218/005/"},
            "T1218.007": {"id": "T1218.007", "name": "Msiexec", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.", "url": "https://attack.mitre.org/techniques/T1218/007/"},
            "T1218.009": {"id": "T1218.009", "name": "Regsvcs/Regasm", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility.", "url": "https://attack.mitre.org/techniques/T1218/009/"},
            "T1218.010": {"id": "T1218.010", "name": "Regsvr32", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code.", "url": "https://attack.mitre.org/techniques/T1218/010/"},
            "T1218.011": {"id": "T1218.011", "name": "Rundll32", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may abuse rundll32.exe to proxy execution of malicious code.", "url": "https://attack.mitre.org/techniques/T1218/011/"},
            "T1218.014": {"id": "T1218.014", "name": "MMC", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may abuse mmc.exe to proxy execution of malicious .msc files.", "url": "https://attack.mitre.org/techniques/T1218/014/"},
            "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.", "url": "https://attack.mitre.org/techniques/T1059/"},
            "T1059.001": {"id": "T1059.001", "name": "PowerShell", "tactics": ["execution"], "platforms": ["windows"], "description": "Adversaries may abuse PowerShell commands and scripts for execution.", "url": "https://attack.mitre.org/techniques/T1059/001/"},
            "T1059.003": {"id": "T1059.003", "name": "Windows Command Shell", "tactics": ["execution"], "platforms": ["windows"], "description": "Adversaries may abuse the Windows command shell for execution.", "url": "https://attack.mitre.org/techniques/T1059/003/"},
            "T1059.005": {"id": "T1059.005", "name": "Visual Basic", "tactics": ["execution"], "platforms": ["windows"], "description": "Adversaries may abuse Visual Basic (VB) for execution.", "url": "https://attack.mitre.org/techniques/T1059/005/"},
            "T1059.007": {"id": "T1059.007", "name": "JavaScript", "tactics": ["execution"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may abuse various implementations of JavaScript for execution.", "url": "https://attack.mitre.org/techniques/T1059/007/"},
            "T1068": {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactics": ["privilege-escalation"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.", "url": "https://attack.mitre.org/techniques/T1068/"},
            "T1219": {"id": "T1219", "name": "Remote Access Software", "tactics": ["command-and-control"], "platforms": ["windows", "linux", "macos"], "description": "An adversary may use legitimate desktop support and remote access software to establish an interactive command and control channel.", "url": "https://attack.mitre.org/techniques/T1219/"},
            "T1543.003": {"id": "T1543.003", "name": "Windows Service", "tactics": ["persistence", "privilege-escalation"], "platforms": ["windows"], "description": "Adversaries may create or modify Windows services to repeatedly execute malicious payloads.", "url": "https://attack.mitre.org/techniques/T1543/003/"},
            "T1105": {"id": "T1105", "name": "Ingress Tool Transfer", "tactics": ["command-and-control"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.", "url": "https://attack.mitre.org/techniques/T1105/"},
            "T1027": {"id": "T1027", "name": "Obfuscated Files or Information", "tactics": ["stealth"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.", "url": "https://attack.mitre.org/techniques/T1027/"},
            "T1036": {"id": "T1036", "name": "Masquerading", "tactics": ["stealth"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.", "url": "https://attack.mitre.org/techniques/T1036/"},
            "T1055": {"id": "T1055", "name": "Process Injection", "tactics": ["stealth", "privilege-escalation"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.", "url": "https://attack.mitre.org/techniques/T1055/"},
            "T1070": {"id": "T1070", "name": "Indicator Removal", "tactics": ["stealth"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence.", "url": "https://attack.mitre.org/techniques/T1070/"},
            "T1003": {"id": "T1003", "name": "OS Credential Dumping", "tactics": ["credential-access"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.", "url": "https://attack.mitre.org/techniques/T1003/"},
            "T1003.001": {"id": "T1003.001", "name": "LSASS Memory", "tactics": ["credential-access"], "platforms": ["windows"], "description": "Adversaries may attempt to access credential material stored in the process memory of the LSASS.", "url": "https://attack.mitre.org/techniques/T1003/001/"},
            "T1047": {"id": "T1047", "name": "Windows Management Instrumentation", "tactics": ["execution"], "platforms": ["windows"], "description": "Adversaries may abuse WMI to execute malicious commands and payloads.", "url": "https://attack.mitre.org/techniques/T1047/"},
            "T1053": {"id": "T1053", "name": "Scheduled Task/Job", "tactics": ["execution", "persistence", "privilege-escalation"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.", "url": "https://attack.mitre.org/techniques/T1053/"},
            "T1082": {"id": "T1082", "name": "System Information Discovery", "tactics": ["discovery"], "platforms": ["windows", "linux", "macos"], "description": "An adversary may attempt to get detailed information about the operating system and hardware.", "url": "https://attack.mitre.org/techniques/T1082/"},
            "T1083": {"id": "T1083", "name": "File and Directory Discovery", "tactics": ["discovery"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may enumerate files and directories or may search in specific locations.", "url": "https://attack.mitre.org/techniques/T1083/"},
            "T1057": {"id": "T1057", "name": "Process Discovery", "tactics": ["discovery"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may attempt to get information about running processes on a system.", "url": "https://attack.mitre.org/techniques/T1057/"},
            "T1202": {"id": "T1202", "name": "Indirect Command Execution", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may abuse utilities that allow for command execution to bypass security restrictions.", "url": "https://attack.mitre.org/techniques/T1202/"},
            "T1140": {"id": "T1140", "name": "Deobfuscate/Decode Files or Information", "tactics": ["stealth"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may use obfuscated files or information to hide artifacts of an intrusion.", "url": "https://attack.mitre.org/techniques/T1140/"},
            "T1564": {"id": "T1564", "name": "Hide Artifacts", "tactics": ["stealth"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may attempt to hide artifacts associated with their behaviors to evade detection.", "url": "https://attack.mitre.org/techniques/T1564/"},
            "T1564.004": {"id": "T1564.004", "name": "NTFS File Attributes", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may use NTFS file attributes to hide their malicious data.", "url": "https://attack.mitre.org/techniques/T1564/004/"},
            "T1574": {"id": "T1574", "name": "Hijack Execution Flow", "tactics": ["stealth", "execution"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs.", "url": "https://attack.mitre.org/techniques/T1574/"},
            "T1127": {"id": "T1127", "name": "Trusted Developer Utilities Proxy Execution", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads.", "url": "https://attack.mitre.org/techniques/T1127/"},
            "T1216": {"id": "T1216", "name": "System Script Proxy Execution", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may use trusted scripts to proxy execution of malicious files.", "url": "https://attack.mitre.org/techniques/T1216/"},
            "T1220": {"id": "T1220", "name": "XSL Script Processing", "tactics": ["stealth"], "platforms": ["windows"], "description": "Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files.", "url": "https://attack.mitre.org/techniques/T1220/"},
            # ClickFix / modern social engineering
            "T1204": {"id": "T1204", "name": "User Execution", "tactics": ["execution"], "platforms": ["windows", "linux", "macos"], "description": "An adversary may rely upon specific actions by a user in order to gain execution.", "url": "https://attack.mitre.org/techniques/T1204/"},
            "T1204.004": {"id": "T1204.004", "name": "Malicious Copy and Paste", "tactics": ["execution"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may rely on users copying and pasting code into a terminal or Run dialog through social engineering (ClickFix, fake CAPTCHA). Users are tricked into executing malicious commands disguised as error fixes or verification steps.", "url": "https://attack.mitre.org/techniques/T1204/004/"},
            # Additional techniques used by new groups
            "T1685": {"id": "T1685", "name": "Disable or Modify Tools", "tactics": ["defense-impairment"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may modify and/or disable security tools to avoid detection.", "url": "https://attack.mitre.org/techniques/T1685/"},
            "T1685.001": {"id": "T1685.001", "name": "Disable or Modify Windows Event Log", "tactics": ["defense-impairment"], "platforms": ["windows"], "description": "Adversaries may disable or modify Windows event logging to limit forensic evidence.", "url": "https://attack.mitre.org/techniques/T1685/001/"},
            "T1686": {"id": "T1686", "name": "Disable or Modify System Firewall", "tactics": ["defense-impairment"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may disable or modify system firewalls to bypass network-based controls.", "url": "https://attack.mitre.org/techniques/T1686/"},
            "T1486": {"id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["impact"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may encrypt data on target systems or on large numbers of systems in order to interrupt availability.", "url": "https://attack.mitre.org/techniques/T1486/"},
            "T1490": {"id": "T1490", "name": "Inhibit System Recovery", "tactics": ["impact"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may delete or remove built-in data recovery mechanisms.", "url": "https://attack.mitre.org/techniques/T1490/"},
            "T1078": {"id": "T1078", "name": "Valid Accounts", "tactics": ["stealth", "persistence", "privilege-escalation", "initial-access"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may obtain and abuse credentials of existing accounts.", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1190": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["initial-access"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may attempt to exploit weaknesses in internet-facing hosts.", "url": "https://attack.mitre.org/techniques/T1190/"},
            "T1133": {"id": "T1133", "name": "External Remote Services", "tactics": ["persistence", "initial-access"], "platforms": ["windows", "linux", "macos"], "description": "Adversaries may use external remote services such as VPNs and RDP to persist.", "url": "https://attack.mitre.org/techniques/T1133/"},
        }
        self._techniques = lol_techniques

        # Common adversary groups that use LOL techniques
        self._groups = {
            "G0016": {"id": "G0016", "name": "APT29", "description": "APT29 is a threat group attributed to Russia's Foreign Intelligence Service (SVR).", "aliases": ["Cozy Bear", "YTTRIUM", "The Dukes", "Midnight Blizzard"], "url": "https://attack.mitre.org/groups/G0016/"},
            "G0007": {"id": "G0007", "name": "APT28", "description": "APT28 is a threat group attributed to Russia's General Staff Main Intelligence Directorate (GRU).", "aliases": ["Fancy Bear", "STRONTIUM", "Forest Blizzard"], "url": "https://attack.mitre.org/groups/G0007/"},
            "G0032": {"id": "G0032", "name": "Lazarus Group", "description": "Lazarus Group is a North Korean state-sponsored cyber threat group.", "aliases": ["HIDDEN COBRA", "Guardians of Peace", "Diamond Sleet"], "url": "https://attack.mitre.org/groups/G0032/"},
            "G0050": {"id": "G0050", "name": "APT32", "description": "APT32 is a suspected Vietnam-based threat group.", "aliases": ["OceanLotus", "Canvas Cyclone"], "url": "https://attack.mitre.org/groups/G0050/"},
            "G0045": {"id": "G0045", "name": "menuPass", "description": "menuPass is a threat group attributed to China.", "aliases": ["APT10", "Stone Panda", "Red Apollo"], "url": "https://attack.mitre.org/groups/G0045/"},
            "G0074": {"id": "G0074", "name": "Dragonfly 2.0", "description": "Dragonfly 2.0 targets energy sector organizations.", "aliases": ["Berserk Bear", "Energetic Bear"], "url": "https://attack.mitre.org/groups/G0074/"},
            "G0010": {"id": "G0010", "name": "Turla", "description": "Turla is a Russian-based threat group that has infected victims in over 45 countries.", "aliases": ["Snake", "Venomous Bear", "Secret Blizzard"], "url": "https://attack.mitre.org/groups/G0010/"},
            "G0022": {"id": "G0022", "name": "APT3", "description": "APT3 is a China-based threat group attributed to the Ministry of State Security.", "aliases": ["Gothic Panda", "UPS Team"], "url": "https://attack.mitre.org/groups/G0022/"},
            "G0027": {"id": "G0027", "name": "Threat Group-3390", "description": "Threat Group-3390 is a Chinese threat group.", "aliases": ["TG-3390", "Emissary Panda", "APT27"], "url": "https://attack.mitre.org/groups/G0027/"},
            "G0096": {"id": "G0096", "name": "APT41", "description": "APT41 is a threat group attributed to China that carries out state-sponsored espionage and financially motivated activity.", "aliases": ["Double Dragon", "Brass Typhoon"], "url": "https://attack.mitre.org/groups/G0096/"},
            "G0114": {"id": "G0114", "name": "Chimera", "description": "Chimera is a suspected China-based threat group.", "aliases": [], "url": "https://attack.mitre.org/groups/G0114/"},
            "G0102": {"id": "G0102", "name": "Wizard Spider", "description": "Wizard Spider is a Russia-based financially motivated threat group.", "aliases": ["Gold Blackburn"], "url": "https://attack.mitre.org/groups/G0102/"},
            "G0060": {"id": "G0060", "name": "BRONZE BUTLER", "description": "BRONZE BUTLER is a cyber espionage group attributed to the People's Republic of China.", "aliases": ["REDBALDKNIGHT", "Tick"], "url": "https://attack.mitre.org/groups/G0060/"},
            "G0065": {"id": "G0065", "name": "Leviathan", "description": "Leviathan is a Chinese state-sponsored cyber espionage group.", "aliases": ["APT40", "TEMP.Periscope", "Kryptonite Panda"], "url": "https://attack.mitre.org/groups/G0065/"},
            "G0094": {"id": "G0094", "name": "Kimsuky", "description": "Kimsuky is a North Korea-based cyber espionage group.", "aliases": ["Velvet Chollima", "Emerald Sleet"], "url": "https://attack.mitre.org/groups/G0094/"},
            # === New high-profile groups ===
            "G1017": {"id": "G1017", "name": "Volt Typhoon", "description": "Volt Typhoon is a Chinese state-sponsored group targeting critical infrastructure using extensive living-off-the-land techniques to maintain stealth.", "aliases": ["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391", "Voltzite", "Insidious Taurus"], "url": "https://attack.mitre.org/groups/G1017/"},
            "G1015": {"id": "G1015", "name": "Scattered Spider", "description": "Scattered Spider is a cybercriminal group known for social engineering, SIM swapping, helpdesk impersonation, and MFA bypass for ransomware and data extortion.", "aliases": ["Roasted 0ktapus", "Octo Tempest", "Storm-0875", "UNC3944"], "url": "https://attack.mitre.org/groups/G1015/"},
            "G0046": {"id": "G0046", "name": "FIN7", "description": "FIN7 is a financially motivated group targeting retail, hospitality, and financial services through spear-phishing, POS malware, and ransomware.", "aliases": ["GOLD NIAGARA", "Carbon Spider", "ELBRUS", "Sangria Tempest"], "url": "https://attack.mitre.org/groups/G0046/"},
            "G0034": {"id": "G0034", "name": "Sandworm Team", "description": "Sandworm Team is a Russian GRU Unit 74455 destructive threat group responsible for NotPetya, Ukrainian power grid attacks, and Olympic Destroyer.", "aliases": ["ELECTRUM", "Telebots", "IRON VIKING", "Voodoo Bear", "Seashell Blizzard", "APT44"], "url": "https://attack.mitre.org/groups/G0034/"},
            "G0129": {"id": "G0129", "name": "Mustang Panda", "description": "Mustang Panda is a China-based APT targeting government organizations and NGOs through spear-phishing with trojanized documents.", "aliases": ["TA416", "RedDelta", "BRONZE PRESIDENT", "STATELY TAURUS", "CAMARO DRAGON", "EARTH PRETA", "TWILL TYPHOON"], "url": "https://attack.mitre.org/groups/G0129/"},
            "G1033": {"id": "G1033", "name": "Star Blizzard", "description": "Star Blizzard is a Russian FSB-attributed group conducting spear-phishing for credential harvesting against NATO government officials and defense organizations.", "aliases": ["SEABORGIUM", "Callisto Group", "TA446", "COLDRIVER"], "url": "https://attack.mitre.org/groups/G1033/"},
            "G0047": {"id": "G0047", "name": "Gamaredon Group", "description": "Gamaredon is a Russian FSB-attributed group aggressively targeting Ukrainian government and military organizations with custom malware.", "aliases": ["IRON TILDEN", "Primitive Bear", "ACTINIUM", "Armageddon", "Shuckworm", "Aqua Blizzard"], "url": "https://attack.mitre.org/groups/G0047/"},
            "G1046": {"id": "G1046", "name": "Black Basta", "description": "Black Basta (Storm-1811) is a ransomware group using email bombing, vishing, and social engineering for initial access before double extortion.", "aliases": ["Storm-1811"], "url": "https://attack.mitre.org/groups/G1046/"},
            "MA-ALPHV": {"id": "MA-ALPHV", "name": "ALPHV/BlackCat", "description": "ALPHV (BlackCat) is a sophisticated Ransomware-as-a-Service operation using Rust-based ransomware and double extortion tactics targeting healthcare and critical infrastructure.", "aliases": ["ALPHV", "BlackCat", "Noberus"], "url": "https://attack.mitre.org/software/S1068/"},
            "MA-LOCKBIT": {"id": "MA-LOCKBIT", "name": "LockBit", "description": "LockBit is the most prolific Ransomware-as-a-Service platform (2022-2024) known for rapid encryption, automated propagation via Group Policy, and extensive affiliate network.", "aliases": ["LockBit 3.0", "LockBit 2.0", "LockBit Black"], "url": "https://attack.mitre.org/software/S1202/"},
        }

        # Map adversary groups to their commonly used LOL techniques
        self._group_techniques = {
            "G0016": ["T1059.001", "T1059.003", "T1218.011", "T1218.005", "T1105", "T1027", "T1036", "T1055", "T1082", "T1083", "T1057", "T1003.001", "T1047", "T1053"],
            "G0007": ["T1059.001", "T1059.003", "T1059.005", "T1218.011", "T1105", "T1027", "T1036", "T1082", "T1083", "T1053", "T1047"],
            "G0032": ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1218.010", "T1218.011", "T1105", "T1027", "T1036", "T1055", "T1082", "T1053"],
            "G0050": ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1218.010", "T1218.011", "T1218.007", "T1105", "T1027", "T1036"],
            "G0045": ["T1059.001", "T1059.003", "T1218.011", "T1105", "T1027", "T1053", "T1082", "T1083"],
            "G0074": ["T1059.001", "T1059.003", "T1218.011", "T1105", "T1082", "T1083", "T1057"],
            "G0010": ["T1059.001", "T1059.003", "T1059.005", "T1218.011", "T1105", "T1027", "T1055", "T1082", "T1083"],
            "G0022": ["T1059.001", "T1059.003", "T1218.011", "T1218.010", "T1105", "T1082"],
            "G0027": ["T1059.001", "T1059.003", "T1218.011", "T1218.005", "T1105", "T1027", "T1053", "T1082"],
            "G0096": ["T1059.001", "T1059.003", "T1059.007", "T1218.005", "T1218.010", "T1218.011", "T1105", "T1027", "T1036", "T1055", "T1053"],
            "G0114": ["T1059.001", "T1059.003", "T1218.011", "T1105", "T1003.001", "T1082", "T1083"],
            "G0102": ["T1059.001", "T1059.003", "T1218.011", "T1105", "T1027", "T1055", "T1053"],
            "G0060": ["T1059.001", "T1059.003", "T1218.011", "T1105", "T1027", "T1082"],
            "G0065": ["T1059.001", "T1059.003", "T1059.007", "T1218.005", "T1218.011", "T1105", "T1027", "T1082"],
            "G0094": ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1105", "T1027", "T1082"],
            # === New groups ===
            "G1017": ["T1059.001", "T1059.003", "T1105", "T1027", "T1036", "T1055", "T1068", "T1047", "T1082", "T1083", "T1003.001", "T1003", "T1543.003", "T1053", "T1218", "T1140", "T1070", "T1564", "T1685", "T1078", "T1190", "T1133"],
            "G1015": ["T1059.001", "T1105", "T1068", "T1219", "T1047", "T1082", "T1083", "T1003", "T1078", "T1190", "T1133", "T1486", "T1685"],
            "G0046": ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1218.007", "T1218.011", "T1105", "T1027", "T1036", "T1055", "T1053", "T1068", "T1219", "T1543.003", "T1047", "T1082", "T1083", "T1003.001", "T1003"],
            "G0034": ["T1059.001", "T1059.003", "T1059.005", "T1218.011", "T1105", "T1027", "T1036", "T1055", "T1053", "T1068", "T1219", "T1543.003", "T1047", "T1082", "T1083", "T1003.001", "T1003"],
            "G0129": ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1218.007", "T1218.014", "T1105", "T1027", "T1036", "T1055", "T1053", "T1068", "T1219", "T1543.003", "T1047", "T1082", "T1083", "T1003.001", "T1003"],
            "G1033": ["T1059.007", "T1078", "T1204", "T1082"],
            "G0047": ["T1059.001", "T1059.003", "T1059.005", "T1218.005", "T1218.011", "T1105", "T1027", "T1036", "T1055", "T1053", "T1047", "T1082", "T1083", "T1140", "T1204"],
            "G1046": ["T1059.001", "T1059.003", "T1105", "T1027", "T1036", "T1068", "T1219", "T1543.003", "T1047", "T1082", "T1083", "T1486", "T1490", "T1685", "T1574", "T1204.004"],
            "MA-ALPHV": ["T1059.003", "T1047", "T1082", "T1083", "T1486", "T1490", "T1685", "T1003", "T1078"],
            "MA-LOCKBIT": ["T1059.001", "T1059.003", "T1218.003", "T1105", "T1027", "T1053", "T1068", "T1219", "T1543.003", "T1047", "T1082", "T1083", "T1003.001", "T1003", "T1486", "T1490", "T1685", "T1078", "T1190", "T1133"],
        }

        self._loaded = True

    def _get_fallback_group_techniques(self, group_id: str) -> list[str]:
        """Return hardcoded technique mappings for key groups as fallback."""
        _FALLBACK = {
            "G0016": ["T1059.001", "T1059.003", "T1218.011", "T1218.005", "T1105", "T1027", "T1036", "T1055", "T1082", "T1083", "T1057", "T1003.001", "T1047", "T1053"],
            "G0007": ["T1059.001", "T1059.003", "T1059.005", "T1218.011", "T1105", "T1027", "T1036", "T1082", "T1083", "T1053", "T1047"],
            "G0032": ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1218.010", "T1218.011", "T1105", "T1027", "T1036", "T1055", "T1082", "T1053"],
            "G0050": ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1218.010", "T1218.011", "T1218.007", "T1105", "T1027", "T1036"],
            "G0045": ["T1059.001", "T1059.003", "T1218.011", "T1105", "T1027", "T1053", "T1082", "T1083"],
            "G0074": ["T1059.001", "T1059.003", "T1218.011", "T1105", "T1082", "T1083", "T1057"],
            "G0010": ["T1059.001", "T1059.003", "T1059.005", "T1218.011", "T1105", "T1027", "T1055", "T1082", "T1083"],
            "G0022": ["T1059.001", "T1059.003", "T1218.011", "T1218.010", "T1105", "T1082"],
            "G0027": ["T1059.001", "T1059.003", "T1218.011", "T1218.005", "T1105", "T1027", "T1053", "T1082"],
            "G0096": ["T1059.001", "T1059.003", "T1059.007", "T1218.005", "T1218.010", "T1218.011", "T1105", "T1027", "T1036", "T1055", "T1053"],
            "G0114": ["T1059.001", "T1059.003", "T1218.011", "T1105", "T1003.001", "T1082", "T1083"],
            "G0102": ["T1059.001", "T1059.003", "T1218.011", "T1105", "T1027", "T1055", "T1053"],
            "G0060": ["T1059.001", "T1059.003", "T1218.011", "T1105", "T1027", "T1082"],
            "G0065": ["T1059.001", "T1059.003", "T1059.007", "T1218.005", "T1218.011", "T1105", "T1027", "T1082"],
            "G0094": ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1105", "T1027", "T1082"],
            "G1017": ["T1059.001", "T1059.003", "T1105", "T1027", "T1036", "T1055", "T1068", "T1047", "T1082", "T1083", "T1003.001", "T1543.003", "T1053", "T1218", "T1140", "T1078", "T1190", "T1133"],
            "G1015": ["T1059.001", "T1105", "T1068", "T1219", "T1047", "T1082", "T1083", "T1003", "T1078", "T1190", "T1486", "T1685"],
            "G0046": ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1218.007", "T1218.011", "T1105", "T1027", "T1036", "T1055", "T1053", "T1068", "T1219", "T1543.003", "T1047", "T1082", "T1083", "T1003.001"],
            "G0034": ["T1059.001", "T1059.003", "T1059.005", "T1218.011", "T1105", "T1027", "T1036", "T1055", "T1053", "T1068", "T1219", "T1543.003", "T1047", "T1082", "T1083", "T1003.001"],
            "G0129": ["T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1218.005", "T1218.007", "T1105", "T1027", "T1036", "T1055", "T1053", "T1068", "T1219", "T1543.003", "T1047", "T1082", "T1083", "T1003.001"],
            "G1033": ["T1059.007", "T1078", "T1204", "T1082"],
            "G0047": ["T1059.001", "T1059.003", "T1059.005", "T1218.005", "T1218.011", "T1105", "T1027", "T1036", "T1055", "T1053", "T1047", "T1082", "T1083", "T1140"],
            "G1046": ["T1059.001", "T1059.003", "T1105", "T1027", "T1036", "T1068", "T1219", "T1543.003", "T1047", "T1082", "T1083", "T1486", "T1490", "T1685", "T1204.004"],
            "MA-ALPHV": ["T1059.003", "T1047", "T1082", "T1083", "T1486", "T1490", "T1685", "T1003", "T1078"],
            "MA-LOCKBIT": ["T1059.001", "T1059.003", "T1218.003", "T1105", "T1027", "T1053", "T1068", "T1219", "T1543.003", "T1047", "T1082", "T1083", "T1003.001", "T1486", "T1490", "T1685", "T1078", "T1190"],
        }
        return _FALLBACK.get(group_id, [])

    def _save_cache(self) -> None:
        settings.mitre_cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = settings.mitre_cache_dir / "attack_data.json"
        cache_file.write_text(json.dumps({
            "cache_version": self.CACHE_VERSION,
            "techniques": self._techniques,
            "groups": self._groups,
            "group_techniques": self._group_techniques,
        }, indent=2))

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def get_technique(self, technique_id: str) -> dict | None:
        return self._techniques.get(technique_id)

    def get_all_techniques(self) -> list[dict]:
        return list(self._techniques.values())

    def get_group(self, group_id: str) -> dict | None:
        return self._groups.get(group_id)

    def get_all_groups(self) -> list[dict]:
        return list(self._groups.values())

    def get_group_techniques(self, group_id: str) -> list[str]:
        return self._group_techniques.get(group_id, [])

    def get_tactic_order(self, technique_id: str) -> int:
        """Return the kill chain order index for a technique (for playbook sorting)."""
        tech = self._techniques.get(technique_id)
        if not tech:
            return 999
        tactics = tech.get("tactics", [])
        if not tactics:
            return 999
        def _order(t: str) -> int:
            if t in TACTIC_ORDER:
                return TACTIC_ORDER.index(t)
            migrated = _TACTIC_MIGRATION.get(t)
            if migrated and migrated in TACTIC_ORDER:
                return TACTIC_ORDER.index(migrated)
            return 999
        return min(_order(t) for t in tactics)


# Singleton
_client: MitreAttackClient | None = None


async def get_mitre_client() -> MitreAttackClient:
    global _client
    if _client is None or not _client.is_loaded:
        _client = MitreAttackClient()
        await _client.load()
    return _client
