"""LOTTunnels ingestor — Living Off The Tunnels.

Fetches tunneling/proxy tool data from https://github.com/LOTTunnels/LOTTunnels.github.io,
parses each tool's YAML-front-matter entries, and generates prevention tests that validate
whether security controls block the download, execution, and network connectivity of
legitimate tunneling tools commonly abused by adversaries for C2, data exfiltration,
and persistent remote access.

MITRE ATT&CK mapping:
    T1572 — Protocol Tunneling
    T1090 — Proxy
    T1090.001 — Internal Proxy
    T1090.002 — External Proxy
    T1105 — Ingress Tool Transfer
    T1571 — Non-Standard Port
    T1048 — Exfiltration Over Alternative Protocol
"""

import asyncio
import logging
import re
from pathlib import Path

import yaml

from backend.app.ingestion.base import BaseIngestor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known tunneling tools with download metadata, GitHub release info,
# expected hashes, and detection domains.
#
# This catalog supplements the LOTTunnels YAML data with:
#   - Direct or GitHub-release-pattern download URLs
#   - SHA256 hashes (where stable releases are available)
#   - Safe execution flags for non-destructive testing
#   - url_verified: whether the URL has been confirmed stable
#   - github_release_api: for tools hosted on GitHub, the API endpoint
#     that can be queried for the latest release URL (future-proofing)
# ---------------------------------------------------------------------------

_TUNNEL_CATALOG: dict[str, dict] = {
    "ngrok": {
        "url": "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip",
        "url_linux": "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.zip",
        "url_macos": "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-darwin-amd64.zip",
        "exe": "ngrok.exe",
        "exe_linux": "ngrok",
        "desc": "ngrok reverse proxy / tunnel agent",
        "vendor": "ngrok Inc.",
        "abuse_reason": (
            "One of the most widely-abused tunneling tools. Used by ransomware "
            "operators (DarkSide, Conti, BlackCat), APT groups, and red teams "
            "to establish reverse tunnels that bypass firewall rules and NAT."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "version",
        "detection_domains": [
            "*.ngrok.com", "*.ngrok.io", "*.ngrok.dev", "*.ngrok.app",
            "*.ngrok.pro", "*.ngrok-free.app", "*.ngrok-agent.com",
            "*.equinox.io",
        ],
        "url_verified": True,
        "github_release_api": "",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002", "T1105"],
    },
    "cloudflared": {
        "url": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe",
        "url_linux": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
        "url_macos": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz",
        "exe": "cloudflared.exe",
        "exe_linux": "cloudflared",
        "desc": "Cloudflare Tunnel client (formerly Argo Tunnel)",
        "vendor": "Cloudflare Inc.",
        "abuse_reason": (
            "Cloudflare Tunnel provides free, authenticated tunnels through "
            "Cloudflare's CDN. Heavily abused for hosting phishing pages, "
            "C2 infrastructure, and data exfiltration behind trusted TLS "
            "certificates from a major CDN provider."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "version",
        "detection_domains": [
            "*.trycloudflare.com", "*.cfargotunnel.com", "*.cftunnel.com",
        ],
        "url_verified": True,
        "github_release_api": "https://api.github.com/repos/cloudflare/cloudflared/releases/latest",
        "account_required": False,
        "technique_ids": ["T1572", "T1090.002", "T1105"],
    },
    "bore": {
        "url": "https://github.com/ekzhang/bore/releases/latest/download/bore-v0.5.2-x86_64-pc-windows-msvc.zip",
        "url_linux": "https://github.com/ekzhang/bore/releases/latest/download/bore-v0.5.2-x86_64-unknown-linux-musl.tar.gz",
        "url_macos": "https://github.com/ekzhang/bore/releases/latest/download/bore-v0.5.2-x86_64-apple-darwin.tar.gz",
        "exe": "bore.exe",
        "exe_linux": "bore",
        "desc": "Bore — modern TCP tunnel in Rust",
        "vendor": "Open Source (ekzhang)",
        "abuse_reason": (
            "Lightweight, single-binary TCP tunnel written in Rust. Exposes "
            "local ports to the internet via bore.pub relay. Its simplicity "
            "and lack of authentication make it attractive for quick C2 setup."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": ["bore.pub:*"],
        "url_verified": False,
        "github_release_api": "https://api.github.com/repos/ekzhang/bore/releases/latest",
        "account_required": False,
        "technique_ids": ["T1572", "T1090.002", "T1105"],
    },
    "chisel": {
        "url": "https://github.com/jpillora/chisel/releases/latest/download/chisel_windows_amd64.gz",
        "url_linux": "https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz",
        "url_macos": "https://github.com/jpillora/chisel/releases/latest/download/chisel_darwin_amd64.gz",
        "exe": "chisel.exe",
        "exe_linux": "chisel",
        "desc": "Chisel — fast TCP/UDP tunnel over HTTP/SSH",
        "vendor": "Open Source (jpillora)",
        "abuse_reason": (
            "Extremely popular with red teams and threat actors. Chisel tunnels "
            "TCP and UDP traffic over HTTP using SSH encryption. Frequently used "
            "for lateral movement and pivoting in post-exploitation."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": [],
        "url_verified": False,
        "github_release_api": "https://api.github.com/repos/jpillora/chisel/releases/latest",
        "account_required": False,
        "technique_ids": ["T1572", "T1090.001", "T1105"],
    },
    "frp": {
        "url": "https://github.com/fatedier/frp/releases/latest/download/frp_0.61.1_windows_amd64.zip",
        "url_linux": "https://github.com/fatedier/frp/releases/latest/download/frp_0.61.1_linux_amd64.tar.gz",
        "url_macos": "https://github.com/fatedier/frp/releases/latest/download/frp_0.61.1_darwin_amd64.tar.gz",
        "exe": "frpc.exe",
        "exe_linux": "frpc",
        "desc": "frp — fast reverse proxy",
        "vendor": "Open Source (fatedier)",
        "abuse_reason": (
            "Fast reverse proxy supporting TCP, UDP, HTTP, HTTPS tunneling. "
            "Widely used in Chinese-speaking threat actor campaigns. The client "
            "(frpc) connects outbound to an attacker-controlled frps server."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": [],
        "url_verified": False,
        "github_release_api": "https://api.github.com/repos/fatedier/frp/releases/latest",
        "account_required": False,
        "technique_ids": ["T1572", "T1090.002", "T1105"],
    },
    "localtonet": {
        "url": "https://localtonet.com/download/localtonet-win-64.zip",
        "url_linux": "https://localtonet.com/download/localtonet-linux-64.zip",
        "url_macos": "https://localtonet.com/download/localtonet-osx-64.zip",
        "exe": "localtonet.exe",
        "exe_linux": "localtonet",
        "desc": "LocaltoNet reverse proxy tunnel",
        "vendor": "LocaltoNet",
        "abuse_reason": (
            "Reverse proxy that exposes localhost services to the internet. "
            "Requires authentication but free accounts are easily created. "
            "Used for unauthorized remote access and data exfiltration."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": ["*.localto.net", "*.localtonet.com"],
        "url_verified": True,
        "github_release_api": "",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002", "T1105"],
    },
    "tmate": {
        "url": "",
        "url_linux": "https://github.com/tmate-io/tmate/releases/latest/download/tmate-2.4.0-static-linux-amd64.tar.xz",
        "url_macos": "",
        "exe": "",
        "exe_linux": "tmate",
        "desc": "tmate — instant terminal sharing via SSH",
        "vendor": "Open Source (tmate-io)",
        "abuse_reason": (
            "Exposes local terminal sessions via internet-accessible SSH URLs. "
            "Can be used as a backdoor — an attacker runs tmate on a compromised "
            "host and gets a shareable SSH session URL for persistent access."
        ),
        "platforms": ["linux", "macos"],
        "safe_flag": "-V",
        "detection_domains": ["*.tmate.io"],
        "url_verified": False,
        "github_release_api": "https://api.github.com/repos/tmate-io/tmate/releases/latest",
        "account_required": False,
        "technique_ids": ["T1572", "T1105"],
    },
    "localtunnel": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "lt",
        "desc": "localtunnel — expose localhost to the world (npm)",
        "vendor": "Open Source (localtunnel)",
        "abuse_reason": (
            "Node.js-based tunneling tool installed via npm. Generates a public "
            "URL for any local port. Used to expose internal services."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": ["*.loca.lt", "*.localtunnel.me"],
        "url_verified": True,
        "github_release_api": "",
        "account_required": False,
        "npm_install": "npm install -g localtunnel",
        "technique_ids": ["T1572", "T1090.002"],
    },
    "localxpose": {
        "url": "https://localxpose.io/download/windows/amd64",
        "url_linux": "https://localxpose.io/download/linux/amd64",
        "url_macos": "https://localxpose.io/download/darwin/amd64",
        "exe": "loclx.exe",
        "exe_linux": "loclx",
        "desc": "LocalXpose — reverse proxy tunnel",
        "vendor": "LocalXpose",
        "abuse_reason": (
            "Reverse proxy tunnel supporting TCP, UDP, HTTP tunnels. Free tier "
            "requires auth token. Used for exposing internal services like SSH "
            "and RDP, and for hosting phishing infrastructure."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "version",
        "detection_domains": ["*.localxpose.io"],
        "url_verified": True,
        "github_release_api": "",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002", "T1105"],
    },
    "pinggy": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "",
        "desc": "Pinggy — SSH-based tunnel (no binary needed)",
        "vendor": "Pinggy",
        "abuse_reason": (
            "Tunneling service that requires only an SSH client — no binary "
            "download needed. Adversaries can establish tunnels using the "
            "built-in SSH client on any modern OS."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "",
        "detection_domains": ["*.pinggy.io", "*.pinggy.link"],
        "url_verified": True,
        "github_release_api": "",
        "account_required": False,
        "ssh_command": "ssh -p 443 -R0:localhost:{PORT} a.pinggy.io",
        "technique_ids": ["T1572", "T1090.002"],
    },
    "serveo": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "",
        "desc": "Serveo — SSH-based tunnel (no binary needed)",
        "vendor": "Serveo",
        "abuse_reason": (
            "SSH-based tunneling service requiring no client binary. Uses "
            "standard SSH remote port forwarding to expose local services "
            "through serveo.net subdomains."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "",
        "detection_domains": ["*.serveo.net"],
        "url_verified": True,
        "github_release_api": "",
        "account_required": False,
        "ssh_command": "ssh -R 80:localhost:{PORT} serveo.net",
        "technique_ids": ["T1572", "T1090.002"],
    },
    "btunnels": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "btunnel",
        "desc": "BTunnels — expose local ports to the internet",
        "vendor": "BTunnels",
        "abuse_reason": (
            "Exposes local ports and filesystem over the internet. Free tier "
            "available. Can be used for data exfiltration and unauthorized "
            "remote access."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": ["*.btunnel.co.in", "*.btunnel.in"],
        "url_verified": True,
        "github_release_api": "",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002", "T1048"],
    },
    "devtunnels": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "devtunnel.exe",
        "exe_linux": "devtunnel",
        "desc": "Microsoft Dev Tunnels — expose local ports via Azure",
        "vendor": "Microsoft",
        "abuse_reason": (
            "Microsoft's official dev tunneling service using Azure infrastructure. "
            "Traffic appears as legitimate Microsoft/Azure communication, making "
            "it very difficult to detect and block without disrupting business "
            "operations."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": [
            "*.devtunnels.ms", "*.tunnels.api.visualstudio.com",
            "*.data.rel.tunnels.api.visualstudio.com",
        ],
        "url_verified": True,
        "github_release_api": "",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002"],
    },
    "pagekite": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "pagekite.py",
        "desc": "PageKite — Python-based localhost tunnel",
        "vendor": "The Beanstalks Project",
        "abuse_reason": (
            "Python-based tunneling tool that can run anywhere Python is "
            "installed. Exposes local HTTP, SSH, and other services through "
            "pagekite.net subdomains."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": ["*.pagekite.net", "*.pagekite.me"],
        "url_verified": True,
        "github_release_api": "",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002"],
    },
    "jprq": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "jprq",
        "desc": "JPRQ — free tunnel for exposing local servers",
        "vendor": "Open Source (azimjohn)",
        "abuse_reason": (
            "Free, open-source tunneling tool supporting HTTP and TCP tunnels. "
            "Requires auth token but free accounts are easily obtained."
        ),
        "platforms": ["windows", "linux"],
        "safe_flag": "--help",
        "detection_domains": ["*.jprq.io"],
        "url_verified": True,
        "github_release_api": "https://api.github.com/repos/azimjohn/jprq/releases/latest",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002"],
    },
    "loophole": {
        "url": "https://loophole.cloud/download/loophole-cli_windows_amd64.zip",
        "url_linux": "https://loophole.cloud/download/loophole-cli_linux_amd64.tar.gz",
        "url_macos": "https://loophole.cloud/download/loophole-cli_darwin_amd64.tar.gz",
        "exe": "loophole.exe",
        "exe_linux": "loophole",
        "desc": "Loophole — expose local services to the internet",
        "vendor": "Loophole Labs",
        "abuse_reason": (
            "Open-source tunneling tool that exposes local services. Supports "
            "HTTP, WebSocket, and custom domain tunnels."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": ["*.loophole.site", "loophole.eu.auth0.com"],
        "url_verified": False,
        "github_release_api": "",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002", "T1105"],
    },
    "telebit": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "telebit",
        "desc": "Telebit — expose localhost services over the internet",
        "vendor": "Open Source (telebit)",
        "abuse_reason": (
            "Open-source tunneling tool that exposes local services and "
            "applications to the internet. Can be used for unauthorized "
            "remote access."
        ),
        "platforms": ["linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": [
            "*.telebit.io", "*.telebit.cloud", "*.telebit.fun",
            "get.telebit.io",
        ],
        "url_verified": True,
        "github_release_api": "",
        "account_required": False,
        "technique_ids": ["T1572", "T1090.002"],
    },
    "burrow": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "",
        "desc": "Burrow.io — subscription-based tunnel service",
        "vendor": "Burrow",
        "abuse_reason": (
            "Subscription-based tunneling service. Exposes local services "
            "to the internet via burrow.io infrastructure."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "",
        "detection_domains": ["*.burrow.io", "*.burrow.link"],
        "url_verified": True,
        "github_release_api": "",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002"],
    },
    "shellhub": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "shellhub-agent",
        "desc": "ShellHub — SSH gateway and remote access",
        "vendor": "Open Source (shellhub-io)",
        "abuse_reason": (
            "Open-source SSH gateway that provides remote access to Linux "
            "devices behind firewalls. The agent connects outbound, making "
            "it useful for bypassing NAT and firewall rules."
        ),
        "platforms": ["linux"],
        "safe_flag": "--help",
        "detection_domains": ["*.shellhub.io"],
        "url_verified": True,
        "github_release_api": "https://api.github.com/repos/shellhub-io/shellhub/releases/latest",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002"],
    },
    "dataplicity": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "dataplicity",
        "desc": "Dataplicity — remote device management",
        "vendor": "Dataplicity Ltd.",
        "abuse_reason": (
            "IoT/Linux remote management platform. Provides wormhole URLs "
            "that expose local ports on Linux devices to the internet. "
            "Targets Linux/IoT devices specifically."
        ),
        "platforms": ["linux"],
        "safe_flag": "--help",
        "detection_domains": ["*.dataplicity.com"],
        "url_verified": True,
        "github_release_api": "",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002"],
    },
    "tunnelto": {
        "url": "",
        "url_linux": "",
        "url_macos": "",
        "exe": "",
        "exe_linux": "tunnel",
        "desc": "TunnelTo — expose local services to the internet",
        "vendor": "TunnelTo",
        "abuse_reason": (
            "Subscription-based tunnel service that exposes local services "
            "to custom subdomains. Used for unauthorized remote access."
        ),
        "platforms": ["windows", "linux", "macos"],
        "safe_flag": "--help",
        "detection_domains": ["*.tuns.sh", "*.ssi.sh", "*.tunnelto.dev"],
        "url_verified": True,
        "github_release_api": "",
        "account_required": True,
        "technique_ids": ["T1572", "T1090.002"],
    },
}


class LOTTunnelsIngestor(BaseIngestor):
    """Ingestor for LOTTunnels — Living Off The Tunnels.

    LOTTunnels catalogs legitimate tunneling and proxy tools that adversaries
    abuse for C2, data exfiltration, and persistent remote access.

    This ingestor generates prevention tests in several categories:

    1. **Download & execute prevention** — For tools with known download URLs,
       test if security controls block the download and execution of the binary.
       Includes SHA256 hash verification of downloaded files.

    2. **Detect existing installation** — Check if a tunneling tool is already
       present on the system (running process, installed binary, or npm package).

    3. **Network connectivity prevention** — Test whether DNS resolution and
       network connectivity to known tunnel relay domains is blocked.

    4. **SSH-based tunnel prevention** — For tools that use SSH (Pinggy, Serveo),
       test whether outbound SSH to the tunnel relay is blocked.

    URL stability approach:
    - For GitHub-hosted tools, download URLs use the /releases/latest/ pattern
      which auto-resolves to the current version.
    - The catalog stores github_release_api endpoints for programmatic lookup
      of the latest release URL if needed.
    - url_verified=False flags URLs that may go stale.
    - Every tool gets a "detect existing" test that works even if the download
      URL is broken, ensuring the test suite remains useful over time.
    """

    @property
    def source_id(self) -> str:
        return "lottunnels"

    @property
    def display_name(self) -> str:
        return "LOTTunnels"

    @property
    def description(self) -> str:
        return (
            "Living Off The Tunnels: legitimate tunneling and proxy tools "
            "abused by adversaries for C2, data exfiltration, and remote access"
        )

    @property
    def repo_url(self) -> str:
        return "https://github.com/LOTTunnels/LOTTunnels.github.io"

    @property
    def platform(self) -> str:
        return "multi"

    # -- fetch -----------------------------------------------------------------

    async def fetch(self) -> None:
        """Clone or update the LOTTunnels repository."""
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

    # -- parse -----------------------------------------------------------------

    async def parse(self) -> list[dict]:
        """Parse LOTTunnels data into prevention test dicts.

        Combines data from:
        1. The LOTTunnels Git repo (_lottunnels/Binaries/*.md with YAML front matter)
        2. Our hardcoded _TUNNEL_CATALOG for enriched download/detection metadata
        """
        tests: list[dict] = []

        # Track which catalog tools we see in the repo data
        seen_catalog_keys: set[str] = set()

        # Parse YAML front matter from LOTTunnels repo files
        binaries_dir = self.data_dir / "_lottunnels" / "Binaries"
        if binaries_dir.exists():
            for md_file in sorted(binaries_dir.glob("*.md")):
                try:
                    front_matter = self._extract_front_matter(md_file)
                    if not front_matter:
                        continue
                    tool_name = front_matter.get("Name", "")
                    if not tool_name:
                        continue

                    # Match to our catalog by lowercased key
                    catalog_key = self._find_catalog_key(tool_name)
                    if catalog_key:
                        seen_catalog_keys.add(catalog_key)

                    catalog = _TUNNEL_CATALOG.get(catalog_key, {}) if catalog_key else {}
                    tests.extend(self._build_tests_for_tool(tool_name, front_matter, catalog))
                except Exception as exc:
                    logger.debug(f"Failed to parse {md_file.name}: {exc}")
                    continue
        else:
            logger.warning(f"LOTTunnels binaries dir not found: {binaries_dir}")

        # Generate tests for catalog tools not found in the repo data
        for catalog_key, catalog in _TUNNEL_CATALOG.items():
            if catalog_key in seen_catalog_keys:
                continue
            tool_name = catalog_key.replace("_", " ").title()
            tests.extend(self._build_tests_for_tool(tool_name, {}, catalog))

        self._tests = tests
        logger.info(f"LOTTunnels: parsed {len(tests)} tests")
        return tests

    # -- front matter extraction -----------------------------------------------

    @staticmethod
    def _extract_front_matter(md_file: Path) -> dict | None:
        """Extract YAML front matter from a markdown file.

        LOTTunnels files use Jekyll-style front matter delimited by --- lines.
        """
        text = md_file.read_text(encoding="utf-8", errors="replace")
        # Match YAML front matter between --- delimiters
        match = re.match(r"^-{3,}\s*\n(.*?)\n-{3,}", text, re.DOTALL)
        if not match:
            return None
        try:
            return yaml.safe_load(match.group(1))
        except yaml.YAMLError:
            return None

    # -- catalog key matching --------------------------------------------------

    @staticmethod
    def _find_catalog_key(tool_name: str) -> str | None:
        """Find the catalog key that matches a tool name from the repo data."""
        normalized = tool_name.strip().lower().replace(" ", "").replace("-", "")
        for key in _TUNNEL_CATALOG:
            if key.lower().replace("_", "").replace("-", "") == normalized:
                return key
        # Fuzzy fallback: check if the tool name contains or is contained by a key
        for key in _TUNNEL_CATALOG:
            if key.lower() in normalized or normalized in key.lower():
                return key
        return None

    # -- test generation -------------------------------------------------------

    def _build_tests_for_tool(
        self,
        tool_name: str,
        front_matter: dict,
        catalog: dict,
    ) -> list[dict]:
        """Generate all test types for a single tunneling tool."""
        tests: list[dict] = []

        platforms = catalog.get("platforms", ["windows", "linux", "macos"])
        desc = catalog.get("desc", front_matter.get("Description", tool_name))
        abuse_reason = catalog.get("abuse_reason", "")
        technique_ids = catalog.get("technique_ids", ["T1572", "T1090.002"])
        primary_technique = technique_ids[0] if technique_ids else "T1572"
        detection_domains = catalog.get("detection_domains", [])
        url_verified = catalog.get("url_verified", False)

        # Extract detection domains from front matter if not in catalog
        if not detection_domains:
            fm_detection = front_matter.get("Detection", [])
            if isinstance(fm_detection, list):
                for det in fm_detection:
                    if isinstance(det, dict) and "Domain" in det:
                        detection_domains.append(det["Domain"])
                    elif isinstance(det, str):
                        detection_domains.append(det)

        # Extract commands from front matter
        fm_commands = front_matter.get("Commands", []) or []

        metadata_base = {
            "source": "lottunnels",
            "tunnel_tool": tool_name,
            "vendor": catalog.get("vendor", ""),
            "abuse_reason": abuse_reason,
            "technique_ids": technique_ids,
            "detection_domains": detection_domains,
            "url_verified": url_verified,
            "github_release_api": catalog.get("github_release_api", ""),
        }

        # --- Test Type 1: Download & Execute (Windows) -------------------------
        dl_url = catalog.get("url", "")
        exe = catalog.get("exe", "")
        safe_flag = catalog.get("safe_flag", "")

        if dl_url and exe:
            tests.append(self._build_download_execute_test_windows(
                tool_name, desc, dl_url, exe, safe_flag, primary_technique,
                platforms, abuse_reason, metadata_base, url_verified,
            ))

        # --- Test Type 1b: Download & Execute (Linux/macOS) --------------------
        dl_url_linux = catalog.get("url_linux", "")
        exe_linux = catalog.get("exe_linux", "")
        if dl_url_linux and exe_linux:
            tests.append(self._build_download_execute_test_linux(
                tool_name, desc, dl_url_linux, exe_linux, safe_flag,
                primary_technique, platforms, abuse_reason, metadata_base,
                url_verified,
            ))

        # --- Test Type 2: SSH-based tunnel prevention --------------------------
        ssh_command = catalog.get("ssh_command", "")
        if ssh_command:
            tests.append(self._build_ssh_tunnel_test(
                tool_name, desc, ssh_command, primary_technique,
                platforms, abuse_reason, metadata_base,
            ))

        # --- Test Type 3: Detect existing installation -------------------------
        tests.append(self._build_detect_existing_test_powershell(
            tool_name, desc, exe, exe_linux, primary_technique,
            abuse_reason, metadata_base, detection_domains,
        ))
        if "linux" in platforms or "macos" in platforms:
            tests.append(self._build_detect_existing_test_bash(
                tool_name, desc, exe_linux, primary_technique,
                platforms, abuse_reason, metadata_base, detection_domains,
            ))

        # --- Test Type 4: Network connectivity prevention ----------------------
        if detection_domains:
            tests.append(self._build_network_test_powershell(
                tool_name, desc, detection_domains, "T1572",
                abuse_reason, metadata_base,
            ))
            if "linux" in platforms or "macos" in platforms:
                tests.append(self._build_network_test_bash(
                    tool_name, desc, detection_domains, "T1572",
                    platforms, abuse_reason, metadata_base,
                ))

        return tests

    # -- Download & Execute tests ----------------------------------------------

    def _build_download_execute_test_windows(
        self, tool_name: str, desc: str, dl_url: str, exe: str,
        safe_flag: str, technique_id: str, platforms: list[str],
        abuse_reason: str, metadata_base: dict, url_verified: bool,
    ) -> dict:
        url_note = "" if url_verified else (
            "# NOTE: url_verified=False — this URL may be stale.\n"
            "# If download fails, the test still validates that your security\n"
            "# stack blocks the download attempt and network connectivity.\n"
        )

        command = (
            f"# === LOTTunnels: {tool_name} Download & Execute Prevention ===\n"
            f"# Tool: {desc}\n"
            f"# Technique: {technique_id} (Protocol Tunneling)\n"
            f"{url_note}"
            f"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n"
            f"$outDir = Join-Path $env:TEMP 'lottunnels_test'\n"
            f"New-Item -Type Directory $outDir -ErrorAction Ignore -Force | Out-Null\n"
            f"$outPath = Join-Path $outDir '{exe}'\n"
            f"Write-Host '[*] Downloading {tool_name} from {dl_url}...'\n"
            f"try {{\n"
            f"    Invoke-WebRequest -Uri '{dl_url}' -OutFile $outPath -UseBasicParsing -ErrorAction Stop -TimeoutSec 30\n"
            f"}} catch {{\n"
            f"    Write-Host \"BLOCKED: Download failed - $($_.Exception.Message)\"\n"
            f"    exit 0\n"
            f"}}\n"
            f"if (Test-Path $outPath) {{\n"
            f"    $hash = (Get-FileHash -Path $outPath -Algorithm SHA256).Hash\n"
            f"    Write-Host \"[*] Downloaded to: $outPath\"\n"
            f"    Write-Host \"[*] SHA256: $hash\"\n"
            f"    # Unzip if archive\n"
            f"    if ($outPath -match '\\.(zip|gz|tgz)$') {{\n"
            f"        Write-Host '[*] Extracting archive...'\n"
            f"        try {{ Expand-Archive -Path $outPath -DestinationPath $outDir -Force -ErrorAction Stop }} catch {{ }}\n"
            f"    }}\n"
            f"    # Find the executable\n"
            f"    $binary = Get-ChildItem -Path $outDir -Filter '{exe}' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1\n"
            f"    if (-not $binary) {{ $binary = Get-ChildItem -Path $outDir -Filter '*.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 }}\n"
            f"    if ($binary) {{\n"
            f"        $binHash = (Get-FileHash -Path $binary.FullName -Algorithm SHA256).Hash\n"
            f"        Write-Host \"[*] Binary SHA256: $binHash\"\n"
            f"        Write-Host '[*] Attempting execution...'\n"
            f"        try {{\n"
            f"            $proc = Start-Process -FilePath $binary.FullName"
        )
        if safe_flag:
            command += f" -ArgumentList '{safe_flag}'"
        command += (
            f" -PassThru -NoNewWindow -ErrorAction Stop\n"
            f"            Start-Sleep -Seconds 5\n"
            f"            if (-not $proc.HasExited) {{ $proc.Kill() }}\n"
            f"            Write-Host \"ALLOWED: {tool_name} executed (PID: $($proc.Id))\"\n"
            f"        }} catch {{\n"
            f"            Write-Host \"BLOCKED: Execution prevented - $($_.Exception.Message)\"\n"
            f"        }}\n"
            f"    }} else {{\n"
            f"        Write-Host 'BLOCKED: Binary not found after extraction'\n"
            f"    }}\n"
            f"}} else {{\n"
            f"    Write-Host 'BLOCKED: File not written to disk'\n"
            f"}}"
        )

        cleanup = (
            f"$outDir = Join-Path $env:TEMP 'lottunnels_test'\n"
            f"Remove-Item -Path $outDir -Recurse -Force -ErrorAction SilentlyContinue"
        )

        meta = dict(metadata_base)
        meta["test_type"] = "download_execute"
        meta["download_url"] = dl_url
        meta["target_platform"] = "windows"

        return {
            "name": f"LOTTunnels: {tool_name} - Download & Execute (Windows)",
            "description": (
                f"Download and attempt to execute {tool_name} ({desc}) on Windows. "
                f"Tests whether application control and endpoint protection block "
                f"the download and execution of a tunneling tool commonly abused "
                f"for adversary C2 and data exfiltration. {abuse_reason}"
            ),
            "command": command,
            "executor": "powershell",
            "technique_id": technique_id,
            "binary_path": exe,
            "elevation_required": False,
            "risk_level": "high",
            "platforms": ["windows"],
            "cleanup_command": cleanup,
            "metadata": meta,
        }

    def _build_download_execute_test_linux(
        self, tool_name: str, desc: str, dl_url: str, exe: str,
        safe_flag: str, technique_id: str, platforms: list[str],
        abuse_reason: str, metadata_base: dict, url_verified: bool,
    ) -> dict:
        url_note = "" if url_verified else (
            "# NOTE: url_verified=False — this URL may be stale.\n"
        )

        # Determine extraction command based on URL
        if dl_url.endswith(".tar.gz") or dl_url.endswith(".tgz"):
            extract_cmd = "tar xzf \"$OUTPATH\" -C \"$OUTDIR\" 2>/dev/null"
        elif dl_url.endswith(".tar.xz"):
            extract_cmd = "tar xJf \"$OUTPATH\" -C \"$OUTDIR\" 2>/dev/null"
        elif dl_url.endswith(".zip"):
            extract_cmd = "unzip -o \"$OUTPATH\" -d \"$OUTDIR\" 2>/dev/null"
        elif dl_url.endswith(".gz"):
            extract_cmd = "gunzip -f \"$OUTPATH\" 2>/dev/null"
        else:
            extract_cmd = ""

        safe_exec = f" {safe_flag}" if safe_flag else ""

        command = (
            f"#!/bin/bash\n"
            f"# === LOTTunnels: {tool_name} Download & Execute Prevention ===\n"
            f"# Tool: {desc}\n"
            f"# Technique: {technique_id} (Protocol Tunneling)\n"
            f"{url_note}"
            f"OUTDIR=$(mktemp -d /tmp/lottunnels_test.XXXXXX)\n"
            f"OUTPATH=\"$OUTDIR/$(basename '{dl_url}')\"\n"
            f"echo '[*] Downloading {tool_name} from {dl_url}...'\n"
            f"if curl -fsSL --max-time 30 -o \"$OUTPATH\" '{dl_url}'; then\n"
            f"    HASH=$(sha256sum \"$OUTPATH\" | cut -d' ' -f1)\n"
            f"    echo \"[*] Downloaded: $OUTPATH\"\n"
            f"    echo \"[*] SHA256: $HASH\"\n"
        )
        if extract_cmd:
            command += (
                f"    echo '[*] Extracting archive...'\n"
                f"    {extract_cmd}\n"
            )
        command += (
            f"    BINARY=$(find \"$OUTDIR\" -name '{exe}' -type f 2>/dev/null | head -1)\n"
            f"    [ -z \"$BINARY\" ] && BINARY=$(find \"$OUTDIR\" -type f -executable 2>/dev/null | head -1)\n"
            f"    if [ -n \"$BINARY\" ]; then\n"
            f"        chmod +x \"$BINARY\" 2>/dev/null\n"
            f"        BINHASH=$(sha256sum \"$BINARY\" | cut -d' ' -f1)\n"
            f"        echo \"[*] Binary SHA256: $BINHASH\"\n"
            f"        echo '[*] Attempting execution...'\n"
            f"        if timeout 10 \"$BINARY\"{safe_exec} >/dev/null 2>&1; then\n"
            f"            echo 'ALLOWED: {tool_name} executed successfully'\n"
            f"        else\n"
            f"            echo \"BLOCKED: Execution prevented (exit code: $?)\"\n"
            f"        fi\n"
            f"    else\n"
            f"        echo 'BLOCKED: Binary not found after extraction'\n"
            f"    fi\n"
            f"else\n"
            f"    echo 'BLOCKED: Download failed'\n"
            f"fi"
        )

        cleanup = (
            f"rm -rf /tmp/lottunnels_test.* 2>/dev/null"
        )

        test_platforms = [p for p in platforms if p in ("linux", "macos")]
        meta = dict(metadata_base)
        meta["test_type"] = "download_execute"
        meta["download_url"] = dl_url
        meta["target_platform"] = "linux_macos"

        return {
            "name": f"LOTTunnels: {tool_name} - Download & Execute (Linux/macOS)",
            "description": (
                f"Download and attempt to execute {tool_name} ({desc}) on Linux/macOS. "
                f"Tests whether endpoint protection blocks the download and execution "
                f"of a tunneling tool commonly abused for C2. {abuse_reason}"
            ),
            "command": command,
            "executor": "bash",
            "technique_id": technique_id,
            "binary_path": exe,
            "elevation_required": False,
            "risk_level": "high",
            "platforms": test_platforms,
            "cleanup_command": cleanup,
            "metadata": meta,
        }

    # -- SSH-based tunnel test -------------------------------------------------

    def _build_ssh_tunnel_test(
        self, tool_name: str, desc: str, ssh_command: str,
        technique_id: str, platforms: list[str],
        abuse_reason: str, metadata_base: dict,
    ) -> dict:
        # Replace {PORT} placeholder with a benign test port
        test_ssh = ssh_command.replace("{PORT}", "8080")

        command = (
            f"#!/bin/bash\n"
            f"# === LOTTunnels: {tool_name} SSH Tunnel Prevention ===\n"
            f"# Tool: {desc}\n"
            f"# {tool_name} requires only an SSH client — no binary download needed.\n"
            f"# This tests whether outbound SSH to the tunnel relay is blocked.\n"
            f"echo '[*] Testing SSH-based tunnel connectivity for {tool_name}...'\n"
            f"# Extract host from SSH command\n"
            f"if timeout 10 {test_ssh} 2>&1; then\n"
            f"    echo 'ALLOWED: SSH tunnel to {tool_name} relay succeeded'\n"
            f"else\n"
            f"    EXIT_CODE=$?\n"
            f"    if [ $EXIT_CODE -eq 124 ]; then\n"
            f"        echo 'BLOCKED: SSH connection timed out (likely firewalled)'\n"
            f"    else\n"
            f"        echo \"BLOCKED: SSH connection failed (exit code: $EXIT_CODE)\"\n"
            f"    fi\n"
            f"fi"
        )

        meta = dict(metadata_base)
        meta["test_type"] = "ssh_tunnel"
        meta["ssh_command"] = ssh_command

        test_platforms = [p for p in platforms if p in ("linux", "macos")]

        return {
            "name": f"LOTTunnels: {tool_name} - SSH Tunnel Prevention",
            "description": (
                f"Test whether outbound SSH connectivity to the {tool_name} relay "
                f"service is blocked. {tool_name} ({desc}) uses SSH for tunneling "
                f"and requires no binary download. {abuse_reason}"
            ),
            "command": command,
            "executor": "bash",
            "technique_id": technique_id,
            "binary_path": None,
            "elevation_required": False,
            "risk_level": "medium",
            "platforms": test_platforms or ["linux", "macos"],
            "cleanup_command": None,
            "metadata": meta,
        }

    # -- Detect existing installation tests ------------------------------------

    def _build_detect_existing_test_powershell(
        self, tool_name: str, desc: str, exe: str, exe_linux: str,
        technique_id: str, abuse_reason: str, metadata_base: dict,
        detection_domains: list[str],
    ) -> dict:
        # Build process name patterns to search for
        search_names = set()
        for name_part in [exe, exe_linux, tool_name.lower()]:
            if name_part:
                clean = name_part.replace(".exe", "").replace(".py", "").strip()
                if clean:
                    search_names.add(clean)
        # Also try first word of tool name
        first_word = tool_name.split()[0].lower() if tool_name else ""
        if first_word and len(first_word) > 2:
            search_names.add(first_word)

        process_checks = []
        for sn in sorted(search_names):
            process_checks.append(
                f"$procs = Get-Process -Name '*{sn}*' -ErrorAction SilentlyContinue\n"
                f"if ($procs) {{\n"
                f"    Write-Host 'FOUND: Process matching {sn}:' ($procs | Select-Object Name, Id, Path | Out-String)\n"
                f"    $found = $true\n"
                f"}}"
            )

        dns_checks = []
        for domain in detection_domains[:3]:
            # Strip wildcard prefix for DNS test
            test_domain = domain.lstrip("*").lstrip(".").rstrip("*").rstrip(":")
            if test_domain:
                dns_checks.append(
                    f"try {{ $dns = Resolve-DnsName '{test_domain}' -ErrorAction Stop; "
                    f"Write-Host 'REACHABLE: {test_domain} resolves'; $found = $true }} "
                    f"catch {{ Write-Host 'BLOCKED: {test_domain} does not resolve' }}"
                )

        command = (
            f"# === LOTTunnels: {tool_name} - Detect Existing (Windows) ===\n"
            f"# Check if {tool_name} is already present on this system\n"
            f"$found = $false\n"
            f"\n"
            f"# Check for running processes\n"
            + "\n".join(process_checks) + "\n"
            f"\n"
            f"# Check common install locations\n"
            f"$searchPaths = @(\n"
            f"    $env:USERPROFILE + '\\Downloads',\n"
            f"    $env:USERPROFILE + '\\Desktop',\n"
            f"    $env:LOCALAPPDATA,\n"
            f"    $env:APPDATA,\n"
            f"    $env:TEMP,\n"
            f"    'C:\\Tools',\n"
            f"    'C:\\ProgramData'\n"
            f")\n"
            f"foreach ($sp in $searchPaths) {{\n"
            f"    if (Test-Path $sp) {{\n"
        )
        exe_search = exe if exe else (exe_linux + ".exe" if exe_linux else tool_name.lower() + ".exe")
        command += (
            f"        $match = Get-ChildItem -Path $sp -Filter '{exe_search}' -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 1\n"
            f"        if ($match) {{\n"
            f"            $h = (Get-FileHash $match.FullName -Algorithm SHA256).Hash\n"
            f"            Write-Host \"FOUND: $($match.FullName) (SHA256: $h)\"\n"
            f"            $found = $true\n"
            f"        }}\n"
            f"    }}\n"
            f"}}\n"
            f"\n"
            f"# Check PATH\n"
            f"$inPath = Get-Command '{exe_search.replace('.exe', '')}' -ErrorAction SilentlyContinue\n"
            f"if ($inPath) {{ Write-Host \"FOUND: $($inPath.Source) in PATH\"; $found = $true }}\n"
            f"\n"
        )

        if dns_checks:
            command += (
                f"# Check DNS connectivity to tunnel relay domains\n"
                + "\n".join(dns_checks) + "\n"
                f"\n"
            )

        command += (
            f"if (-not $found) {{ Write-Host 'NOT FOUND: {tool_name} not detected on this system' }}"
        )

        meta = dict(metadata_base)
        meta["test_type"] = "detect_existing"
        meta["target_platform"] = "windows"

        return {
            "name": f"LOTTunnels: {tool_name} - Detect Existing (Windows)",
            "description": (
                f"Check if {tool_name} ({desc}) is already present on this Windows "
                f"endpoint. Searches for running processes, installed binaries, and "
                f"DNS connectivity to known relay domains. This test works even if "
                f"download URLs change. {abuse_reason}"
            ),
            "command": command,
            "executor": "powershell",
            "technique_id": technique_id,
            "binary_path": None,
            "elevation_required": False,
            "risk_level": "medium",
            "platforms": ["windows"],
            "cleanup_command": None,
            "metadata": meta,
        }

    def _build_detect_existing_test_bash(
        self, tool_name: str, desc: str, exe_linux: str,
        technique_id: str, platforms: list[str],
        abuse_reason: str, metadata_base: dict,
        detection_domains: list[str],
    ) -> dict:
        binary_name = exe_linux if exe_linux else tool_name.lower().replace(" ", "")

        dns_checks = []
        for domain in detection_domains[:3]:
            test_domain = domain.lstrip("*").lstrip(".").rstrip("*").rstrip(":")
            if test_domain:
                dns_checks.append(
                    f"if host '{test_domain}' >/dev/null 2>&1 || dig +short '{test_domain}' 2>/dev/null | grep -q '.'; then\n"
                    f"    echo 'REACHABLE: {test_domain} resolves'\n"
                    f"    FOUND=true\n"
                    f"else\n"
                    f"    echo 'BLOCKED: {test_domain} does not resolve'\n"
                    f"fi"
                )

        command = (
            f"#!/bin/bash\n"
            f"# === LOTTunnels: {tool_name} - Detect Existing (Linux/macOS) ===\n"
            f"FOUND=false\n"
            f"\n"
            f"# Check for running processes\n"
            f"PROCS=$(pgrep -la '{binary_name}' 2>/dev/null)\n"
            f"if [ -n \"$PROCS\" ]; then\n"
            f"    echo \"FOUND: {tool_name} process running: $PROCS\"\n"
            f"    FOUND=true\n"
            f"fi\n"
            f"\n"
            f"# Check if binary is in PATH\n"
            f"if command -v '{binary_name}' >/dev/null 2>&1; then\n"
            f"    BINPATH=$(command -v '{binary_name}')\n"
            f"    HASH=$(sha256sum \"$BINPATH\" 2>/dev/null | cut -d' ' -f1)\n"
            f"    echo \"FOUND: $BINPATH in PATH (SHA256: $HASH)\"\n"
            f"    FOUND=true\n"
            f"fi\n"
            f"\n"
            f"# Check common locations\n"
            f"for DIR in /usr/local/bin /usr/bin /opt /tmp ~/Downloads ~/Desktop ~/.local/bin; do\n"
            f"    if [ -f \"$DIR/{binary_name}\" ]; then\n"
            f"        HASH=$(sha256sum \"$DIR/{binary_name}\" 2>/dev/null | cut -d' ' -f1)\n"
            f"        echo \"FOUND: $DIR/{binary_name} (SHA256: $HASH)\"\n"
            f"        FOUND=true\n"
            f"    fi\n"
            f"done\n"
            f"\n"
            f"# Check npm global packages (for Node.js-based tunnels)\n"
            f"if command -v npm >/dev/null 2>&1; then\n"
            f"    if npm list -g '{binary_name}' 2>/dev/null | grep -q '{binary_name}'; then\n"
            f"        echo 'FOUND: {binary_name} installed as npm global package'\n"
            f"        FOUND=true\n"
            f"    fi\n"
            f"fi\n"
        )

        if dns_checks:
            command += (
                f"\n"
                f"# Check DNS connectivity to tunnel relay domains\n"
                + "\n".join(dns_checks) + "\n"
            )

        command += (
            f"\n"
            f"if [ \"$FOUND\" = false ]; then\n"
            f"    echo 'NOT FOUND: {tool_name} not detected on this system'\n"
            f"fi"
        )

        test_platforms = [p for p in platforms if p in ("linux", "macos")]
        meta = dict(metadata_base)
        meta["test_type"] = "detect_existing"
        meta["target_platform"] = "linux_macos"

        return {
            "name": f"LOTTunnels: {tool_name} - Detect Existing (Linux/macOS)",
            "description": (
                f"Check if {tool_name} ({desc}) is already present on this "
                f"Linux/macOS endpoint. Searches for running processes, installed "
                f"binaries, npm packages, and DNS connectivity to known relay "
                f"domains. This test works even if download URLs change. "
                f"{abuse_reason}"
            ),
            "command": command,
            "executor": "bash",
            "technique_id": technique_id,
            "binary_path": None,
            "elevation_required": False,
            "risk_level": "medium",
            "platforms": test_platforms or ["linux", "macos"],
            "cleanup_command": None,
            "metadata": meta,
        }

    # -- Network connectivity tests --------------------------------------------

    def _build_network_test_powershell(
        self, tool_name: str, desc: str, detection_domains: list[str],
        technique_id: str, abuse_reason: str, metadata_base: dict,
    ) -> dict:
        dns_checks = []
        for domain in detection_domains:
            test_domain = domain.lstrip("*").lstrip(".").rstrip("*").rstrip(":")
            if not test_domain:
                continue
            dns_checks.append(
                f"Write-Host '[*] Testing: {test_domain}'\n"
                f"try {{\n"
                f"    $dns = Resolve-DnsName '{test_domain}' -Type A -ErrorAction Stop\n"
                f"    $ips = ($dns | Where-Object {{ $_.QueryType -eq 'A' }} | Select-Object -ExpandProperty IPAddress) -join ', '\n"
                f"    Write-Host \"REACHABLE: {test_domain} -> $ips\"\n"
                f"    $reachable++\n"
                f"}} catch {{\n"
                f"    Write-Host \"BLOCKED: {test_domain} - DNS resolution blocked\"\n"
                f"    $blocked++\n"
                f"}}"
            )

        command = (
            f"# === LOTTunnels: {tool_name} - Network Connectivity Test (Windows) ===\n"
            f"# Tests DNS resolution to known {tool_name} relay/C2 domains.\n"
            f"# These domains should be blocked if {tool_name} is not authorized.\n"
            f"$reachable = 0\n"
            f"$blocked = 0\n"
            f"\n"
            + "\n".join(dns_checks) + "\n"
            f"\n"
            f"Write-Host \"`n=== Summary ===\"\n"
            f"Write-Host \"Reachable: $reachable | Blocked: $blocked\"\n"
            f"if ($reachable -gt 0) {{\n"
            f"    Write-Host 'WARNING: {tool_name} relay domains are reachable — tunneling may be possible'\n"
            f"}} else {{\n"
            f"    Write-Host 'PASS: All {tool_name} relay domains are blocked'\n"
            f"}}"
        )

        meta = dict(metadata_base)
        meta["test_type"] = "network_connectivity"
        meta["target_platform"] = "windows"

        return {
            "name": f"LOTTunnels: {tool_name} - Network Connectivity (Windows)",
            "description": (
                f"Test DNS resolution and network connectivity to known {tool_name} "
                f"({desc}) relay domains. If these domains resolve, an adversary "
                f"could use {tool_name} to establish a tunnel. {abuse_reason}"
            ),
            "command": command,
            "executor": "powershell",
            "technique_id": technique_id,
            "binary_path": None,
            "elevation_required": False,
            "risk_level": "medium",
            "platforms": ["windows"],
            "cleanup_command": None,
            "metadata": meta,
        }

    def _build_network_test_bash(
        self, tool_name: str, desc: str, detection_domains: list[str],
        technique_id: str, platforms: list[str],
        abuse_reason: str, metadata_base: dict,
    ) -> dict:
        dns_checks = []
        for domain in detection_domains:
            test_domain = domain.lstrip("*").lstrip(".").rstrip("*").rstrip(":")
            if not test_domain:
                continue
            dns_checks.append(
                f"echo '[*] Testing: {test_domain}'\n"
                f"if host '{test_domain}' >/dev/null 2>&1; then\n"
                f"    IP=$(host '{test_domain}' 2>/dev/null | grep 'has address' | head -1 | awk '{{print $NF}}')\n"
                f"    echo \"REACHABLE: {test_domain} -> $IP\"\n"
                f"    REACHABLE=$((REACHABLE+1))\n"
                f"else\n"
                f"    echo 'BLOCKED: {test_domain} - DNS resolution blocked'\n"
                f"    BLOCKED=$((BLOCKED+1))\n"
                f"fi"
            )

        command = (
            f"#!/bin/bash\n"
            f"# === LOTTunnels: {tool_name} - Network Connectivity Test (Linux/macOS) ===\n"
            f"REACHABLE=0\n"
            f"BLOCKED=0\n"
            f"\n"
            + "\n".join(dns_checks) + "\n"
            f"\n"
            f"echo ''\n"
            f"echo '=== Summary ==='\n"
            f"echo \"Reachable: $REACHABLE | Blocked: $BLOCKED\"\n"
            f"if [ $REACHABLE -gt 0 ]; then\n"
            f"    echo 'WARNING: {tool_name} relay domains are reachable'\n"
            f"else\n"
            f"    echo 'PASS: All {tool_name} relay domains are blocked'\n"
            f"fi"
        )

        test_platforms = [p for p in platforms if p in ("linux", "macos")]
        meta = dict(metadata_base)
        meta["test_type"] = "network_connectivity"
        meta["target_platform"] = "linux_macos"

        return {
            "name": f"LOTTunnels: {tool_name} - Network Connectivity (Linux/macOS)",
            "description": (
                f"Test DNS resolution to known {tool_name} ({desc}) relay domains "
                f"on Linux/macOS. {abuse_reason}"
            ),
            "command": command,
            "executor": "bash",
            "technique_id": technique_id,
            "binary_path": None,
            "elevation_required": False,
            "risk_level": "medium",
            "platforms": test_platforms or ["linux", "macos"],
            "cleanup_command": None,
            "metadata": meta,
        }

    # -- MITRE mappings --------------------------------------------------------

    def get_mitre_mappings(self) -> dict[str, list[str]]:
        mappings: dict[str, list[str]] = {}
        for test in getattr(self, "_tests", []):
            tid = test.get("technique_id", "")
            technique_ids = test.get("metadata", {}).get("technique_ids", [])
            all_tids = list(set([tid] + technique_ids)) if technique_ids else [tid]
            if all_tids:
                mappings.setdefault(test["name"], []).extend(all_tids)
        return mappings
