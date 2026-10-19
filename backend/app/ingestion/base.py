from abc import ABC, abstractmethod
from pathlib import Path

from backend.app.core.config import settings


class BaseIngestor(ABC):
    """Abstract base class that all LOL source plugins must implement.

    To add a new LOL data source:
    1. Create a new class that extends BaseIngestor
    2. Implement all abstract methods/properties
    3. Place the file in backend/app/ingestion/
    4. The registry will auto-discover it
    """

    @property
    @abstractmethod
    def source_id(self) -> str:
        """Unique identifier for this source (e.g., 'lolbas')."""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name (e.g., 'LOLBAS')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description of this source."""
        ...

    @property
    @abstractmethod
    def repo_url(self) -> str:
        """GitHub repository URL."""
        ...

    @property
    @abstractmethod
    def platform(self) -> str:
        """Primary platform: 'windows', 'linux', 'macos', 'multi'."""
        ...

    @property
    def data_dir(self) -> Path:
        """Local directory for cloned data."""
        return settings.data_dir / self.source_id

    @abstractmethod
    async def fetch(self) -> None:
        """Clone or update the source repository data."""
        ...

    @abstractmethod
    async def parse(self) -> list[dict]:
        """Parse source data into a list of PreventionTest dicts.

        Each dict should have keys:
            - name: str
            - description: str
            - command: str
            - executor: str ("cmd" | "powershell" | "bash" | "manual")
            - technique_id: str (MITRE technique ID like "T1218.010")
            - binary_path: str | None
            - elevation_required: bool
            - risk_level: str ("low" | "medium" | "high")
            - platforms: list[str]
            - cleanup_command: str | None
            - metadata: dict (any extra source-specific fields)
        """
        ...

    @abstractmethod
    def get_mitre_mappings(self) -> dict[str, list[str]]:
        """Return mapping of test names to MITRE technique IDs.

        Returns:
            dict like {"Regsvr32 remote scriptlet": ["T1218.010"]}
        """
        ...
