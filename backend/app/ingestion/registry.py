from backend.app.ingestion.base import BaseIngestor
from backend.app.ingestion.lolbas import LOLBASIngestor
from backend.app.ingestion.loldrivers import LOLDriversIngestor
from backend.app.ingestion.lolrmm import LOLRMMIngestor
from backend.app.ingestion.atomic_red_team import AtomicRedTeamIngestor
from backend.app.ingestion.loobins import LOOBinsIngestor
from backend.app.ingestion.lolapi import LOLAPIIngestor
from backend.app.ingestion.loltunnels import LOTTunnelsIngestor
from backend.app.ingestion.persistence_info import PersistenceInfoIngestor
from backend.app.ingestion.gtfobins import GTFOBinsIngestor
from backend.app.ingestion.loas import LOASIngestor
from backend.app.ingestion.sysinternals import SysinternalsIngestor


class IngestorRegistry:
    """Registry that manages all available data source ingestors."""

    def __init__(self):
        self._ingestors: dict[str, BaseIngestor] = {}

    def register(self, ingestor: BaseIngestor) -> None:
        self._ingestors[ingestor.source_id] = ingestor

    def get(self, source_id: str) -> BaseIngestor | None:
        return self._ingestors.get(source_id)

    def get_all(self) -> list[BaseIngestor]:
        return list(self._ingestors.values())

    def source_ids(self) -> list[str]:
        return list(self._ingestors.keys())


_registry: IngestorRegistry | None = None


def get_registry() -> IngestorRegistry:
    global _registry
    if _registry is None:
        _registry = IngestorRegistry()
        # Auto-register built-in ingestors
        _registry.register(LOLBASIngestor())
        _registry.register(LOLDriversIngestor())
        _registry.register(LOLRMMIngestor())
        _registry.register(AtomicRedTeamIngestor())
        _registry.register(LOOBinsIngestor())
        _registry.register(LOLAPIIngestor())
        _registry.register(LOTTunnelsIngestor())
        _registry.register(PersistenceInfoIngestor())
        _registry.register(GTFOBinsIngestor())
        _registry.register(LOASIngestor())
        _registry.register(SysinternalsIngestor())
    return _registry
