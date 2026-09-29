from typing import Protocol

from ..models import IOC, IOCType, ProviderResult


class ThreatProvider(Protocol):
    name: str

    def supports(self, ioc_type: IOCType) -> bool:
        ...

    def lookup(self, ioc: IOC) -> ProviderResult:
        ...
