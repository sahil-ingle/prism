from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IOCType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


@dataclass(frozen=True)
class IOC:
    value: str
    type: IOCType


@dataclass
class ProviderResult:
    provider: str
    status: str = "success"
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    # Complete provider/API payload when available. The overview uses the
    # normalized ``data`` while the All Details tab uses this untouched data.
    raw_data: Any = None


@dataclass
class Investigation:
    ioc: IOC
    results: list[ProviderResult] = field(default_factory=list)
