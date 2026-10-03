
from __future__ import annotations

from typing import Any

from prism.models import IOC, IOCType, ProviderResult
from prism.providers.base import ThreatProvider


class AbuseIPDBProvider(ThreatProvider):
    name = "AbuseIPDB"

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        api_key: str | None,
        client: Any,
    ):
        self.api_key = api_key
        self.client = client

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type == IOCType.IPV4

    def lookup(self, ioc: IOC) -> ProviderResult:
        if not self.api_key:
            return ProviderResult(
                provider=self.name,
                status="skipped",
                data={},
                error="ABUSEIPDB_API_KEY is not configured",
            )

        try:
            response = self.client.get(
                self.BASE_URL,
                headers={
                    "Accept": "application/json",
                    "Key": self.api_key,
                },
                params={
                    "ipAddress": ioc.value,
                    "maxAgeInDays": 90,
                },
            )

            response.raise_for_status()

            payload = response.json()
            data = payload.get("data", {}) if isinstance(payload, dict) else {}

            confidence = data.get(
                "abuseConfidenceScore",
                0,
            )

            reports = data.get(
                "totalReports",
                0,
            )

            return ProviderResult(
                provider=self.name,
                status="success",
                data={
                    "abuse_confidence_score": confidence,
                    "total_reports": reports,
                    "num_distinct_users": data.get(
                        "numDistinctUsers",
                        0,
                    ),
                    "country_code": data.get(
                        "countryCode"
                    ),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "hostnames": data.get(
                        "hostnames",
                        [],
                    ),
                    "usage_type": data.get(
                        "usageType"
                    ),
                    "is_tor": data.get("isTor"),
                    "last_reported_at": data.get(
                        "lastReportedAt"
                    ),
                },
                error=None,
                raw_data=payload,
            )

        except Exception as exc:
            return ProviderResult(
                provider=self.name,
                status="error",
                data={},
                error=str(exc),
            )

