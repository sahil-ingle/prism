from typing import Any

import httpx

from ..models import IOC, IOCType, ProviderResult


class VirusTotalProvider:
    name = "VirusTotal"
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None, client: httpx.Client):
        self.api_key = api_key
        self.client = client

    def supports(self, ioc_type: IOCType) -> bool:
        return True

    def lookup(self, ioc: IOC) -> ProviderResult:
        if not self.api_key:
            return ProviderResult(
                provider=self.name,
                status="skipped",
                error="VIRUSTOTAL_API_KEY is not configured.",
            )

        if ioc.type in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}:
            endpoint = f"{self.base_url}/files/{ioc.value}"
        elif ioc.type == IOCType.DOMAIN:
            endpoint = f"{self.base_url}/domains/{ioc.value}"
        elif ioc.type == IOCType.IPV4:
            endpoint = f"{self.base_url}/ip_addresses/{ioc.value}"
        elif ioc.type == IOCType.URL:
            # VirusTotal accepts an unpadded URL-safe base64 identifier.
            import base64
            url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
            endpoint = f"{self.base_url}/urls/{url_id}"
        else:
            return ProviderResult(self.name, "skipped", error="Unsupported IOC type.")

        response = self.client.get(
            endpoint,
            headers={"x-apikey": self.api_key, "accept": "application/json"},
        )

        if response.status_code == 404:
            return ProviderResult(
                provider=self.name,
                status="not_found",
                data={},
                error="No VirusTotal object was found for this IOC.",
            )

        if response.status_code >= 400:
            return ProviderResult(
                provider=self.name,
                status="error",
                error=f"HTTP {response.status_code}: {self._error_message(response)}",
            )

        payload = response.json()
        return ProviderResult(
            provider=self.name,
            status="success",
            data=self._normalize(payload, ioc),
            raw_data=payload,
        )

    @staticmethod
    def _error_message(response: httpx.Response) -> str:
        try:
            return response.json().get("error", {}).get("message", response.text)
        except Exception:
            return response.text

    @staticmethod
    def _normalize(payload: dict[str, Any], ioc: IOC) -> dict[str, Any]:
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        reputation = attrs.get("reputation")

        data: dict[str, Any] = {
            "type": ioc.type.value,
            "reputation": reputation,
            "analysis": {
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "undetected": stats.get("undetected"),
                "harmless": stats.get("harmless"),
                "timeout": stats.get("timeout"),
            },
        }

        # Useful common fields, when present.
        for key in (
            "country",
            "as_owner",
            "asn",
            "network",
            "registrar",
            "creation_date",
            "last_modification_date",
            "last_analysis_date",
            "meaningful_name",
            "size",
            "type_description",
        ):
            if key in attrs:
                data[key] = attrs[key]

        return data
