from typing import Any

import httpx

from ..models import IOC, IOCType, ProviderResult


class URLScanProvider:
    name = "urlscan.io"
    base_url = "https://urlscan.io"

    def __init__(self, api_key: str | None, client: httpx.Client, result_limit: int = 5):
        self.api_key = api_key
        self.client = client
        self.result_limit = result_limit

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in {
            IOCType.URL,
            IOCType.DOMAIN,
            IOCType.IPV4,
            IOCType.MD5,
            IOCType.SHA1,
            IOCType.SHA256,
        }

    def lookup(self, ioc: IOC) -> ProviderResult:
        if not self.api_key:
            return ProviderResult(
                provider=self.name,
                status="skipped",
                error="URLSCAN_API_KEY is not configured.",
            )

        query = self._query(ioc)
        response = self.client.get(
            f"{self.base_url}/api/v1/search/",
            params={"q": query, "size": self.result_limit},
            headers={"api-key": self.api_key, "accept": "application/json"},
        )

        if response.status_code >= 400:
            return ProviderResult(
                provider=self.name,
                status="error",
                error=f"HTTP {response.status_code}: {self._error_message(response)}",
            )

        payload = response.json()
        results = payload.get("results", [])

        return ProviderResult(
            provider=self.name,
            status="success",
            data={
                "query": query,
                "total": payload.get("total", 0),
                "results": [self._compact_result(item) for item in results],
            },
        )

    @staticmethod
    def _query(ioc: IOC) -> str:
        if ioc.type == IOCType.URL:
            # Search historical scans by exact page URL.
            escaped = ioc.value.replace("\\", "\\\\").replace('"', '\\"')
            return f'page.url:"{escaped}"'
        if ioc.type == IOCType.DOMAIN:
            return f"domain:{ioc.value}"
        if ioc.type == IOCType.IPV4:
            return f"ip:{ioc.value}"
        # urlscan's search index exposes hash-related fields. The generic hash
        # query is intentionally kept isolated here so it can be adjusted
        # without touching the engine if their search syntax evolves.
        return f"hash:{ioc.value}"

    @staticmethod
    def _error_message(response: httpx.Response) -> str:
        try:
            payload = response.json()
            return payload.get("message") or payload.get("error") or response.text
        except Exception:
            return response.text

    @staticmethod
    def _compact_result(item: dict[str, Any]) -> dict[str, Any]:
        page = item.get("page") or {}
        task = item.get("task") or {}
        stats = item.get("stats") or {}

        return {
            "scan_id": item.get("_id"),
            "time": item.get("task", {}).get("time") or task.get("time"),
            "url": page.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "country": page.get("country"),
            "asn": page.get("asn"),
            "asnname": page.get("asnname"),
            "status": page.get("status"),
            "unique_ips": stats.get("uniqIPs"),
            "unique_countries": stats.get("uniqCountries"),
            "result_url": (
                f"https://urlscan.io/result/{item.get('_id')}/"
                if item.get("_id")
                else None
            ),
        }
