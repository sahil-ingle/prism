from __future__ import annotations

from typing import Any
from urllib.parse import quote

from prism.models import IOC, IOCType, ProviderResult


class URLScanProvider:
    name = "urlscan.io"

    def __init__(
        self,
        api_key: str | None,
        client,
        result_limit: int = 5,
        timeout: float = 15,
        ):
        self.api_key = api_key
        self.client = client
        self.result_limit = result_limit
        self.timeout = timeout

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in {
            IOCType.IPV4,
            IOCType.DOMAIN,
            IOCType.URL,
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

        try:
            query = self._build_query(ioc)

            response = self.client.get(
                "https://urlscan.io/api/v1/search/",
                params={
                    "q": query,
                    "size": self.result_limit,
                },
                headers={
                    "api-key": self.api_key,
                },
                timeout=self.timeout,
            )

            response.raise_for_status()
            search_data = response.json()

            results = search_data.get("results", [])

            if not results:
                return ProviderResult(
                    provider=self.name,
                    status="success",
                    data={
                        "query": query,
                        "found": False,
                    },
                    raw_data=search_data,
                )

            # Pick the first relevant result.
            scan = self._find_relevant_result(results, ioc)

            if not scan:
                return ProviderResult(
                    provider=self.name,
                    status="success",
                    data={
                        "query": query,
                        "found": False,
                    },
                    raw_data=search_data,
                )

            scan_id = scan.get("_id")

            if not scan_id:
                return ProviderResult(
                    provider=self.name,
                    status="error",
                    error="urlscan search result did not contain a scan ID.",
                )

            # Fetch the complete scan.
            result_response = self.client.get(
                f"https://urlscan.io/api/v1/result/{quote(scan_id)}/",
                headers={
                    "api-key": self.api_key,
                },
                timeout=self.timeout,
            )

            result_response.raise_for_status()
            result_data = result_response.json()

            return ProviderResult(
                provider=self.name,
                status="success",
                data=self._normalize_result(
                    result_data,
                    query=query,
                    scan_id=scan_id,
                ),
                raw_data=result_data,
            )

        except Exception as exc:
            return ProviderResult(
                provider=self.name,
                status="error",
                error=str(exc),
            )

    def _build_query(self, ioc: IOC) -> str:
        if ioc.type == IOCType.DOMAIN:
            return f"page.domain:{ioc.value}"

        if ioc.type == IOCType.IPV4:
            return f"page.ip:{ioc.value}"

        if ioc.type == IOCType.URL:
            return f'page.url:"{ioc.value}"'

        return f"hash:{ioc.value}"

    def _find_relevant_result(
        self,
        results: list[dict[str, Any]],
        ioc: IOC,
    ) -> dict[str, Any] | None:

        value = ioc.value.lower().rstrip(".")

        for result in results:
            page = result.get("page", {})

            domain = str(
                page.get("domain", "")
            ).lower().rstrip(".")

            ip = str(page.get("ip", ""))

            if ioc.type == IOCType.DOMAIN:
                if domain == value or domain.endswith("." + value):
                    return result

            elif ioc.type == IOCType.IPV4:
                if ip == value:
                    return result

            elif ioc.type == IOCType.URL:
                page_url = str(page.get("url", "")).lower()

                if page_url == value:
                    return result

            else:
                # Hash results are already constrained by the query.
                return result

        return None

    def _normalize_result(
        self,
        result: dict[str, Any],
        query: str,
        scan_id: str,
    ) -> dict[str, Any]:

        page = result.get("page", {})
        stats = result.get("stats", {})
        lists = result.get("lists", {})
        task = result.get("task", {})

        return {
            "query": query,
            "scan_id": scan_id,
            "scan_time": task.get("time"),

            "page": {
                "url": page.get("url"),
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "country": page.get("country"),
                "asn": page.get("asn"),
                "asnname": page.get("asnname"),
                "status": page.get("status"),
                "title": page.get("title"),
                "umbrella_rank": page.get("umbrellaRank"),
            },

            "stats": {
                "ips": stats.get("uniqIPs"),
                "countries": stats.get("uniqCountries"),
                "requests": stats.get("requests"),
                "domains": len(lists.get("domains", [])),
            },

            "tls": {
                "issuer": page.get("tlsIssuer"),
                "age_days": page.get("tlsAgeDays"),
                "valid_days": page.get("tlsValidDays"),
                "valid_from": page.get("tlsValidFrom"),
            },

            "lists": {
                "ips": lists.get("ips", []),
                "countries": lists.get("countries", []),
                "domains": lists.get("domains", []),
            },

            "result_url": f"https://urlscan.io/result/{scan_id}/",
        }