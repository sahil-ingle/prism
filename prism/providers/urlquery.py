from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

import httpx

from ..models import IOC, IOCType, ProviderResult
from .base import ThreatProvider


class URLQueryProvider:
    """URLQuery public API integration.

    URLQuery exposes three useful API flows:
      * reputation check for domains/IPs/URLs
      * report search for previously analyzed IOCs
      * URL submission -> queue polling -> report retrieval

    For URLs, PRISM first tries to reuse an existing URLQuery report. If no
    matching report is found, it submits the URL for a fresh sandbox scan.
    """

    name = "urlquery.net"
    base_url = "https://api.urlquery.net"

    def __init__(
        self,
        api_key: str | None,
        client: httpx.Client,
        poll_interval: float = 3.0,
        poll_timeout: float = 90.0,
    ):
        self.api_key = api_key
        self.client = client
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout

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
                data={},
                error="URLQUERY_API_KEY is not configured.",
            )

        try:
            if ioc.type == IOCType.DOMAIN:
                return self._lookup_domain(ioc)

            if ioc.type == IOCType.IPV4:
                return self._lookup_ip(ioc)

            if ioc.type == IOCType.URL:
                return self._lookup_url(ioc)

            # Hashes are useful as report-search terms. URLQuery is primarily
            # a web-analysis service, so do not pretend it has file reputation.
            return self._search_reports(ioc)

        except httpx.HTTPStatusError as exc:
            response = exc.response
            return ProviderResult(
                provider=self.name,
                status="error",
                data={},
                error=self._http_error(response),
            )
        except Exception as exc:
            return ProviderResult(
                provider=self.name,
                status="error",
                data={},
                error=f"{type(exc).__name__}: {exc}",
            )

    def _headers(self) -> dict[str, str]:
        return {
            "X-APIKEY": self.api_key or "",
            "Accept": "application/json",
            "User-Agent": "PRISM/0.1.0",
        }

    def _reputation(self, ioc: IOC) -> ProviderResult:
        response = self.client.get(
            f"{self.base_url}/public/v1/reputation/check/",
            params={"query": ioc.value},
            headers=self._headers(),
        )
        response.raise_for_status()

        payload = response.json()

        # Current public API returns {url, verdict}; keep any additional
        # fields so PRISM does not throw away useful future API fields.
        data = dict(payload) if isinstance(payload, dict) else {}

        data.setdefault("query", ioc.value)
        data.setdefault("verdict", "unknown")
        data["source"] = "reputation"

        return ProviderResult(
            provider=self.name,
            status="success",
            data=data,
            raw_data=payload,
        )

    def _lookup_domain(self, ioc: IOC) -> ProviderResult:
        # Reputation is useful even when there is no sandbox report.
        reputation = self._reputation(ioc)

        # Prefer an existing report before creating a new sandbox job.
        existing = self._search_reports(ioc)
        if existing.status == "success" and existing.data.get("found"):
            existing.data["reputation"] = reputation.data
            existing.raw_data = {
                "report": existing.raw_data,
                "reputation": reputation.raw_data,
            }
            return existing

        # URLQuery's sandbox accepts URLs, so turn a bare domain into a
        # canonical URL when a fresh scan is required.
        scanned = self._submit_and_scan(f"https://{ioc.value}")
        if scanned.status == "success":
            scanned.data["reputation"] = reputation.data
            scanned.raw_data = {
                "report": scanned.raw_data,
                "reputation": reputation.raw_data,
            }

        return scanned

    def _lookup_ip(self, ioc: IOC) -> ProviderResult:
        # URLQuery's documented reputation API accepts IPs directly. Searching
        # existing reports can provide richer context without submitting an
        # arbitrary IP URL to the sandbox.
        reputation = self._reputation(ioc)

        existing = self._search_reports(ioc)
        if existing.status == "success" and existing.data.get("found"):
            existing.data["reputation"] = reputation.data
            existing.raw_data = {
                "report": existing.raw_data,
                "reputation": reputation.raw_data,
            }
            return existing

        return reputation

    def _lookup_url(self, ioc: IOC) -> ProviderResult:
        # Reuse an existing report first. This avoids creating a new sandbox
        # job every time the same URL is looked up.
        existing = self._search_reports(ioc)

        if existing.status == "success" and existing.data.get("found"):
            return existing

        # No existing report: submit the URL for sandbox analysis.
        return self._submit_and_scan(ioc.value)

    def _search_reports(self, ioc: IOC) -> ProviderResult:
        response = self.client.get(
            f"{self.base_url}/public/v1/search/reports/",
            params={
                "query": ioc.value,
                "limit": 5,
                "offset": 0,
            },
            headers=self._headers(),
        )
        response.raise_for_status()

        payload = response.json()
        reports = payload.get("reports", []) if isinstance(payload, dict) else []

        if not reports:
            return ProviderResult(
                provider=self.name,
                status="success",
                data={
                    "query": ioc.value,
                    "found": False,
                    "source": "report_search",
                },
                raw_data=payload,
            )

        # Prefer a report whose URL/domain/hash actually contains the IOC.
        selected = self._select_report(reports, ioc)

        if selected is None:
            return ProviderResult(
                provider=self.name,
                status="success",
                data={
                    "query": ioc.value,
                    "found": False,
                    "source": "report_search",
                },
                raw_data=payload,
            )

        report_id = selected.get("report_id")
        if not report_id:
            return ProviderResult(
                provider=self.name,
                status="success",
                data={
                    "query": ioc.value,
                    "found": True,
                    "source": "report_search",
                    "report": selected,
                },
                raw_data=selected,
            )

        report = self._get_report(report_id)
        return ProviderResult(
            provider=self.name,
            status="success",
            data=self._normalize_report(
                report,
                query=ioc.value,
                source="report_search",
            ),
            raw_data=report,
        )

    def _submit_and_scan(self, url: str) -> ProviderResult:
        response = self.client.post(
            f"{self.base_url}/public/v1/submit/url",
            headers={
                **self._headers(),
                "Content-Type": "application/json",
            },
            json={
                "url": url,
                "access": "public",
            },
        )
        response.raise_for_status()

        queue = response.json()
        queue_id = queue.get("queue_id")
        status = str(queue.get("status", "")).lower()

        if not queue_id:
            return ProviderResult(
                provider=self.name,
                status="error",
                data=queue if isinstance(queue, dict) else {},
                error="URLQuery submission did not return a queue_id.",
            )

        if status in {"failed", "error"}:
            return ProviderResult(
                provider=self.name,
                status="error",
                data={
                    "query": url,
                    "queue_id": queue_id,
                    "queue_status": status,
                },
                error="URLQuery rejected or failed the submission.",
            )

        deadline = time.monotonic() + self.poll_timeout
        last_queue = queue

        while time.monotonic() < deadline:
            if status == "done":
                break

            time.sleep(self.poll_interval)

            status_response = self.client.get(
                f"{self.base_url}/public/v1/submit/status/{quote(queue_id, safe='')}",
                headers=self._headers(),
            )
            status_response.raise_for_status()
            last_queue = status_response.json()
            status = str(last_queue.get("status", "")).lower()

            if status in {"failed", "error"}:
                return ProviderResult(
                    provider=self.name,
                    status="error",
                    data={
                        "query": url,
                        "queue_id": queue_id,
                        "queue_status": status,
                    },
                    error="URLQuery sandbox processing failed.",
                )

        if status != "done":
            return ProviderResult(
                provider=self.name,
                status="processing",
                data={
                    "query": url,
                    "source": "submission",
                    "scan_status": status or "processing",
                    "queue_id": queue_id,
                    "queue_url": f"https://urlquery.net/queue/{queue_id}",
                },
                error="URLQuery is still processing this submission. Increase PRISM_URLQUERY_POLL_TIMEOUT if you want PRISM to wait longer for the final report.",
            )

        report_id = last_queue.get("report_id")
        if not report_id:
            return ProviderResult(
                provider=self.name,
                status="success",
                data={
                    "query": url,
                    "source": "submission",
                    "scan_status": "done",
                    "queue_id": queue_id,
                },
                error="URLQuery completed the queue but did not return a report_id.",
            )

        report = self._get_report(report_id)

        return ProviderResult(
            provider=self.name,
            status="success",
            data=self._normalize_report(
                report,
                query=url,
                source="submission",
                queue_id=queue_id,
            ),
            raw_data={
                "submission": last_queue,
                "report": report,
            },
        )

    def _get_report(self, report_id: str) -> dict[str, Any]:
        response = self.client.get(
            f"{self.base_url}/public/v1/report/{quote(report_id, safe='')}",
            headers=self._headers(),
        )
        response.raise_for_status()
        payload = response.json()

        if not isinstance(payload, dict):
            raise ValueError("URLQuery report response was not a JSON object.")

        return payload

    @staticmethod
    def _select_report(
        reports: list[dict[str, Any]],
        ioc: IOC,
    ) -> dict[str, Any] | None:
        value = ioc.value.lower().rstrip("/").rstrip(".")

        for report in reports:
            if URLQueryProvider._report_matches(report, value, ioc.type):
                return report

        # Search is already constrained by the API. If it returned reports
        # but none can be matched confidently, do not associate the wrong
        # report with the IOC.
        return None

    @staticmethod
    def _report_matches(
        report: dict[str, Any],
        value: str,
        ioc_type: IOCType,
    ) -> bool:
        url_obj = report.get("url") or {}
        final_obj = report.get("final") or {}
        final_url = final_obj.get("url") or {}

        candidates = {
            str(url_obj.get("addr", "")).lower().rstrip("/"),
            str(url_obj.get("fqdn", "")).lower().rstrip("."),
            str(url_obj.get("domain", "")).lower().rstrip("."),
            str(final_url.get("addr", "")).lower().rstrip("/"),
            str(final_url.get("fqdn", "")).lower().rstrip("."),
            str(final_url.get("domain", "")).lower().rstrip("."),
        }

        if ioc_type == IOCType.DOMAIN:
            return any(
                candidate == value or candidate.endswith("." + value)
                for candidate in candidates
                if candidate
            )

        if ioc_type == IOCType.IPV4:
            ip = str((report.get("ip") or {}).get("addr", ""))
            return ip == value

        if ioc_type == IOCType.URL:
            return any(
                candidate == value
                for candidate in candidates
                if candidate
            )

        # Hash searches can return reports where the hash appears in the
        # detailed report, but the overview may not expose it. Let the search
        # result stand for hash IOCs.
        return True

    @staticmethod
    def _normalize_report(
        report: dict[str, Any],
        query: str,
        source: str,
        queue_id: str | None = None,
    ) -> dict[str, Any]:
        url_obj = report.get("url") or {}
        final_obj = report.get("final") or {}
        final_url = final_obj.get("url") or {}
        ip_obj = report.get("ip") or {}
        stats = report.get("stats") or {}
        alert_count = stats.get("alert_count") or {}

        alerts = []
        sensors = report.get("sensors") or {}

        for alert in sensors.get("urlquery", []) or []:
            alerts.append({
                "sensor": alert.get("sensor_name"),
                "alert": alert.get("alert"),
                "verdict": alert.get("verdict"),
                "severity": alert.get("severity"),
                "comment": alert.get("comment"),
                "tags": alert.get("tags", []),
            })

        for alert in sensors.get("analyzer", []) or []:
            alerts.append({
                "sensor": alert.get("sensor_name"),
                "alert": alert.get("alert"),
                "verdict": alert.get("verdict"),
                "severity": alert.get("severity"),
                "comment": alert.get("comment"),
                "tags": [],
            })

        return {
            "query": query,
            "source": source,
            "found": True,
            "report_id": report.get("report_id"),
            "status": report.get("status"),
            "date": report.get("date"),
            "submitted_url": url_obj.get("addr"),
            "domain": url_obj.get("domain"),
            "fqdn": url_obj.get("fqdn"),
            "ip": ip_obj.get("addr"),
            "final_url": final_url.get("addr"),
            "final_title": final_obj.get("title"),
            "verdict": URLQueryProvider._derive_verdict(alerts),
            "alert_count": {
                "urlquery": alert_count.get("urlquery"),
                "ids": alert_count.get("ids"),
                "analyzer": alert_count.get("analyzer"),
            },
            "alerts": alerts,
            "result_url": (
                f"https://urlquery.net/report/{report.get('report_id')}"
                if report.get("report_id")
                else None
            ),
            **({"queue_id": queue_id} if queue_id else {}),
        }

    @staticmethod
    def _derive_verdict(alerts: list[dict[str, Any]]) -> str:
        verdicts = {
            str(alert.get("verdict", "")).strip().lower()
            for alert in alerts
            if alert.get("verdict")
        }

        if not verdicts:
            return "unknown"

        for value in ("malware", "phishing", "fraud", "malicious"):
            if value in verdicts:
                return value

        if "suspicious" in verdicts:
            return "suspicious"

        return next(iter(verdicts))

    @staticmethod
    def _http_error(response: httpx.Response) -> str:
        try:
            payload = response.json()
            if isinstance(payload, dict):
                message = payload.get("message") or payload.get("error")
                if message:
                    return f"HTTP {response.status_code}: {message}"
        except Exception:
            pass

        return f"HTTP {response.status_code}: {response.text[:300]}"
