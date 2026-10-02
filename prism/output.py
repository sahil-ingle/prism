import json
from typing import Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import Investigation, ProviderResult


console = Console()


def render_json(investigation: Investigation) -> None:
    payload: dict[str, Any] = {
        "ioc": investigation.ioc.value,
        "type": investigation.ioc.type.value,
        "providers": [
            {
                "provider": result.provider,
                "status": result.status,
                "data": result.data,
                "error": result.error,
            }
            for result in investigation.results
        ],
    }

    console.print_json(json.dumps(payload, default=str))


def render_terminal( investigation: Investigation, verbose: bool = False, ) -> None:
    console.print()

    console.print(
        Panel.fit(
            f"[bold]PRISM[/bold]\n"
            f"[dim]IOC Intelligence[/dim]\n\n"
            f"[bold]IOC:[/bold] {investigation.ioc.value}\n"
            f"[bold]Type:[/bold] {investigation.ioc.type.value.upper()}",
            border_style="cyan",
        )
    )

    for result in investigation.results:
        _render_provider(result, verbose)

    console.print()


def _render_provider(
    result: ProviderResult,
    verbose: bool,
    )-> None:
    if result.status == "success":
        style = "green"
        status = "OK"
    elif result.status == "not_found":
        style = "yellow"
        status = "NOT FOUND"
    elif result.status == "skipped":
        style = "yellow"
        status = "SKIPPED"
    else:
        style = "red"
        status = "ERROR"

    console.print(
        f"\n[bold cyan]{result.provider}[/bold cyan]  "
        f"[{style}]{status}[/{style}]"
    )

    if result.error and (
        verbose
        or result.status in {"error", "skipped", "not_found"}
    ):
        console.print(f"  [dim]{result.error}[/dim]")

    if result.status != "success":
        return

    if result.provider == "VirusTotal":
        _render_vt(result.data)

    elif result.provider == "urlscan.io":
        _render_urlscan(result.data)

    elif result.provider == "AbuseIPDB":
        _render_abuseipdb(result.data)

    else:
        console.print_json(
            json.dumps(result.data, default=str)
        )


def _render_vt(data: dict[str, Any]) -> None:
    table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
    )

    table.add_column(style="dim")
    table.add_column()

    table.add_row(
        "Reputation",
        str(data.get("reputation", "—")),
    )

    analysis = data.get("analysis") or {}

    for key in (
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "timeout",
    ):
        table.add_row(
            key.title(),
            str(analysis.get(key, "—")),
        )

    for key in (
        "country",
        "as_owner",
        "asn",
        "network",
        "registrar",
        "meaningful_name",
    ):
        if data.get(key) is not None:
            table.add_row(
                key.replace("_", " ").title(),
                str(data[key]),
            )

    console.print(table)


def _render_abuseipdb(data: dict[str, Any]) -> None:
    table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
    )

    table.add_column(
        style="dim",
        no_wrap=True,
    )
    table.add_column()

    confidence = data.get("abuse_confidence_score")
    reports = data.get("total_reports")
    users = data.get("num_distinct_users")

    # Determine display status from AbuseIPDB score.
    if confidence is None:
        confidence_display = "—"
    else:
        confidence_display = f"{confidence}%"

    if confidence is None:
        risk = "UNKNOWN"
        risk_style = "yellow"
    elif confidence >= 70:
        risk = "HIGH"
        risk_style = "red"
    elif confidence >= 30:
        risk = "MEDIUM"
        risk_style = "yellow"
    else:
        risk = "LOW"
        risk_style = "green"

    table.add_row(
        "Abuse Confidence",
        confidence_display,
    )

    table.add_row(
        "Risk",
        f"[{risk_style}]{risk}[/{risk_style}]",
    )

    table.add_row(
        "Reports",
        str(reports if reports is not None else "—"),
    )

    table.add_row(
        "Distinct Reporters",
        str(users if users is not None else "—"),
    )

    fields = [
        ("Country", data.get("country_code")),
        ("ISP", data.get("isp")),
        ("Domain", data.get("domain")),
        ("Usage Type", data.get("usage_type")),
        ("Tor", data.get("is_tor")),
        ("Last Reported", data.get("last_reported_at")),
    ]

    for label, value in fields:
        if value is not None:
            table.add_row(
                label,
                str(value),
            )

    console.print(table)


def _render_urlscan(data: dict[str, Any]) -> None:
    if not data.get("found", True):
        console.print(
            "  [dim]No relevant scan found.[/dim]"
        )
        return

    console.print()

    query = data.get("query")

    if query:
        console.print(
            f"  [dim]Query:[/dim] {query}"
        )

    page = data.get("page", {})
    stats = data.get("stats", {})
    tls = data.get("tls", {})

    table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
    )

    table.add_column(
        style="dim",
        no_wrap=True,
    )
    table.add_column()

    fields = [
        ("URL", page.get("url")),
        ("DOMAIN", page.get("domain")),
        ("IP", page.get("ip")),
        ("COUNTRY", page.get("country")),
        ("ASN", page.get("asn")),
        ("ORGANIZATION", page.get("asnname")),
        ("STATUS", page.get("status")),
    ]

    for label, value in fields:
        if value is not None:
            table.add_row(
                label,
                str(value),
            )

    console.print(table)
    console.print()

    console.print("  [bold]IMPRINT[/bold]")

    imprint = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
    )

    imprint.add_column(
        style="dim",
        no_wrap=True,
    )
    imprint.add_column()

    stats_fields = [
        ("IPs", stats.get("ips")),
        ("Countries", stats.get("countries")),
        ("Domains", stats.get("domains")),
        ("HTTP Requests", stats.get("requests")),
    ]

    for label, value in stats_fields:
        if value is not None:
            imprint.add_row(
                label,
                str(value),
            )

    console.print(imprint)

    umbrella_rank = page.get("umbrella_rank")

    if umbrella_rank is not None:
        console.print(
            f"  Umbrella Rank  {umbrella_rank}"
        )

    if any(value is not None for value in tls.values()):
        console.print()
        console.print("  [bold]TLS[/bold]")

        tls_table = Table(
            show_header=False,
            box=None,
            padding=(0, 2),
        )

        tls_table.add_column(
            style="dim",
            no_wrap=True,
        )
        tls_table.add_column()

        tls_fields = [
            ("Issuer", tls.get("issuer")),
            ("Age", _format_days(tls.get("age_days"))),
            ("Valid", _format_days(tls.get("valid_days"))),
            ("Issued", tls.get("valid_from")),
        ]

        for label, value in tls_fields:
            if value is not None:
                tls_table.add_row(
                    label,
                    str(value),
                )

        console.print(tls_table)

    result_url = data.get("result_url")

    if result_url:
        console.print()
        console.print(
            f"  [dim]Result:[/dim] {result_url}"
        )


def _format_days(days: int | None) -> str | None:
    if days is None:
        return None

    if days >= 365:
        years = days // 365
        remaining = days % 365

        if remaining:
            return f"{years}yr {remaining}d"

        return f"{years}yr"

    if days >= 30:
        months = days // 30
        return f"{months}mo"

    return f"{days}d"

