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


def render_terminal(investigation: Investigation, verbose: bool = False) -> None:
    console.print()
    console.print(
        Panel.fit(
            f"[bold]PRISM[/bold]\\n"
            f"[dim]IOC Intelligence[/dim]\\n\\n"
            f"[bold]IOC:[/bold] {investigation.ioc.value}\\n"
            f"[bold]Type:[/bold] {investigation.ioc.type.value.upper()}",
            border_style="cyan",
        )
    )

    for result in investigation.results:
        _render_provider(result, verbose)

    console.print()


def _render_provider(result: ProviderResult, verbose: bool) -> None:
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

    console.print(f"\n[bold cyan]{result.provider}[/bold cyan]  [{style}]{status}[/{style}]")

    if result.error and (verbose or result.status in {"error", "skipped", "not_found"}):
        console.print(f"  [dim]{result.error}[/dim]")

    if result.status != "success":
        return

    if result.provider == "VirusTotal":
        _render_vt(result.data)
    elif result.provider == "urlscan.io":
        _render_urlscan(result.data)
    else:
        console.print_json(json.dumps(result.data, default=str))


def _render_vt(data: dict[str, Any]) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()

    table.add_row("Reputation", str(data.get("reputation", "—")))
    analysis = data.get("analysis") or {}
    for key in ("malicious", "suspicious", "harmless", "undetected", "timeout"):
        table.add_row(key.title(), str(analysis.get(key, "—")))

    for key in ("country", "as_owner", "asn", "network", "registrar", "meaningful_name"):
        if data.get(key) is not None:
            table.add_row(key.replace("_", " ").title(), str(data[key]))

    console.print(table)


def _render_urlscan(data: dict[str, Any]) -> None:
    console.print(f"  [dim]Query:[/dim] {data.get('query')}")
    console.print(f"  [dim]Historical results:[/dim] {data.get('total', 0)}")

    for item in data.get("results", []):
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="dim")
        table.add_column()
        for key in ("time", "domain", "ip", "country", "asn", "asnname", "status"):
            if item.get(key) is not None:
                table.add_row(key.upper(), str(item[key]))
        if item.get("result_url"):
            table.add_row("RESULT", item["result_url"])
        console.print(table)
