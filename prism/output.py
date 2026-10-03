"""Terminal / JSON rendering for PRISM.

Layout, top to bottom (what a SOC analyst reads first -> last):

1. Triage panel   - IOC, overall triage hint, and the signals behind it.
2. Provider table - one line per provider: status + key finding.
3. Details        - compact, grouped facts per provider (only for providers
                    that actually returned data).

All provider-supplied strings are rendered through ``rich.text.Text`` so
characters like ``[red]`` in a page title or alert name can never be parsed as
console markup (which would hide data or raise ``MarkupError``).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Investigation, ProviderResult


console = Console()

_HASH_RE = re.compile(r"[A-Fa-f0-9]{32,128}")
_STATE = {"defang": False}

LEVEL_STYLE = {
    "high": "bold red",
    "medium": "bold yellow",
    "clear": "green",
    "info": "cyan",
}

TRIAGE = {
    "high": ("HIGH RISK", "bold white on red", "red"),
    "medium": ("SUSPICIOUS", "bold black on yellow", "yellow"),
    "clear": ("NO DETECTIONS", "bold black on green", "green"),
    "none": ("NO DATA", "bold white on grey37", "grey50"),
}

HIGH_URL_VERDICTS = {"malware", "phishing", "fraud", "malicious"}


# ----------------------------------------------------------------------
# JSON
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------
def _as_int(value: Any) -> int | None:
    try:
        if value is None or value == "" or isinstance(value, bool):
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _d(value: Any) -> str | None:
    """Defang hosts/URLs for safe copy-paste into tickets (optional)."""
    if value is None:
        return None
    text = str(value)
    if not _STATE["defang"] or _HASH_RE.fullmatch(text):
        return text
    return text.replace("http", "hxxp").replace(".", "[.]")


def _parse_ts(value: Any) -> datetime | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
            n = float(value)
            return datetime.fromtimestamp(n / 1000 if n > 1e11 else n, tz=timezone.utc)
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _ago(dt: datetime) -> str:
    secs = int((datetime.now(timezone.utc) - dt).total_seconds())
    if secs < 0:
        return "in the future"
    if secs < 3600:
        return f"{max(secs // 60, 1)}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    days = secs // 86400
    if days < 60:
        return f"{days}d ago"
    if days < 730:
        return f"{days // 30}mo ago"
    return f"{days // 365}y ago"


def _when(value: Any) -> str | None:
    """'2026-10-01 12:04 UTC (2d ago)' - freshness matters when triaging."""
    if value is None or value == "":
        return None
    dt = _parse_ts(value)
    if dt is None:
        return str(value)
    return f"{dt:%Y-%m-%d %H:%M} UTC ({_ago(dt)})"


def _human_size(value: Any) -> str | None:
    n = _as_int(value)
    if n is None:
        return None
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            pretty = f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
            return f"{pretty} ({n:,} bytes)"
        size /= 1024
    return None


def _format_days(days: Any) -> str | None:
    n = _as_int(days)
    if n is None:
        return None
    if n >= 365:
        years, rest = divmod(n, 365)
        return f"{years}yr {rest}d" if rest else f"{years}yr"
    if n >= 30:
        return f"{n // 30}mo"
    return f"{n}d"


def _short(text: str | None, verbose: bool, limit: int = 110) -> str:
    line = (text or "").strip().splitlines()[0] if text and text.strip() else ""
    if verbose or len(line) <= limit:
        return line
    return line[: limit - 1] + "…"


def _count(value: Any, style_if_nonzero: str | None) -> Text | None:
    n = _as_int(value)
    if n is None:
        return None
    return Text(str(n), style=style_if_nonzero if (n and style_if_nonzero) else "")


def _yes_no(value: Any, bad_if_yes: bool = False) -> Text | None:
    if value is None:
        return None
    yes = bool(value)
    return Text("Yes" if yes else "No", style="yellow" if (yes and bad_if_yes) else "")


def _section(title: str | None, rows: list[tuple[str, Any]]) -> None:
    rows = [(k, v) for k, v in rows if v is not None and not (isinstance(v, str) and v == "")]
    if not rows:
        return
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", no_wrap=True)
    table.add_column(overflow="fold")
    for key, value in rows:
        table.add_row(key, value if isinstance(value, Text) else Text(str(value)))
    if title:
        console.print(Text(f"  {title}", style="bold"))
    console.print(Padding(table, (0, 0, 1, 4 if title else 2)))


# ----------------------------------------------------------------------
# Per-provider analysis: (key finding, triage signals)
# Signals are (level, text) where level is high | medium | clear | info.
# Only high / medium / clear influence the overall triage hint.
# ----------------------------------------------------------------------
Signals = list[tuple[str, str]]


def _analyse(result: ProviderResult, verbose: bool) -> tuple[Text, Signals]:
    if result.status == "not_found":
        return Text("No record found", style="yellow"), []
    if result.status == "skipped":
        return Text(_short(result.error, verbose) or "Skipped", style="yellow"), []
    if result.status != "success":
        return Text(_short(result.error, verbose) or "Request failed", style="red"), []

    data = result.data or {}
    name = result.provider.lower()

    if "virustotal" in name:
        return _analyse_vt(data)
    if "abuseipdb" in name:
        return _analyse_abuseipdb(data)
    if "urlquery" in name:
        return _analyse_urlquery(data)
    if "urlscan" in name:
        return _analyse_urlscan(data)
    return Text("Data returned", style="cyan"), []


def _signal_text(level: str, text: str) -> Text:
    return Text(text, style=LEVEL_STYLE[level])


def _analyse_vt(data: dict[str, Any]) -> tuple[Text, Signals]:
    stats = data.get("analysis") or {}
    mal = _as_int(stats.get("malicious")) or 0
    sus = _as_int(stats.get("suspicious")) or 0
    total = sum(
        _as_int(stats.get(k)) or 0
        for k in ("malicious", "suspicious", "harmless", "undetected")
    )
    if not total:
        return Text("No analysis stats", style="dim"), []

    text = f"{mal} malicious, {sus} suspicious (of {total} engines)"
    level = "high" if mal >= 5 else "medium" if (mal or sus) else "clear"
    return _signal_text(level, text), [(level, f"VirusTotal: {text}")]


def _analyse_abuseipdb(data: dict[str, Any]) -> tuple[Text, Signals]:
    score = _as_int(data.get("abuse_confidence_score"))
    reports = _as_int(data.get("total_reports"))
    if score is None:
        return Text("No confidence score", style="dim"), []

    level = "high" if score >= 70 else "medium" if score >= 30 else "clear"
    text = f"{score}% abuse confidence"
    if reports is not None:
        text += f", {reports} report{'s' if reports != 1 else ''}"
    return _signal_text(level, text), [(level, f"AbuseIPDB: {text}")]


def _alert_counts(data: dict[str, Any]) -> dict[str, int | None]:
    raw = data.get("alert_count")
    if isinstance(raw, dict):
        return {str(k): _as_int(v) for k, v in raw.items()}
    n = _as_int(raw)
    return {"total": n} if n is not None else {}


def _analyse_urlquery(data: dict[str, Any]) -> tuple[Text, Signals]:
    if not data.get("found", True):
        return Text("No report found", style="dim"), []

    signals: Signals = []
    verdict = data.get("verdict")
    if verdict:
        v = str(verdict).lower()
        if v in HIGH_URL_VERDICTS:
            level = "high"
        elif v == "suspicious":
            level = "medium"
        elif v in {"unknown", "unclassified"}:
            level = "info"
        else:
            level = "clear"
        text = f"Verdict: {verdict}"
        signals.append((level, f"urlquery.net: {text}"))
    else:
        level, text = "info", "Report found"

    ids = (_alert_counts(data).get("ids")) or 0
    if ids > 0:
        text += f", {ids} IDS alert{'s' if ids != 1 else ''}"
        signals.append(("medium", f"urlquery.net: {ids} IDS alert(s)"))
        level = level if level in {"high"} else "medium"
    return _signal_text(level, text), signals


def _analyse_urlscan(data: dict[str, Any]) -> tuple[Text, Signals]:
    if not data.get("found", True):
        return Text("No scan found", style="dim"), []
    page = data.get("page") or {}
    parts = [str(p) for p in (page.get("domain"), page.get("ip"), page.get("country")) if p]
    return Text(_d(" · ".join(parts)) if parts else "Scan found", style="cyan"), []


def _triage(signals: Signals) -> str:
    levels = {level for level, _ in signals}
    for level in ("high", "medium", "clear"):
        if level in levels:
            return level
    return "none"


# ----------------------------------------------------------------------
# Terminal
# ----------------------------------------------------------------------
def render_terminal(
    investigation: Investigation,
    verbose: bool = False,
    defang: bool = False,
) -> None:
    _STATE["defang"] = defang
    analysed = [(r, *_analyse(r, verbose)) for r in investigation.results]
    signals: Signals = [s for _, _, sigs in analysed for s in sigs]
    level = _triage(signals)
    label, badge_style, border = TRIAGE[level]

    # 1) Triage panel ---------------------------------------------------
    head = Table.grid(padding=(0, 2))
    head.add_column(style="dim", no_wrap=True)
    head.add_column(overflow="fold")
    head.add_row("IOC", Text(_d(investigation.ioc.value) or "", style="bold"))
    head.add_row("Type", Text(investigation.ioc.type.value.upper()))

    badge = Text(f" {label} ", style=badge_style)
    ok = sum(r.status == "success" for r in investigation.results)
    badge.append(f"   {ok}/{len(investigation.results)} providers returned data", style="dim")
    head.add_row("Triage", badge)

    reasons = [s for s in signals if s[0] == "high"] + [s for s in signals if s[0] == "medium"]
    if not reasons:
        reasons = [s for s in signals if s[0] == "clear"]
    for lvl, text in reasons:
        head.add_row("", Text("• " + text, style=LEVEL_STYLE[lvl]))
    if level in {"clear", "none"}:
        head.add_row("", Text("Absence of detections is not proof of safety.", style="dim italic"))

    console.print()
    console.print(
        Panel(
            head,
            title="[bold]PRISM[/bold] [dim]· IOC Intelligence[/dim]",
            title_align="left",
            border_style=border,
            padding=(1, 2),
        )
    )

    # 2) Provider table -------------------------------------------------
    table = Table(box=box.SIMPLE_HEAD, header_style="dim", pad_edge=False, expand=False)
    table.add_column("Provider", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Key finding", overflow="fold")
    for result, key, _ in analysed:
        status, style = _status(result.status)
        table.add_row(Text(result.provider, style="bold"), Text(status, style=style), key)
    console.print(Padding(table, (0, 0, 0, 1)))

    # 3) Details --------------------------------------------------------
    for result, _, _ in analysed:
        data = result.data or {}
        if result.status == "success":
            if not data.get("found", True):
                continue
            console.rule(Text(result.provider, style="bold cyan"), align="left", style="dim")
            _render_details(result)
        elif verbose and result.error:
            console.rule(Text(result.provider, style="bold cyan"), align="left", style="dim")
            console.print(Padding(Text(result.error, style="dim"), (0, 0, 1, 2)))

    console.print()


def _status(status: str) -> tuple[str, str]:
    return {
        "success": ("OK", "green"),
        "not_found": ("NOT FOUND", "yellow"),
        "skipped": ("SKIPPED", "yellow"),
    }.get(status, ("ERROR", "red"))


def _render_details(result: ProviderResult) -> None:
    data = result.data or {}
    name = result.provider.lower()
    if "virustotal" in name:
        _render_vt(data)
    elif "abuseipdb" in name:
        _render_abuseipdb(data)
    elif "urlquery" in name:
        _render_urlquery(data)
    elif "urlscan" in name:
        _render_urlscan(data)
    else:
        console.print_json(json.dumps(data, default=str))


# ----------------------------------------------------------------------
# Provider detail views
# ----------------------------------------------------------------------
def _render_vt(data: dict[str, Any]) -> None:
    stats = data.get("analysis") or {}
    _section("DETECTIONS", [
        ("Malicious", _count(stats.get("malicious"), "bold red")),
        ("Suspicious", _count(stats.get("suspicious"), "yellow")),
        ("Harmless", _count(stats.get("harmless"), None)),
        ("Undetected", _count(stats.get("undetected"), None)),
        ("Timeout", _count(stats.get("timeout"), None)),
        ("Reputation", data.get("reputation")),
        ("Last analysed", _when(data.get("last_analysis_date"))),
    ])
    _section("FILE", [
        ("Name", data.get("meaningful_name")),
        ("Type", data.get("type_description")),
        ("Size", _human_size(data.get("size"))),
    ])
    _section("NETWORK", [
        ("Country", data.get("country")),
        ("ASN", data.get("asn")),
        ("AS owner", data.get("as_owner")),
        ("Network", data.get("network")),
        ("Registrar", data.get("registrar")),
    ])
    _section("TIMELINE", [
        ("Created", _when(data.get("creation_date"))),
        ("Last modified", _when(data.get("last_modification_date"))),
    ])


def _render_abuseipdb(data: dict[str, Any]) -> None:
    score = _as_int(data.get("abuse_confidence_score"))
    verdict: Text | None = None
    if score is not None:
        level = "high" if score >= 70 else "medium" if score >= 30 else "clear"
        label = {"high": "HIGH", "medium": "MEDIUM", "clear": "LOW"}[level]
        verdict = Text(f"{score}%  {label}", style=LEVEL_STYLE[level])

    reports = _as_int(data.get("total_reports"))
    users = _as_int(data.get("num_distinct_users"))
    report_text = None
    if reports is not None:
        report_text = f"{reports}" + (f" from {users} distinct reporters" if users is not None else "")

    hostnames = data.get("hostnames")
    if isinstance(hostnames, list):
        hostnames = ", ".join(_d(h) or "" for h in hostnames) or None

    _section("ABUSE ASSESSMENT", [
        ("Confidence", verdict),
        ("Reports", report_text),
        ("Last reported", _when(data.get("last_reported_at"))),
        ("Tor exit", _yes_no(data.get("is_tor"), bad_if_yes=True)),
    ])
    _section("NETWORK", [
        ("Country", data.get("country_code")),
        ("ISP", data.get("isp")),
        ("Usage type", data.get("usage_type")),
        ("Domain", _d(data.get("domain"))),
        ("Hostnames", hostnames),
    ])


def _render_urlquery(data: dict[str, Any]) -> None:
    verdict = data.get("verdict")
    verdict_text: Text | None = None
    if verdict:
        v = str(verdict).lower()
        style = (
            "bold red" if v in HIGH_URL_VERDICTS
            else "bold yellow" if v in {"suspicious", "unknown", "unclassified"}
            else "green"
        )
        verdict_text = Text(str(verdict), style=style)

    submitted, final = data.get("submitted_url"), data.get("final_url")
    redirected = bool(submitted and final and submitted != final)

    counts = _alert_counts(data)
    labels = {"urlquery": "URLQuery alerts", "ids": "IDS alerts",
              "analyzer": "Analyzer alerts", "total": "Alerts"}
    alert_rows = [
        (labels.get(k, k.title()), _count(v, "yellow"))
        for k, v in counts.items() if v is not None
    ]

    _section("VERDICT", [
        ("Verdict", verdict_text),
        ("Scan status", data.get("scan_status") or data.get("status")),
        *alert_rows,
    ])
    _section("URL", [
        ("Submitted", _d(submitted)),
        ("Final", Text(_d(final) + "   (redirected)", style="yellow") if redirected and final
         else (_d(final) if final and not submitted else None)),
        ("Title", data.get("final_title")),
        ("Domain", _d(data.get("domain"))),
        ("FQDN", _d(data.get("fqdn"))),
        ("IP", _d(data.get("ip"))),
    ])

    alerts = data.get("alerts") or []
    if isinstance(alerts, list) and alerts:
        console.print(Text(f"  ALERTS ({len(alerts)})", style="bold"))
        alert_table = Table(show_header=True, box=None, padding=(0, 2), header_style="dim")
        for col in ("Severity", "Verdict", "Alert", "Sensor"):
            alert_table.add_column(col, overflow="fold")
        for alert in alerts[:10]:
            if not isinstance(alert, dict):
                continue
            alert_table.add_row(
                Text(str(alert.get("severity") or "—")),
                Text(str(alert.get("verdict") or "—")),
                Text(str(alert.get("alert") or alert.get("comment") or "—")),
                Text(str(alert.get("sensor") or "—")),
            )
        console.print(Padding(alert_table, (0, 0, 0, 4)))
        if len(alerts) > 10:
            console.print(Text(f"    … {len(alerts) - 10} more (use --json for all)", style="dim"))
        console.print()

    _section(None, [
        ("Report", data.get("result_url") or data.get("queue_url") or data.get("report_id")),
        ("Analysed", _when(data.get("date"))),
    ])


def _render_urlscan(data: dict[str, Any]) -> None:
    page = data.get("page") or {}
    stats = data.get("stats") or {}
    tls = data.get("tls") or {}

    _section("WEB IDENTITY", [
        ("URL", _d(page.get("url"))),
        ("Domain", _d(page.get("domain"))),
        ("IP", _d(page.get("ip"))),
        ("Title", page.get("title")),
        ("HTTP status", page.get("status")),
        ("Country", page.get("country")),
        ("ASN", page.get("asn")),
        ("Organisation", page.get("asnname")),
        ("Umbrella rank", page.get("umbrella_rank")),
    ])
    _section("SCAN ACTIVITY", [
        ("HTTP requests", stats.get("requests")),
        ("Unique IPs", stats.get("ips")),
        ("Unique domains", stats.get("domains")),
        ("Countries", stats.get("countries")),
        ("Scanned", _when(data.get("scan_time"))),
    ])

    age = _as_int(tls.get("age_days"))
    age_text: Text | None = None
    if age is not None:
        fresh = age <= 7
        age_text = Text(
            (_format_days(age) or "") + ("   (very new certificate)" if fresh else ""),
            style="yellow" if fresh else "",
        )
    _section("TLS", [
        ("Issuer", tls.get("issuer")),
        ("Cert age", age_text),
        ("Valid for", _format_days(tls.get("valid_days"))),
        ("Issued", _when(tls.get("valid_from"))),
    ])
    _section(None, [("Report", data.get("result_url"))])