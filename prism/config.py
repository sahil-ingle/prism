from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _env_candidates() -> list[Path]:
    candidates: list[Path] = []

    # Explicit working-directory configuration is convenient for both source
    # installs and a portable Windows build.
    candidates.append(Path.cwd() / ".env")

    # When packaged by PyInstaller, place .env next to PRISM.exe.
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / ".env")
    else:
        candidates.append(Path(__file__).resolve().parent.parent / ".env")

    # Windows per-user fallback. This keeps secrets out of the install folder
    # when PRISM is installed under Program Files.
    appdata = os.getenv("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "PRISM" / ".env")

    return candidates


for _env_file in _env_candidates():
    if _env_file.is_file():
        load_dotenv(_env_file, override=False)


@dataclass(frozen=True)
class Settings:
    virustotal_api_key: str | None
    urlscan_api_key: str | None
    abuseipdb_api_key: str | None
    urlquery_api_key: str | None
    timeout: float = 15.0
    urlscan_results: int = 5
    urlquery_poll_interval: float = 3.0
    urlquery_poll_timeout: float = 180.0


def load_settings() -> Settings:
    timeout_raw = os.getenv("PRISM_TIMEOUT", "15")
    results_raw = os.getenv("PRISM_URLSCAN_RESULTS", "5")
    poll_interval_raw = os.getenv("PRISM_URLQUERY_POLL_INTERVAL", "3")
    poll_timeout_raw = os.getenv("PRISM_URLQUERY_POLL_TIMEOUT", "180")

    try:
        timeout = max(1.0, float(timeout_raw))
    except ValueError:
        timeout = 15.0

    try:
        results = max(1, min(20, int(results_raw)))
    except ValueError:
        results = 5

    try:
        poll_interval = max(1.0, float(poll_interval_raw))
    except ValueError:
        poll_interval = 3.0

    try:
        poll_timeout = max(poll_interval, float(poll_timeout_raw))
    except ValueError:
        poll_timeout = 180.0

    return Settings(
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
        urlscan_api_key=os.getenv("URLSCAN_API_KEY") or None,
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
        urlquery_api_key=os.getenv("URLQUERY_API_KEY") or None,
        timeout=timeout,
        urlscan_results=results,
        urlquery_poll_interval=poll_interval,
        urlquery_poll_timeout=poll_timeout,
    )
