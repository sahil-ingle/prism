import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE)


@dataclass(frozen=True)
class Settings:
    virustotal_api_key: str | None
    urlscan_api_key: str | None
    timeout: float = 15.0
    urlscan_results: int = 5


def load_settings() -> Settings:
    timeout_raw = os.getenv("PRISM_TIMEOUT", "15")
    results_raw = os.getenv("PRISM_URLSCAN_RESULTS", "5")

    try:
        timeout = float(timeout_raw)
    except ValueError:
        timeout = 15.0

    try:
        results = max(1, min(20, int(results_raw)))
    except ValueError:
        results = 5

    return Settings(
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
        urlscan_api_key=os.getenv("URLSCAN_API_KEY") or None,
        timeout=timeout,
        urlscan_results=results,
    )