from ..config import Settings
from ..http import build_client

from .urlquery import URLQueryProvider
from .urlscan import URLScanProvider
from .virustotal import VirusTotalProvider
from .abuseipdb import AbuseIPDBProvider


def build_providers(settings: Settings):
    # A single client is shared because the providers are lightweight HTTP
    # adapters. The engine still runs provider calls independently.
    client = build_client(settings.timeout)

    return [
        VirusTotalProvider(
            settings.virustotal_api_key,
            client,
        ),
        URLScanProvider(
            settings.urlscan_api_key,
            client,
            result_limit=settings.urlscan_results,
        ),
        URLQueryProvider(
            settings.urlquery_api_key,
            client,
            poll_interval=settings.urlquery_poll_interval,
            poll_timeout=settings.urlquery_poll_timeout,
        ),
        AbuseIPDBProvider(
            settings.abuseipdb_api_key,
            client,
        ),
    ]
