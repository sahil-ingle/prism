import ipaddress
import re
from urllib.parse import urlparse

from .models import IOC, IOCType

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc(value: str) -> IOC:
    value = value.strip()

    if not value:
        raise ValueError("IOC cannot be empty.")

    if MD5_RE.fullmatch(value):
        return IOC(value.lower(), IOCType.MD5)

    if SHA1_RE.fullmatch(value):
        return IOC(value.lower(), IOCType.SHA1)

    if SHA256_RE.fullmatch(value):
        return IOC(value.lower(), IOCType.SHA256)

    try:
        ipaddress.ip_address(value)
        if ":" in value:
            raise ValueError("IPv6 is not supported in PRISM v0.1.")
        return IOC(value, IOCType.IPV4)
    except ValueError as exc:
        if str(exc).startswith("IPv6"):
            raise

    candidate = value
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    host = parsed.hostname

    if parsed.scheme in {"http", "https"} and host:
        # Treat explicit URLs containing a path/query/fragment as URLs.
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return IOC(value, IOCType.URL)

        # A bare hostname supplied without scheme is treated as a domain.
        if "://" not in value:
            return IOC(value.lower().rstrip("."), IOCType.DOMAIN)

        return IOC(value, IOCType.URL)

    # Conservative domain validation.
    domain = value.lower().rstrip(".")
    if len(domain) <= 253 and "." in domain:
        labels = domain.split(".")
        if all(
            0 < len(label) <= 63
            and not label.startswith("-")
            and not label.endswith("-")
            and re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels
        ):
            return IOC(domain, IOCType.DOMAIN)

    raise ValueError(
        "Unable to detect IOC type. Supported types: IPv4, domain, URL, MD5, SHA1, SHA256."
    )
