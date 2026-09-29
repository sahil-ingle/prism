import httpx


def build_client(timeout: float) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
        headers={"User-Agent": "PRISM/0.1.0"},
    )
