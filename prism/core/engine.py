from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import Investigation, IOC, ProviderResult
from ..providers.base import ThreatProvider


class IOCEngine:
    def __init__(self, providers: list[ThreatProvider]):
        self.providers = providers

    def investigate(self, ioc: IOC) -> Investigation:
        applicable = [p for p in self.providers if p.supports(ioc.type)]
        results: list[ProviderResult] = []

        # Providers are independent. A slow/broken provider should not prevent
        # another provider from returning useful intelligence.
        with ThreadPoolExecutor(max_workers=max(1, len(applicable))) as executor:
            futures = {
                executor.submit(provider.lookup, ioc): provider
                for provider in applicable
            }

            for future in as_completed(futures):
                provider = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append(
                        ProviderResult(
                            provider=provider.name,
                            status="error",
                            error=f"{type(exc).__name__}: {exc}",
                        )
                    )

        order = {provider.name: index for index, provider in enumerate(self.providers)}
        results.sort(key=lambda result: order.get(result.provider, 999))
        return Investigation(ioc=ioc, results=results)
