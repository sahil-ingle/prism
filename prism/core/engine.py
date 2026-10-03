from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable

from ..models import Investigation, IOC, ProviderResult
from ..providers.base import ThreatProvider


class IOCEngine:
    def __init__(self, providers: list[ThreatProvider]):
        self.providers = providers

    def investigate(
        self,
        ioc: IOC,
        on_result: Callable[[ProviderResult], None] | None = None,
    ) -> Investigation:
        """Run all applicable providers concurrently.

        Results are delivered to ``on_result`` as soon as each provider
        finishes. The returned Investigation is still complete and sorted in
        configured provider order, preserving the original CLI behaviour.
        """
        applicable = [p for p in self.providers if p.supports(ioc.type)]
        results: list[ProviderResult] = []

        with ThreadPoolExecutor(max_workers=max(1, len(applicable))) as executor:
            futures = {
                executor.submit(provider.lookup, ioc): provider
                for provider in applicable
            }

            for future in as_completed(futures):
                provider = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = ProviderResult(
                        provider=provider.name,
                        status="error",
                        error=f"{type(exc).__name__}: {exc}",
                    )

                results.append(result)

                # A provider callback is intentionally isolated from the
                # investigation itself. A UI callback must never make one
                # provider fail or prevent the remaining providers finishing.
                if on_result is not None:
                    try:
                        on_result(result)
                    except Exception:
                        pass

        order = {provider.name: index for index, provider in enumerate(self.providers)}
        results.sort(key=lambda result: order.get(result.provider, 999))
        return Investigation(ioc=ioc, results=results)
