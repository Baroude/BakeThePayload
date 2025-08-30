# ABOUTME: Collector agent implementation with AsyncHTTPClient for concurrent data fetching
# ABOUTME: Handles multi-source collection, retry logic, connection pooling, and circuit breaker patterns

import asyncio
import time
from typing import Any, Dict, List, Optional, Union

import aiohttp

from .base import BaseAgent


class AsyncHTTPClient:
    """Async HTTP client with retry logic, connection pooling, and circuit breaker."""

    def __init__(
        self,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        timeout: float = 30.0,
        max_connections: int = 100,
        failure_threshold: int = 5,
        circuit_breaker_timeout: float = 60.0,
    ):
        """Initialize AsyncHTTPClient with configuration."""
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.max_connections = max_connections
        self.failure_threshold = failure_threshold
        self.circuit_breaker_timeout = circuit_breaker_timeout

        # Circuit breaker state
        self._failure_count = 0
        self._circuit_open = False
        self._circuit_open_time = 0.0

        # Connection management
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[aiohttp.TCPConnector] = None
        self._closed = False

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session with connection pooling."""
        if self._closed:
            raise RuntimeError("HTTP client has been closed")

        if self._session is None or self._session.closed:
            self._connector = aiohttp.TCPConnector(
                limit=self.max_connections, limit_per_host=20
            )
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(
                connector=self._connector, timeout=timeout
            )
        return self._session

    def _check_circuit_breaker(self) -> None:
        """Check circuit breaker state and raise exception if open."""
        if self._circuit_open:
            if time.time() - self._circuit_open_time < self.circuit_breaker_timeout:
                raise Exception("Circuit breaker is open")
            else:
                # Reset circuit breaker
                self._circuit_open = False
                self._failure_count = 0

    def _record_failure(self) -> None:
        """Record a failure and potentially open circuit breaker."""
        self._failure_count += 1
        if self._failure_count >= self.failure_threshold:
            self._circuit_open = True
            self._circuit_open_time = time.time()

    def _record_success(self) -> None:
        """Record a success and reset failure count."""
        self._failure_count = 0

    async def _make_request(
        self, method: str, url: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """Make HTTP request with retry logic."""
        self._check_circuit_breaker()

        session = await self._get_session()
        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                async with session.request(method, url, **kwargs) as response:
                    response.raise_for_status()
                    self._record_success()
                    return await response.json()  # type: ignore[no-any-return]

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exception = e
                if attempt < self.max_retries:
                    await asyncio.sleep(
                        self.retry_delay * (2**attempt)
                    )  # Exponential backoff
                continue

        # All retries exhausted
        self._record_failure()
        if last_exception:
            raise last_exception
        raise RuntimeError("All retries failed with no recorded exception")

    async def get(self, url: str, **kwargs: Any) -> Dict[str, Any]:
        """Make HTTP GET request."""
        return await self._make_request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Dict[str, Any]:
        """Make HTTP POST request."""
        return await self._make_request("POST", url, **kwargs)

    async def fetch_multiple(
        self, urls: List[str], continue_on_error: bool = False
    ) -> List[Dict[str, Any]]:
        """Fetch multiple URLs concurrently with error handling."""

        async def fetch_single(url: str) -> Optional[Dict[str, Any]]:
            try:
                return await self.get(url)
            except Exception:
                if not continue_on_error:
                    raise
                return None

        tasks = [fetch_single(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=not continue_on_error)

        if continue_on_error:
            return [
                result
                for result in results
                if result is not None and not isinstance(result, BaseException)
            ]
        # Filter out None and BaseException types to match return type
        return [
            result
            for result in results
            if result is not None and not isinstance(result, BaseException)
        ]

    async def close(self) -> None:
        """Close the HTTP session and connector."""
        self._closed = True
        if self._session and not self._session.closed:
            await self._session.close()
        if self._connector:
            await self._connector.close()


class CollectorAgent(BaseAgent):
    """Agent responsible for collecting vulnerability data from multiple sources."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize collector agent."""
        super().__init__(config)
        self.http_client = AsyncHTTPClient(
            max_retries=config.get("max_retries", 3) if config else 3,
            retry_delay=config.get("retry_delay", 1.0) if config else 1.0,
            timeout=config.get("timeout", 30.0) if config else 30.0,
        )

    async def process(self, data: Any) -> Any:
        """Process data collection requests."""
        # Implementation will be added in subsequent phases
        pass

    async def cleanup(self) -> None:
        """Clean up collector agent resources."""
        await self.http_client.close()
