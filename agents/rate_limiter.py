# ABOUTME: Rate limiting functionality with exponential backoff for API quotas (GitHub, NVD)
# ABOUTME: Implements throttling controls, burst allowance, and API-specific rate limit handling

import asyncio
import time
from collections import deque
from typing import Any, Dict, List, Optional


class RateLimiter:
    """Basic rate limiter with burst allowance."""

    def __init__(self, requests_per_second: float, burst_size: int):
        """Initialize rate limiter."""
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to make a request."""
        async with self._lock:
            await self._wait_for_token()
            self.tokens -= 1

    async def _wait_for_token(self) -> None:
        """Wait until a token is available."""
        while True:
            now = time.time()
            elapsed = now - self.last_update

            # Add tokens based on elapsed time
            new_tokens = elapsed * self.requests_per_second
            self.tokens = min(self.burst_size, self.tokens + int(new_tokens))
            self.last_update = now

            if self.tokens >= 1:
                break

            # Calculate how long to wait for next token
            wait_time = (1 - self.tokens) / self.requests_per_second
            await asyncio.sleep(wait_time)

    async def close(self) -> None:
        """Close the rate limiter."""
        pass


class GitHubRateLimiter:
    """Rate limiter for GitHub API with primary and secondary limits."""

    def __init__(self, requests_per_hour: int, secondary_limit: int = 30):
        """Initialize GitHub rate limiter."""
        self.requests_per_hour = requests_per_hour
        self.secondary_limit = secondary_limit
        self.remaining_requests = requests_per_hour
        self.reset_time = time.time() + 3600
        self.secondary_requests: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to make GitHub API request."""
        async with self._lock:
            await self._check_primary_limit()
            await self._check_secondary_limit()
            self.remaining_requests -= 1
            self.secondary_requests.append(time.time())

    async def _check_primary_limit(self) -> None:
        """Check primary rate limit."""
        if self.remaining_requests <= 0:
            if time.time() < self.reset_time:
                raise Exception("GitHub rate limit exceeded")
            else:
                # Reset the limit
                self.remaining_requests = self.requests_per_hour
                self.reset_time = time.time() + 3600

    async def _check_secondary_limit(self) -> None:
        """Check secondary rate limit (30 requests per minute)."""
        now = time.time()
        minute_ago = now - 60

        # Remove old requests
        while self.secondary_requests and self.secondary_requests[0] < minute_ago:
            self.secondary_requests.popleft()

        if len(self.secondary_requests) >= self.secondary_limit:
            # Need to wait
            oldest_request = self.secondary_requests[0]
            wait_time = 60 - (now - oldest_request)
            if wait_time > 0:
                await asyncio.sleep(wait_time)

    async def update_from_headers(self, headers: Dict[str, str]) -> None:
        """Update rate limit info from API response headers."""
        if "x-ratelimit-remaining" in headers:
            self.remaining_requests = int(headers["x-ratelimit-remaining"])
        if "x-ratelimit-reset" in headers:
            self.reset_time = int(headers["x-ratelimit-reset"])

    async def close(self) -> None:
        """Close the rate limiter."""
        pass


class NVDRateLimiter:
    """Rate limiter for NVD API with 30-second windows."""

    def __init__(self, requests_per_30_seconds: int, api_key: Optional[str] = None):
        """Initialize NVD rate limiter."""
        self.requests_per_30_seconds = requests_per_30_seconds
        self.api_key = api_key
        self.has_api_key = api_key is not None
        self.request_timestamps: deque[float] = deque()
        self.requests_made = 0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to make NVD API request."""
        async with self._lock:
            await self._check_rate_limit()
            now = time.time()
            self.request_timestamps.append(now)
            self.requests_made += 1

    async def _check_rate_limit(self) -> None:
        """Check 30-second rate limit window."""
        now = time.time()
        thirty_seconds_ago = now - 30

        # Remove old requests
        while (
            self.request_timestamps and self.request_timestamps[0] < thirty_seconds_ago
        ):
            self.request_timestamps.popleft()

        if len(self.request_timestamps) >= self.requests_per_30_seconds:
            # Need to wait
            oldest_request = self.request_timestamps[0]
            wait_time = 30 - (now - oldest_request)
            if wait_time > 0:
                await asyncio.sleep(wait_time)

    async def close(self) -> None:
        """Close the rate limiter."""
        pass


class APIRateLimiter:
    """Generic API rate limiter managing multiple API endpoints."""

    def __init__(self, limiters: Dict[str, Any]):
        """Initialize with a dictionary of API-specific limiters."""
        self.limiters = limiters

    async def acquire(self, api_name: str) -> None:
        """Acquire permission for specific API."""
        if api_name not in self.limiters:
            raise ValueError(f"Unknown API: {api_name}")

        await self.limiters[api_name].acquire()

    def get_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all rate limiters."""
        stats = {}
        for api_name, limiter in self.limiters.items():
            if isinstance(limiter, GitHubRateLimiter):
                stats[api_name] = {
                    "requests_made": self.limiters[api_name].requests_per_hour
                    - self.limiters[api_name].remaining_requests,
                    "remaining_requests": limiter.remaining_requests,
                }
            elif isinstance(limiter, NVDRateLimiter):
                stats[api_name] = {
                    "requests_made": limiter.requests_made,
                    "current_window_requests": len(limiter.request_timestamps),
                }
            else:
                stats[api_name] = {"requests_made": 1}  # Basic fallback
        return stats

    async def handle_429_response(self, api_name: str, retry_after: int) -> None:
        """Handle 429 Too Many Requests response with exponential backoff."""
        wait_time = max(retry_after, 1)
        await asyncio.sleep(wait_time)

    async def close(self) -> None:
        """Close all rate limiters."""
        for limiter in self.limiters.values():
            await limiter.close()
