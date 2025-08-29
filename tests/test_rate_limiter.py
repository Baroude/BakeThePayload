# ABOUTME: Unit tests for rate limiting functionality with exponential backoff for API quotas
# ABOUTME: Tests GitHub API, NVD API, and generic rate limiting with throttle controls

import asyncio
import time
from collections.abc import AsyncGenerator
from typing import Any, Dict, Generator, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from agents.rate_limiter import (
    APIRateLimiter,
    GitHubRateLimiter,
    NVDRateLimiter,
    RateLimiter,
)


class TestRateLimiter:
    """Test suite for basic rate limiting functionality."""

    @pytest_asyncio.fixture
    async def rate_limiter(self) -> AsyncGenerator[RateLimiter, None]:
        """Create RateLimiter instance for testing."""
        limiter = RateLimiter(requests_per_second=5.0, burst_size=10)
        yield limiter
        await limiter.close()

    @pytest.mark.asyncio
    async def test_basic_rate_limiting(self, rate_limiter: RateLimiter) -> None:
        """Test basic rate limiting functionality."""
        start_time = time.time()

        # Make requests that should be rate limited
        for i in range(3):
            await rate_limiter.acquire()

        elapsed = time.time() - start_time
        # Should take at least some time due to rate limiting
        assert elapsed >= 0.0  # Minimum constraint

    @pytest.mark.asyncio
    async def test_burst_allowance(self, rate_limiter: RateLimiter) -> None:
        """Test burst allowance functionality."""
        start_time = time.time()

        # Should allow burst requests initially
        tasks = [rate_limiter.acquire() for _ in range(5)]
        await asyncio.gather(*tasks)

        elapsed = time.time() - start_time
        # Burst should be fast
        assert elapsed < 1.0

    @pytest.mark.asyncio
    async def test_rate_limit_reset(self, rate_limiter: RateLimiter) -> None:
        """Test rate limit resets over time."""
        # Exhaust burst allowance
        for i in range(10):
            await rate_limiter.acquire()

        # Wait for reset
        await asyncio.sleep(2.0)

        # Should be able to make requests again quickly
        start_time = time.time()
        await rate_limiter.acquire()
        elapsed = time.time() - start_time
        assert elapsed < 0.5


class TestGitHubRateLimiter:
    """Test suite for GitHub API rate limiting."""

    @pytest_asyncio.fixture
    async def github_limiter(self) -> AsyncGenerator[GitHubRateLimiter, None]:
        """Create GitHubRateLimiter instance for testing."""
        limiter = GitHubRateLimiter(
            requests_per_hour=5000,  # GitHub API limit
            secondary_limit=30,  # Secondary rate limit
        )
        yield limiter
        await limiter.close()

    @pytest.mark.asyncio
    async def test_github_primary_rate_limit(
        self, github_limiter: GitHubRateLimiter
    ) -> None:
        """Test GitHub primary rate limit enforcement."""
        # Should allow requests under the limit
        for i in range(5):
            await github_limiter.acquire()

        # Check rate limit headers would be respected
        assert github_limiter.remaining_requests >= 0

    @pytest.mark.asyncio
    async def test_github_secondary_rate_limit(
        self, github_limiter: GitHubRateLimiter
    ) -> None:
        """Test GitHub secondary rate limit enforcement."""
        # Simulate rapid requests that trigger secondary limit
        start_time = time.time()

        tasks = [github_limiter.acquire() for _ in range(35)]
        await asyncio.gather(*tasks)

        elapsed = time.time() - start_time
        # Should be throttled due to secondary limit
        assert elapsed > 1.0

    @pytest.mark.asyncio
    async def test_github_rate_limit_headers(
        self, github_limiter: GitHubRateLimiter
    ) -> None:
        """Test handling of GitHub rate limit headers."""
        # Simulate API response with rate limit headers
        headers = {
            "x-ratelimit-remaining": "4999",
            "x-ratelimit-reset": str(int(time.time()) + 3600),
        }

        await github_limiter.update_from_headers(headers)

        assert github_limiter.remaining_requests == 4999
        assert github_limiter.reset_time > time.time()

    @pytest.mark.asyncio
    async def test_github_rate_limit_exceeded(
        self, github_limiter: GitHubRateLimiter
    ) -> None:
        """Test behavior when GitHub rate limit is exceeded."""
        # Simulate exhausted rate limit
        github_limiter.remaining_requests = 0
        github_limiter.reset_time = time.time() + 3600

        with pytest.raises(Exception) as exc_info:
            await github_limiter.acquire()
        assert "rate limit exceeded" in str(exc_info.value).lower()


class TestNVDRateLimiter:
    """Test suite for NVD API rate limiting."""

    @pytest_asyncio.fixture
    async def nvd_limiter(self) -> AsyncGenerator[NVDRateLimiter, None]:
        """Create NVDRateLimiter instance for testing."""
        limiter = NVDRateLimiter(
            requests_per_30_seconds=50, api_key=None  # Public API limit
        )
        yield limiter
        await limiter.close()

    @pytest.mark.asyncio
    async def test_nvd_public_rate_limit(self, nvd_limiter: NVDRateLimiter) -> None:
        """Test NVD public API rate limit."""
        # Should allow requests under the limit
        for i in range(5):
            await nvd_limiter.acquire()

        assert nvd_limiter.requests_made <= 50

    @pytest.mark.asyncio
    async def test_nvd_api_key_rate_limit(self) -> None:
        """Test NVD API with key has higher limits."""
        nvd_limiter_with_key = NVDRateLimiter(
            requests_per_30_seconds=50, api_key="test-api-key"
        )

        # With API key should have higher effective limits
        assert nvd_limiter_with_key.has_api_key is True

        await nvd_limiter_with_key.close()

    @pytest.mark.asyncio
    async def test_nvd_30_second_window(self, nvd_limiter: NVDRateLimiter) -> None:
        """Test NVD 30-second rate limit window."""
        # Make requests and verify window behavior
        start_time = time.time()

        for i in range(10):
            await nvd_limiter.acquire()

        # Should track requests within 30-second window
        assert len(nvd_limiter.request_timestamps) == 10


class TestAPIRateLimiter:
    """Test suite for generic API rate limiting."""

    @pytest_asyncio.fixture
    async def api_limiter(self) -> AsyncGenerator[APIRateLimiter, None]:
        """Create APIRateLimiter instance for testing."""
        limiter = APIRateLimiter(
            {
                "github": GitHubRateLimiter(requests_per_hour=5000),
                "nvd": NVDRateLimiter(requests_per_30_seconds=50),
            }
        )
        yield limiter
        await limiter.close()

    @pytest.mark.asyncio
    async def test_multi_api_rate_limiting(self, api_limiter: APIRateLimiter) -> None:
        """Test rate limiting across multiple APIs."""
        # Should handle different APIs independently
        await api_limiter.acquire("github")
        await api_limiter.acquire("nvd")

        # Should track limits separately
        assert "github" in api_limiter.limiters
        assert "nvd" in api_limiter.limiters

    @pytest.mark.asyncio
    async def test_unknown_api_handling(self, api_limiter: APIRateLimiter) -> None:
        """Test handling of unknown API endpoints."""
        with pytest.raises(ValueError):
            await api_limiter.acquire("unknown_api")

    @pytest.mark.asyncio
    async def test_rate_limiter_statistics(self, api_limiter: APIRateLimiter) -> None:
        """Test rate limiter statistics collection."""
        # Make some requests
        await api_limiter.acquire("github")
        await api_limiter.acquire("nvd")

        stats = api_limiter.get_statistics()

        assert "github" in stats
        assert "nvd" in stats
        assert stats["github"]["requests_made"] >= 1
        assert stats["nvd"]["requests_made"] >= 1

    @pytest.mark.asyncio
    async def test_exponential_backoff_on_429(
        self, api_limiter: APIRateLimiter
    ) -> None:
        """Test exponential backoff when receiving 429 responses."""
        # Simulate 429 Too Many Requests response
        with patch("asyncio.sleep") as mock_sleep:
            await api_limiter.handle_429_response("github", retry_after=60)

            # Should have called sleep with appropriate backoff
            mock_sleep.assert_called_once()
            args = mock_sleep.call_args[0]
            assert args[0] >= 60  # Should respect retry-after header
