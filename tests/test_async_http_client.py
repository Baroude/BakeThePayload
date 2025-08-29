# ABOUTME: Unit tests for AsyncHTTPClient infrastructure with retry logic and connection pooling
# ABOUTME: Tests concurrent fetching, error handling, circuit breakers, and graceful degradation

import asyncio
from typing import Any, AsyncGenerator, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
import pytest_asyncio
from aioresponses import aioresponses

from agents.collector import AsyncHTTPClient


class TestAsyncHTTPClient:
    """Test suite for AsyncHTTPClient infrastructure."""

    @pytest_asyncio.fixture
    async def client(self) -> AsyncGenerator[AsyncHTTPClient, None]:
        """Create AsyncHTTPClient instance for testing."""
        client = AsyncHTTPClient(
            max_retries=3, retry_delay=0.1, timeout=5.0, max_connections=10
        )
        yield client
        await client.close()

    @pytest.mark.asyncio
    async def test_successful_get_request(self, client: AsyncHTTPClient) -> None:
        """Test successful HTTP GET request."""
        url = "https://api.example.com/data"
        expected_data = {"test": "data"}

        with aioresponses() as mock_resp:
            mock_resp.get(url, payload=expected_data)

            result = await client.get(url)

            assert result == expected_data

    @pytest.mark.asyncio
    async def test_retry_logic_on_failure(self, client: AsyncHTTPClient) -> None:
        """Test retry logic when requests fail."""
        url = "https://api.example.com/data"
        expected_data = {"test": "data"}

        with aioresponses() as mock_resp:
            # First two calls fail, third succeeds
            mock_resp.get(url, status=500)
            mock_resp.get(url, status=503)
            mock_resp.get(url, payload=expected_data)

            result = await client.get(url)

            assert result == expected_data

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self, client: AsyncHTTPClient) -> None:
        """Test behavior when max retries are exceeded."""
        url = "https://api.example.com/data"

        with aioresponses() as mock_resp:
            # All attempts fail
            mock_resp.get(url, status=500, repeat=True)

            with pytest.raises(aiohttp.ClientResponseError):
                await client.get(url)

    @pytest.mark.asyncio
    async def test_connection_pooling(self, client: AsyncHTTPClient) -> None:
        """Test connection pooling functionality."""
        urls = [f"https://api.example.com/data/{i}" for i in range(5)]

        with aioresponses() as mock_resp:
            for url in urls:
                mock_resp.get(url, payload={"id": url.split("/")[-1]})

            # Make concurrent requests
            tasks = [client.get(url) for url in urls]
            results = await asyncio.gather(*tasks)

            assert len(results) == 5
            assert all("id" in result for result in results)

    @pytest.mark.asyncio
    async def test_timeout_handling(self, client: AsyncHTTPClient) -> None:
        """Test timeout handling."""
        url = "https://api.example.com/slow"

        with aioresponses() as mock_resp:
            mock_resp.get(
                url,
                exception=OSError("Connection timeout"),
            )

            with pytest.raises((OSError, aiohttp.ClientError)):
                await client.get(url)

    @pytest.mark.asyncio
    async def test_circuit_breaker_activation(self, client: AsyncHTTPClient) -> None:
        """Test circuit breaker activation after repeated failures."""
        url = "https://api.example.com/data"

        # Configure client with low failure threshold for testing
        client.failure_threshold = 2
        client.circuit_breaker_timeout = 1.0

        with aioresponses() as mock_resp:
            mock_resp.get(url, status=500, repeat=True)

            # First few requests should trigger circuit breaker
            with pytest.raises(aiohttp.ClientResponseError):
                await client.get(url)
            with pytest.raises(aiohttp.ClientResponseError):
                await client.get(url)

            # Circuit breaker should now be open
            with pytest.raises(Exception) as exc_info:
                await client.get(url)
            assert "circuit breaker" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_graceful_degradation(self, client: AsyncHTTPClient) -> None:
        """Test graceful degradation when some endpoints fail."""
        urls = [
            "https://api.example.com/data/1",
            "https://api.example.com/data/2",
            "https://api.example.com/data/3",
        ]

        with aioresponses() as mock_resp:
            mock_resp.get(urls[0], payload={"id": "1"})
            mock_resp.get(urls[1], status=500)
            mock_resp.get(urls[2], payload={"id": "3"})

            results = await client.fetch_multiple(urls, continue_on_error=True)

            assert len(results) == 2
            assert results[0]["id"] == "1"
            assert results[1]["id"] == "3"

    @pytest.mark.asyncio
    async def test_post_request_with_data(self, client: AsyncHTTPClient) -> None:
        """Test POST request with JSON data."""
        url = "https://api.example.com/submit"
        post_data = {"name": "test", "value": 123}
        expected_response = {"status": "created", "id": "abc123"}

        with aioresponses() as mock_resp:
            mock_resp.post(url, payload=expected_response)

            result = await client.post(url, json=post_data)

            assert result == expected_response

    @pytest.mark.asyncio
    async def test_custom_headers(self, client: AsyncHTTPClient) -> None:
        """Test requests with custom headers."""
        url = "https://api.example.com/data"
        headers = {"Authorization": "Bearer token123", "User-Agent": "TestClient/1.0"}
        expected_data = {"authenticated": True}

        with aioresponses() as mock_resp:
            mock_resp.get(url, payload=expected_data)

            result = await client.get(url, headers=headers)

            assert result == expected_data

    @pytest.mark.asyncio
    async def test_resource_cleanup(self, client: AsyncHTTPClient) -> None:
        """Test that resources are properly cleaned up."""
        # This test ensures the client can be closed without errors
        await client.close()

        # Attempting to use closed client should raise an error
        with pytest.raises((RuntimeError, aiohttp.ClientError)):
            with aioresponses() as mock_resp:
                mock_resp.get("https://api.example.com/data", payload={"test": "data"})
                await client.get("https://api.example.com/data")
