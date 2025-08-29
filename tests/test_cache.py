# ABOUTME: Unit tests for AI response caching system with memory and disk storage
# ABOUTME: Tests LRU memory cache, compressed disk cache, semantic similarity, and TTL functionality

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio

from cache.disk import DiskCache
from cache.manager import CacheManager
from cache.memory import MemoryCache
from cache.utils import CacheKeyGenerator, SemanticSimilarity


class TestMemoryCache:
    """Test suite for in-memory LRU cache with TTL."""

    def test_memory_cache_creation(self) -> None:
        """Test memory cache initialization."""
        cache = MemoryCache(max_size_mb=50, default_ttl=3600)

        assert cache.max_size_bytes == 50 * 1024 * 1024
        assert cache.default_ttl == 3600
        assert cache.current_size == 0

    def test_cache_set_and_get(self) -> None:
        """Test basic cache set and get operations."""
        cache = MemoryCache(max_size_mb=50, default_ttl=3600)

        key = "test_prompt_123"
        value = {"response": "This is a test AI response", "tokens": 150}

        cache.set(key, value)
        retrieved = cache.get(key)

        assert retrieved == value

    def test_cache_expiration(self) -> None:
        """Test cache TTL expiration."""
        cache = MemoryCache(max_size_mb=50, default_ttl=1)  # 1 second TTL

        key = "test_prompt_short_ttl"
        value = {"response": "This will expire soon", "tokens": 100}

        cache.set(key, value)
        assert cache.get(key) == value

        # Wait for expiration
        import time

        time.sleep(1.1)

        assert cache.get(key) is None

    def test_lru_eviction(self) -> None:
        """Test LRU eviction when cache is full."""
        # Small cache to trigger eviction
        cache = MemoryCache(
            max_size_mb=1, default_ttl=3600
        )  # ~1MB (changed from 0.001 to avoid float type issue)

        # Fill cache beyond capacity
        for i in range(10):
            key = f"prompt_{i}"
            value = {"response": "x" * 200, "tokens": 50}  # ~200 bytes each
            cache.set(key, value)

        # Early entries should be evicted
        assert cache.get("prompt_0") is None
        assert cache.get("prompt_9") is not None

    def test_cache_statistics(self) -> None:
        """Test cache hit/miss statistics."""
        cache = MemoryCache(max_size_mb=50, default_ttl=3600)

        key = "stats_test"
        value = {"response": "Testing stats", "tokens": 75}

        # Miss
        assert cache.get(key) is None

        # Set and hit
        cache.set(key, value)
        assert cache.get(key) == value

        stats = cache.get_stats()
        assert stats["hits"] >= 1
        assert stats["misses"] >= 1
        assert stats["total_requests"] >= 2

    def test_cache_clear(self) -> None:
        """Test cache clearing functionality."""
        cache = MemoryCache(max_size_mb=50, default_ttl=3600)

        cache.set("key1", {"data": "value1"})
        cache.set("key2", {"data": "value2"})

        assert cache.get("key1") is not None
        assert cache.get("key2") is not None

        cache.clear()

        assert cache.get("key1") is None
        assert cache.get("key2") is None


class TestDiskCache:
    """Test suite for compressed disk cache with persistence."""

    @pytest.fixture
    def temp_cache_dir(self) -> Generator[str, None, None]:
        """Create temporary directory for cache testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest_asyncio.fixture
    async def disk_cache(self, temp_cache_dir: str) -> AsyncGenerator[DiskCache, None]:
        """Create DiskCache instance for testing."""
        cache = DiskCache(
            cache_dir=temp_cache_dir,
            max_size_mb=500,
            default_ttl=86400,  # 24 hours
            compression_enabled=True,
        )
        await cache.initialize()
        yield cache
        await cache.close()

    @pytest.mark.asyncio
    async def test_disk_cache_creation(self, temp_cache_dir: str) -> None:
        """Test disk cache initialization."""
        cache = DiskCache(cache_dir=temp_cache_dir, max_size_mb=500, default_ttl=86400)
        await cache.initialize()

        assert os.path.exists(temp_cache_dir)
        assert cache.max_size_bytes == 500 * 1024 * 1024

        await cache.close()

    @pytest.mark.asyncio
    async def test_disk_cache_set_and_get(self, disk_cache: DiskCache) -> None:
        """Test disk cache set and get with compression."""
        key = "disk_test_prompt"
        value = {
            "response": "This is a comprehensive AI response that will be compressed",
            "tokens": 250,
            "model": "gpt-4",
        }

        await disk_cache.set(key, value)
        retrieved = await disk_cache.get(key)

        assert retrieved == value

    @pytest.mark.asyncio
    async def test_disk_cache_persistence(self, temp_cache_dir: str) -> None:
        """Test that disk cache persists across restarts."""
        key = "persistence_test"
        value = {"response": "This should persist", "tokens": 100}

        # First cache instance
        cache1 = DiskCache(cache_dir=temp_cache_dir, max_size_mb=500, default_ttl=86400)
        await cache1.initialize()
        await cache1.set(key, value)
        await cache1.close()

        # Second cache instance (simulating restart)
        cache2 = DiskCache(cache_dir=temp_cache_dir, max_size_mb=500, default_ttl=86400)
        await cache2.initialize()
        retrieved = await cache2.get(key)

        assert retrieved == value
        await cache2.close()

    @pytest.mark.asyncio
    async def test_disk_cache_compression(self, disk_cache: DiskCache) -> None:
        """Test compression effectiveness."""
        # Large, repetitive data that compresses well
        large_response = "This is a repeated response. " * 1000
        key = "compression_test"
        value = {"response": large_response, "tokens": 500}

        await disk_cache.set(key, value)

        # Check that file exists and is smaller than uncompressed
        cache_files = list(Path(disk_cache.cache_dir).glob("*.cache"))
        assert len(cache_files) > 0

        # File should be smaller than uncompressed JSON
        uncompressed_size = len(json.dumps(value).encode())
        compressed_size = cache_files[0].stat().st_size

        assert compressed_size < uncompressed_size

    @pytest.mark.asyncio
    async def test_disk_cache_cleanup(self, disk_cache: DiskCache) -> None:
        """Test cleanup of expired entries."""
        # Set entry with short TTL
        key = "cleanup_test"
        value = {"response": "Will expire", "tokens": 50}

        await disk_cache.set(key, value, ttl=1)  # 1 second TTL

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Trigger cleanup
        await disk_cache.cleanup()

        # Entry should be gone
        retrieved = await disk_cache.get(key)
        assert retrieved is None


class TestSemanticSimilarity:
    """Test suite for semantic similarity matching."""

    def test_similarity_creation(self) -> None:
        """Test semantic similarity matcher initialization."""
        similarity = SemanticSimilarity(threshold=0.8)

        assert similarity.threshold == 0.8

    def test_exact_match(self) -> None:
        """Test exact string matching."""
        similarity = SemanticSimilarity(threshold=0.8)

        prompt1 = "Analyze this vulnerability for SQL injection"
        prompt2 = "Analyze this vulnerability for SQL injection"

        score = similarity.calculate_similarity(prompt1, prompt2)
        assert score == 1.0

    def test_similar_prompts(self) -> None:
        """Test similarity detection for similar prompts."""
        similarity = SemanticSimilarity(threshold=0.8)

        prompt1 = "Analyze this vulnerability for SQL injection attacks"
        prompt2 = "Analyze this vulnerability for SQL injection exploits"

        score = similarity.calculate_similarity(prompt1, prompt2)
        assert score > 0.8

    def test_dissimilar_prompts(self) -> None:
        """Test dissimilarity detection."""
        similarity = SemanticSimilarity(threshold=0.8)

        prompt1 = "Analyze this vulnerability for SQL injection"
        prompt2 = "What's the weather like today?"

        score = similarity.calculate_similarity(prompt1, prompt2)
        assert score < 0.5

    def test_find_similar_cached_prompt(self) -> None:
        """Test finding similar cached prompts."""
        similarity = SemanticSimilarity(threshold=0.8)

        cached_prompts = [
            "Analyze CVE-2021-1234 for buffer overflow",
            "Check CVE-2021-5678 for XSS vulnerability",
            "Examine CVE-2021-9999 for authentication bypass",
        ]

        query_prompt = "Analyze CVE-2021-1234 for buffer overrun"

        match = similarity.find_similar_prompt(query_prompt, cached_prompts)
        assert match == "Analyze CVE-2021-1234 for buffer overflow"


class TestCacheKeyGenerator:
    """Test suite for cache key generation."""

    def test_key_generation_consistency(self) -> None:
        """Test that same input generates same key."""
        generator = CacheKeyGenerator()

        prompt = "Analyze this vulnerability"
        context = {"cve_id": "CVE-2021-1234", "severity": "high"}

        key1 = generator.generate_key(prompt, context)
        key2 = generator.generate_key(prompt, context)

        assert key1 == key2

    def test_key_generation_uniqueness(self) -> None:
        """Test that different inputs generate different keys."""
        generator = CacheKeyGenerator()

        key1 = generator.generate_key("prompt1", {"cve": "CVE-1"})
        key2 = generator.generate_key("prompt2", {"cve": "CVE-2"})

        assert key1 != key2

    def test_key_format(self) -> None:
        """Test cache key format."""
        generator = CacheKeyGenerator()

        key = generator.generate_key("test prompt", {"test": "data"})

        # Should be a hex string
        assert isinstance(key, str)
        assert len(key) == 64  # SHA256 hex length
        assert all(c in "0123456789abcdef" for c in key)


class TestCacheManager:
    """Test suite for integrated cache manager."""

    @pytest.fixture
    def temp_cache_dir(self) -> Generator[str, None, None]:
        """Create temporary directory for cache testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest_asyncio.fixture
    async def cache_manager(
        self, temp_cache_dir: str
    ) -> AsyncGenerator[CacheManager, None]:
        """Create CacheManager instance for testing."""
        manager = CacheManager(
            memory_cache_mb=50,
            disk_cache_dir=temp_cache_dir,
            disk_cache_mb=500,
            similarity_threshold=0.8,
        )
        await manager.initialize()
        yield manager
        await manager.close()

    @pytest.mark.asyncio
    async def test_cache_manager_initialization(self, temp_cache_dir: str) -> None:
        """Test cache manager initialization with both caches."""
        manager = CacheManager(
            memory_cache_mb=50, disk_cache_dir=temp_cache_dir, disk_cache_mb=500
        )

        await manager.initialize()

        assert manager.memory_cache is not None
        assert manager.disk_cache is not None
        assert manager.similarity is not None

        await manager.close()

    @pytest.mark.asyncio
    async def test_cache_hierarchical_lookup(self, cache_manager: CacheManager) -> None:
        """Test hierarchical lookup: memory -> disk."""
        prompt = "Test prompt for hierarchy"
        context = {"test": True}
        response = {"response": "Test response", "tokens": 100}

        # Store in manager (should go to both caches)
        await cache_manager.set(prompt, context, response)

        # Clear memory cache to test disk fallback
        cache_manager.memory_cache.clear()

        # Should still retrieve from disk
        retrieved = await cache_manager.get(prompt, context)
        assert retrieved == response

    @pytest.mark.asyncio
    async def test_semantic_similarity_cache_hit(
        self, cache_manager: CacheManager
    ) -> None:
        """Test cache hit through semantic similarity."""
        original_prompt = "Analyze CVE-2021-1234 for buffer overflow vulnerability"
        context = {"cve_id": "CVE-2021-1234"}
        response = {"response": "Buffer overflow analysis", "tokens": 200}

        # Store original
        await cache_manager.set(original_prompt, context, response)

        # Query with similar prompt (very similar to ensure threshold is met)
        similar_prompt = "Analyze CVE-2021-1234 for buffer overflow"
        retrieved = await cache_manager.get(similar_prompt, context)

        # Should find similar cached response
        assert retrieved == response

    @pytest.mark.asyncio
    async def test_cache_statistics_integration(
        self, cache_manager: CacheManager
    ) -> None:
        """Test integrated cache statistics."""
        prompt = "Stats test prompt"
        context = {"test": "stats"}
        response = {"response": "Stats response", "tokens": 75}

        # Miss
        await cache_manager.get(prompt, context)

        # Set and hit
        await cache_manager.set(prompt, context, response)
        await cache_manager.get(prompt, context)

        stats = await cache_manager.get_statistics()

        assert "memory_cache" in stats
        assert "disk_cache" in stats
        assert "similarity_matches" in stats
        assert stats["total_requests"] >= 2
