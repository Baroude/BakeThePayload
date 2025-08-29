# ABOUTME: Integrated cache manager coordinating memory and disk caches with semantic similarity
# ABOUTME: Provides unified interface for hierarchical caching with similarity-based lookups

import asyncio
from typing import Any, Dict, List, Optional

from .disk import DiskCache
from .memory import MemoryCache
from .utils import CacheKeyGenerator, SemanticSimilarity


class CacheManager:
    """Integrated cache manager with memory, disk, and similarity matching."""

    def __init__(
        self,
        memory_cache_mb: int,
        disk_cache_dir: str,
        disk_cache_mb: int,
        memory_ttl: int = 3600,  # 1 hour
        disk_ttl: int = 86400,  # 24 hours
        similarity_threshold: float = 0.8,
    ):
        """Initialize cache manager with memory and disk caches."""
        self.memory_cache = MemoryCache(
            max_size_mb=memory_cache_mb, default_ttl=memory_ttl
        )

        self.disk_cache = DiskCache(
            cache_dir=disk_cache_dir, max_size_mb=disk_cache_mb, default_ttl=disk_ttl
        )

        self.key_generator = CacheKeyGenerator()
        self.similarity = SemanticSimilarity(threshold=similarity_threshold)

        # Track cached prompts for similarity matching
        self.cached_prompts: Dict[str, str] = {}  # key -> prompt
        self.similarity_matches = 0
        self.total_similarity_checks = 0

        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize both cache layers."""
        await self.disk_cache.initialize()
        await self._load_cached_prompts()

    async def get(
        self, prompt: str, context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Get cached response with hierarchical lookup and similarity matching."""
        async with self._lock:
            # Generate primary cache key
            cache_key = self.key_generator.generate_key(prompt, context)

            # 1. Check memory cache first
            result = self.memory_cache.get(cache_key)
            if result is not None:
                return result

            # 2. Check disk cache
            result = await self.disk_cache.get(cache_key)
            if result is not None:
                # Promote to memory cache
                self.memory_cache.set(cache_key, result)
                return result

            # 3. Check for similar prompts
            self.total_similarity_checks += 1
            similar_prompt = self.similarity.find_similar_prompt(
                prompt, list(self.cached_prompts.values())
            )

            if similar_prompt:
                # Find the cache key for similar prompt
                similar_key = None
                for key, cached_prompt in self.cached_prompts.items():
                    if cached_prompt == similar_prompt:
                        similar_key = key
                        break

                if similar_key:
                    # Try to get similar response from caches
                    result = self.memory_cache.get(similar_key)
                    if result is None:
                        result = await self.disk_cache.get(similar_key)

                    if result is not None:
                        self.similarity_matches += 1
                        # Store under original key for future lookups (without recursion)
                        new_cache_key = self.key_generator.generate_key(prompt, context)
                        self.memory_cache.set(new_cache_key, result)
                        await self.disk_cache.set(new_cache_key, result)
                        self.cached_prompts[new_cache_key] = prompt
                        return result

            return None

    async def set(
        self, prompt: str, context: Dict[str, Any], response: Dict[str, Any]
    ) -> None:
        """Store response in both cache layers."""
        async with self._lock:
            cache_key = self.key_generator.generate_key(prompt, context)

            # Store in both caches
            self.memory_cache.set(cache_key, response)
            await self.disk_cache.set(cache_key, response)

            # Track prompt for similarity matching
            self.cached_prompts[cache_key] = prompt

    async def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        memory_stats = self.memory_cache.get_stats()
        disk_stats = self.disk_cache.get_stats()

        similarity_hit_rate = self.similarity_matches / max(
            self.total_similarity_checks, 1
        )

        return {
            "memory_cache": memory_stats,
            "disk_cache": disk_stats,
            "similarity_matches": self.similarity_matches,
            "similarity_checks": self.total_similarity_checks,
            "similarity_hit_rate": similarity_hit_rate,
            "total_requests": memory_stats["total_requests"],
            "cached_prompts": len(self.cached_prompts),
        }

    async def cleanup(self) -> Dict[str, int]:
        """Clean up expired entries in both caches."""
        memory_cleaned = self.memory_cache.cleanup_expired()
        disk_cleaned = await self.disk_cache.cleanup()

        # Clean up cached prompts for removed entries
        await self._update_cached_prompts()

        return {"memory_cleaned": memory_cleaned, "disk_cleaned": disk_cleaned}

    async def clear_all(self) -> None:
        """Clear all cached data."""
        async with self._lock:
            self.memory_cache.clear()
            self.cached_prompts.clear()
            # Note: Disk cache doesn't have a clear method, would need cleanup

    async def close(self) -> None:
        """Close cache manager and cleanup resources."""
        await self.disk_cache.close()
        await self.cleanup()

    async def _load_cached_prompts(self) -> None:
        """Load existing cached prompts from disk cache for similarity matching."""
        # This would require scanning disk cache files to rebuild prompt mapping
        # For now, prompts will be built up as new entries are added
        pass

    async def _update_cached_prompts(self) -> None:
        """Update cached prompts mapping after cleanup."""
        # Remove prompts for keys that no longer exist in either cache
        keys_to_remove = []

        for cache_key in self.cached_prompts.keys():
            memory_exists = self.memory_cache.get(cache_key) is not None
            disk_exists = await self.disk_cache.get(cache_key) is not None

            if not memory_exists and not disk_exists:
                keys_to_remove.append(cache_key)

        for key in keys_to_remove:
            self.cached_prompts.pop(key, None)

    def get_cache_key(self, prompt: str, context: Dict[str, Any]) -> str:
        """Get cache key for given prompt and context (for testing)."""
        return self.key_generator.generate_key(prompt, context)
