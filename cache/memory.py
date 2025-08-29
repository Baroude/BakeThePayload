# ABOUTME: In-memory LRU cache for AI responses with TTL support and size management
# ABOUTME: Provides fast access to frequently used AI responses with automatic eviction

import sys
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Optional


class MemoryCache:
    """In-memory LRU cache with TTL support for AI responses."""

    def __init__(self, max_size_mb: int, default_ttl: int):
        """Initialize memory cache with size and TTL limits."""
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.default_ttl = default_ttl
        self.cache: OrderedDict = OrderedDict()
        self.current_size = 0
        self.hits = 0
        self.misses = 0
        self.total_requests = 0
        self._lock = threading.RLock()

    def set(self, key: str, value: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Store value in cache with TTL."""
        with self._lock:
            ttl = ttl or self.default_ttl
            expiry_time = time.time() + ttl

            # Calculate size of entry
            entry_size = sys.getsizeof(key) + sys.getsizeof(str(value))

            # Remove key if it already exists
            if key in self.cache:
                old_entry = self.cache.pop(key)
                self.current_size -= old_entry["size"]

            # Create cache entry
            cache_entry = {
                "value": value,
                "expiry": expiry_time,
                "size": entry_size,
                "access_time": time.time(),
            }

            # Add to cache
            self.cache[key] = cache_entry
            self.current_size += entry_size

            # Evict if over size limit
            self._evict_if_needed()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve value from cache if not expired."""
        with self._lock:
            self.total_requests += 1

            if key not in self.cache:
                self.misses += 1
                return None

            entry = self.cache[key]

            # Check if expired
            if time.time() > entry["expiry"]:
                self.cache.pop(key)
                self.current_size -= entry["size"]
                self.misses += 1
                return None

            # Move to end (most recently used)
            self.cache.move_to_end(key)
            entry["access_time"] = time.time()

            self.hits += 1
            return entry["value"]  # type: ignore[no-any-return]

    def _evict_if_needed(self) -> None:
        """Evict least recently used items if cache is over size limit."""
        while self.current_size > self.max_size_bytes and self.cache:
            # Remove least recently used item
            oldest_key, oldest_entry = self.cache.popitem(last=False)
            self.current_size -= oldest_entry["size"]

    def clear(self) -> None:
        """Clear all cached items."""
        with self._lock:
            self.cache.clear()
            self.current_size = 0

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            hit_rate = self.hits / max(self.total_requests, 1)
            return {
                "hits": self.hits,
                "misses": self.misses,
                "total_requests": self.total_requests,
                "hit_rate": hit_rate,
                "current_size_bytes": self.current_size,
                "current_entries": len(self.cache),
                "max_size_bytes": self.max_size_bytes,
            }

    def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed."""
        with self._lock:
            expired_keys = []
            current_time = time.time()

            for key, entry in self.cache.items():
                if current_time > entry["expiry"]:
                    expired_keys.append(key)

            for key in expired_keys:
                entry = self.cache.pop(key)
                self.current_size -= entry["size"]

            return len(expired_keys)
