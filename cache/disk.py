# ABOUTME: Compressed disk cache for AI responses with persistence and TTL management
# ABOUTME: Uses zstandard compression for efficient storage and automatic cleanup of expired entries

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

import zstandard as zstd


class DiskCache:
    """Compressed disk cache for AI responses with persistence."""

    def __init__(
        self,
        cache_dir: str,
        max_size_mb: int,
        default_ttl: int = 86400,  # 24 hours
        compression_enabled: bool = True,
    ):
        """Initialize disk cache."""
        self.cache_dir = Path(cache_dir)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.default_ttl = default_ttl
        self.compression_enabled = compression_enabled

        # Compression setup
        if self.compression_enabled:
            self.compressor = zstd.ZstdCompressor(level=3)
            self.decompressor = zstd.ZstdDecompressor()

        self.current_size = 0
        self.hits = 0
        self.misses = 0
        self.total_requests = 0
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize cache directory and calculate current size."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        await self._calculate_current_size()

    async def set(
        self, key: str, value: Dict[str, Any], ttl: Optional[int] = None
    ) -> None:
        """Store value in disk cache with compression."""
        async with self._lock:
            ttl = ttl or self.default_ttl
            expiry_time = time.time() + ttl

            # Create cache entry
            cache_entry = {
                "value": value,
                "expiry": expiry_time,
                "created": time.time(),
            }

            # Serialize and optionally compress
            data = json.dumps(cache_entry).encode("utf-8")
            if self.compression_enabled:
                data = self.compressor.compress(data)

            # Generate file path
            file_path = self._get_file_path(key)

            # Remove existing file if present
            if file_path.exists():
                old_size = file_path.stat().st_size
                self.current_size -= old_size

            # Write to file
            with open(file_path, "wb") as f:
                f.write(data)

            # Update size tracking
            new_size = file_path.stat().st_size
            self.current_size += new_size

            # Clean up if over size limit
            await self._cleanup_if_needed()

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve value from disk cache."""
        async with self._lock:
            self.total_requests += 1

            file_path = self._get_file_path(key)

            if not file_path.exists():
                self.misses += 1
                return None

            try:
                # Read file
                with open(file_path, "rb") as f:
                    data = f.read()

                # Decompress if needed
                if self.compression_enabled:
                    data = self.decompressor.decompress(data)

                # Deserialize
                cache_entry = json.loads(data.decode("utf-8"))

                # Check if expired
                if time.time() > cache_entry["expiry"]:
                    await self._remove_file(file_path)
                    self.misses += 1
                    return None

                self.hits += 1
                return cache_entry["value"]  # type: ignore[no-any-return]

            except (json.JSONDecodeError, IOError, KeyError) as e:
                # Corrupted file, remove it
                await self._remove_file(file_path)
                self.misses += 1
                return None

    async def cleanup(self) -> int:
        """Remove expired entries and return count removed."""
        async with self._lock:
            removed_count = 0
            current_time = time.time()

            for cache_file in self.cache_dir.glob("*.cache"):
                try:
                    with open(cache_file, "rb") as f:
                        data = f.read()

                    if self.compression_enabled:
                        data = self.decompressor.decompress(data)

                    cache_entry = json.loads(data.decode("utf-8"))

                    if current_time > cache_entry["expiry"]:
                        await self._remove_file(cache_file)
                        removed_count += 1

                except (json.JSONDecodeError, IOError, KeyError):
                    # Corrupted file, remove it
                    await self._remove_file(cache_file)
                    removed_count += 1

            return removed_count

    async def close(self) -> None:
        """Close disk cache (cleanup operation)."""
        await self.cleanup()

    def _get_file_path(self, key: str) -> Path:
        """Generate file path for cache key."""
        # Hash key to create safe filename
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"

    async def _remove_file(self, file_path: Path) -> None:
        """Remove cache file and update size tracking."""
        if file_path.exists():
            file_size = file_path.stat().st_size
            file_path.unlink()
            self.current_size -= file_size

    async def _calculate_current_size(self) -> None:
        """Calculate current cache directory size."""
        total_size = 0
        for cache_file in self.cache_dir.glob("*.cache"):
            if cache_file.is_file():
                total_size += cache_file.stat().st_size
        self.current_size = total_size

    async def _cleanup_if_needed(self) -> None:
        """Clean up oldest files if cache is over size limit."""
        if self.current_size <= self.max_size_bytes:
            return

        # Get all cache files with their modification times
        cache_files = []
        for cache_file in self.cache_dir.glob("*.cache"):
            if cache_file.is_file():
                cache_files.append((cache_file.stat().st_mtime, cache_file))

        # Sort by modification time (oldest first)
        cache_files.sort(key=lambda x: x[0])

        # Remove oldest files until under size limit
        for _, cache_file in cache_files:
            if self.current_size <= self.max_size_bytes:
                break
            await self._remove_file(cache_file)

    def get_stats(self) -> Dict[str, Any]:
        """Get disk cache statistics."""
        hit_rate = self.hits / max(self.total_requests, 1)
        return {
            "hits": self.hits,
            "misses": self.misses,
            "total_requests": self.total_requests,
            "hit_rate": hit_rate,
            "current_size_bytes": self.current_size,
            "max_size_bytes": self.max_size_bytes,
            "compression_enabled": self.compression_enabled,
        }
