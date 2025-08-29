# ABOUTME: Data deduplication functionality with content hashing and fuzzy matching
# ABOUTME: Handles cross-referencing of related vulnerabilities and prevents duplicate processing

import hashlib
import json
from difflib import SequenceMatcher
from typing import Any, Dict, List, Set, Tuple


class Deduplicator:
    """Handles deduplication of vulnerability data from multiple sources."""

    def __init__(self, similarity_threshold: float = 0.8):
        """Initialize deduplicator with similarity threshold."""
        self.similarity_threshold = similarity_threshold
        self.seen_hashes: Set[str] = set()
        self.content_cache: Dict[str, Dict[str, Any]] = {}

    def generate_content_hash(self, data: Dict[str, Any]) -> str:
        """Generate content hash for deduplication."""
        # Normalize data for consistent hashing
        normalized_data = self._normalize_for_hashing(data)

        # Create JSON string with sorted keys
        json_str = json.dumps(normalized_data, sort_keys=True, separators=(",", ":"))

        # Generate SHA256 hash
        return hashlib.sha256(json_str.encode("utf-8")).hexdigest()

    def is_duplicate(self, data: Dict[str, Any]) -> bool:
        """Check if data is a duplicate based on content hash."""
        content_hash = self.generate_content_hash(data)

        if content_hash in self.seen_hashes:
            return True

        # Mark as seen
        self.seen_hashes.add(content_hash)
        self.content_cache[content_hash] = data

        return False

    def find_fuzzy_duplicates(
        self, entries: List[Dict[str, Any]]
    ) -> List[Tuple[int, int, float]]:
        """Find fuzzy duplicate entries using similarity matching."""
        duplicates = []

        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                similarity = self._calculate_similarity(entries[i], entries[j])

                if similarity >= self.similarity_threshold:
                    duplicates.append((i, j, similarity))

        return duplicates

    def build_cross_references(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Set[str]]:
        """Build cross-reference mapping between related vulnerabilities."""
        cross_refs: Dict[str, Set[str]] = {}

        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            if not cve_id:
                continue

            if cve_id not in cross_refs:
                cross_refs[cve_id] = set()

            # Add explicit related CVEs
            related_cves = vuln.get("related_cves", [])
            for related_cve in related_cves:
                cross_refs[cve_id].add(related_cve)

                # Add reverse reference
                if related_cve not in cross_refs:
                    cross_refs[related_cve] = set()
                cross_refs[related_cve].add(cve_id)

            # Find implicit relationships through similarity
            for other_vuln in vulnerabilities:
                other_cve = other_vuln.get("cve_id")
                if other_cve and other_cve != cve_id:
                    similarity = self._calculate_similarity(vuln, other_vuln)
                    if similarity >= self.similarity_threshold:
                        cross_refs[cve_id].add(other_cve)

                        if other_cve not in cross_refs:
                            cross_refs[other_cve] = set()
                        cross_refs[other_cve].add(cve_id)

        # Convert sets to lists for JSON serialization
        return {k: list(v) for k, v in cross_refs.items()}  # type: ignore[misc]

    def merge_duplicate_entries(
        self, entries: List[Dict[str, Any]], duplicates: List[Tuple[int, int, float]]
    ) -> List[Dict[str, Any]]:
        """Merge duplicate entries into single consolidated entries."""
        # Track which entries have been merged
        merged_indices = set()
        merged_entries = []

        # Process duplicates
        for i, j, similarity in duplicates:
            if i in merged_indices or j in merged_indices:
                continue

            # Merge entries i and j
            merged_entry = self._merge_entries(entries[i], entries[j])
            merged_entries.append(merged_entry)

            merged_indices.add(i)
            merged_indices.add(j)

        # Add non-duplicate entries
        for i, entry in enumerate(entries):
            if i not in merged_indices:
                merged_entries.append(entry)

        return merged_entries

    def get_deduplication_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        return {
            "total_hashes": len(self.seen_hashes),
            "cached_entries": len(self.content_cache),
            "similarity_threshold": self.similarity_threshold,
        }

    def clear_cache(self) -> None:
        """Clear deduplication cache."""
        self.seen_hashes.clear()
        self.content_cache.clear()

    def _normalize_for_hashing(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize data structure for consistent hashing."""
        normalized: Dict[str, Any] = {}

        for key, value in data.items():
            # Skip volatile fields that shouldn't affect deduplication
            if key in ["timestamp", "last_updated", "crawl_time", "request_id"]:
                continue

            if isinstance(value, dict):
                normalized[key] = self._normalize_for_hashing(value)
            elif isinstance(value, list):
                # Sort lists of simple types for consistency
                if value and all(
                    isinstance(item, (str, int, float, bool)) for item in value
                ):
                    normalized[key] = sorted(value, key=str)
                else:
                    # For complex lists, normalize each item
                    normalized[key] = [
                        self._normalize_for_hashing(item)
                        if isinstance(item, dict)
                        else item
                        for item in value
                    ]
            else:
                normalized[key] = value

        return normalized

    def _calculate_similarity(
        self, entry1: Dict[str, Any], entry2: Dict[str, Any]
    ) -> float:
        """Calculate similarity between two entries."""
        # Focus on key descriptive fields
        key_fields = ["description", "summary", "title", "cve_id", "affected_packages"]

        similarities = []

        for field in key_fields:
            if field in entry1 and field in entry2:
                value1 = str(entry1[field]).lower()
                value2 = str(entry2[field]).lower()

                similarity = SequenceMatcher(None, value1, value2).ratio()
                similarities.append(similarity)

        # Return average similarity if any fields matched
        return sum(similarities) / len(similarities) if similarities else 0.0

    def _merge_entries(
        self, entry1: Dict[str, Any], entry2: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Merge two similar entries into one consolidated entry."""
        merged = entry1.copy()

        # Merge fields from entry2, preferring more complete data
        for key, value in entry2.items():
            if key not in merged:
                merged[key] = value
            elif isinstance(value, list) and isinstance(merged[key], list):
                # Merge lists and deduplicate
                merged_list = merged[key] + value
                # Handle both simple and complex list items
                if all(
                    isinstance(item, (str, int, float, bool)) for item in merged_list
                ):
                    merged[key] = list(dict.fromkeys(merged_list))
                else:
                    # For complex objects, use content-based deduplication
                    seen_items = []
                    for item in merged_list:
                        if item not in seen_items:
                            seen_items.append(item)
                    merged[key] = seen_items
            elif isinstance(value, dict) and isinstance(merged[key], dict):
                # Recursively merge dictionaries
                merged[key] = {**merged[key], **value}
            elif not merged[key] and value:
                # Prefer non-empty values
                merged[key] = value

        # Add metadata about the merge
        merged["_merge_info"] = {
            "merged_from": [
                entry1.get("source", "unknown"),
                entry2.get("source", "unknown"),
            ],
            "merge_reason": "fuzzy_duplicate",
        }

        return merged
