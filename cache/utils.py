# ABOUTME: Cache utilities for key generation and semantic similarity matching
# ABOUTME: Provides consistent cache key generation and similarity-based cache lookups

import hashlib
import json
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional


class CacheKeyGenerator:
    """Generates consistent cache keys from prompts and context."""

    def __init__(self) -> None:
        """Initialize cache key generator."""
        pass

    def generate_key(self, prompt: str, context: Dict[str, Any]) -> str:
        """Generate SHA256 cache key from prompt and context."""
        # Create deterministic representation
        key_data = {
            "prompt": prompt.strip(),
            "context": self._normalize_context(context),
        }

        # Serialize to consistent JSON
        serialized = json.dumps(key_data, sort_keys=True, separators=(",", ":"))

        # Generate SHA256 hash
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _normalize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize context dictionary for consistent key generation."""
        # Sort keys and handle nested dictionaries
        normalized: Dict[str, Any] = {}
        for key, value in sorted(context.items()):
            if isinstance(value, dict):
                normalized[key] = self._normalize_context(value)
            elif isinstance(value, list):
                # Sort lists of simple types, preserve order for complex types
                if value and all(
                    isinstance(item, (str, int, float, bool)) for item in value
                ):
                    normalized[key] = sorted(value, key=str)
                else:
                    normalized[key] = value
            else:
                normalized[key] = value

        return normalized


class SemanticSimilarity:
    """Provides semantic similarity matching for cached prompts."""

    def __init__(self, threshold: float = 0.8):
        """Initialize semantic similarity matcher."""
        self.threshold = threshold

    def calculate_similarity(self, prompt1: str, prompt2: str) -> float:
        """Calculate similarity score between two prompts."""
        # Normalize prompts
        norm_prompt1 = self._normalize_prompt(prompt1)
        norm_prompt2 = self._normalize_prompt(prompt2)

        # Use SequenceMatcher for similarity
        matcher = SequenceMatcher(None, norm_prompt1, norm_prompt2)
        return matcher.ratio()

    def find_similar_prompt(
        self, query_prompt: str, cached_prompts: List[str]
    ) -> Optional[str]:
        """Find most similar cached prompt above threshold."""
        best_match = None
        best_score = 0.0

        for cached_prompt in cached_prompts:
            score = self.calculate_similarity(query_prompt, cached_prompt)
            if score > best_score and score >= self.threshold:
                best_score = score
                best_match = cached_prompt

        return best_match

    def _normalize_prompt(self, prompt: str) -> str:
        """Normalize prompt for similarity comparison."""
        # Convert to lowercase
        normalized = prompt.lower().strip()

        # Remove extra whitespace
        normalized = re.sub(r"\s+", " ", normalized)

        # Remove common variations that don't affect meaning
        replacements = [
            (r"\banalyz[es]\b", "analyze"),
            (r"\bexamin[es]\b", "examine"),
            (r"\bcheck[s]?\b", "check"),
            (r"\bvulnerabilit(?:y|ies)\b", "vulnerability"),
            (r"\bexploit[s]?\b", "exploit"),
            (r"\battack[s]?\b", "attack"),
        ]

        for pattern, replacement in replacements:
            normalized = re.sub(pattern, replacement, normalized)

        return normalized

    def get_similarity_features(self, prompt: str) -> Dict[str, Any]:
        """Extract features from prompt for similarity matching."""
        normalized = self._normalize_prompt(prompt)

        # Extract key features
        features = {
            "length": len(normalized),
            "word_count": len(normalized.split()),
            "has_cve": bool(re.search(r"cve-\d{4}-\d{4,}", normalized)),
            "vulnerability_types": self._extract_vulnerability_types(normalized),
            "action_words": self._extract_action_words(normalized),
        }

        return features

    def _extract_vulnerability_types(self, normalized_prompt: str) -> List[str]:
        """Extract vulnerability type keywords."""
        vuln_patterns = [
            r"sql injection",
            r"xss",
            r"cross-site scripting",
            r"buffer overflow",
            r"buffer overrun",
            r"authentication bypass",
            r"privilege escalation",
            r"code injection",
            r"command injection",
            r"path traversal",
            r"directory traversal",
            r"denial of service",
            r"dos attack",
            r"memory corruption",
            r"use after free",
        ]

        found_types = []
        for pattern in vuln_patterns:
            if re.search(pattern, normalized_prompt):
                found_types.append(pattern.replace(" ", "_"))

        return found_types

    def _extract_action_words(self, normalized_prompt: str) -> List[str]:
        """Extract action keywords from prompt."""
        action_patterns = [
            r"analyze",
            r"examine",
            r"check",
            r"assess",
            r"evaluate",
            r"review",
            r"investigate",
            r"scan",
        ]

        found_actions = []
        for pattern in action_patterns:
            if re.search(f"\\b{pattern}\\b", normalized_prompt):
                found_actions.append(pattern)

        return found_actions
