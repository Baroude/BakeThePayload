import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union

from packaging import version as pkg_version
from packaging.specifiers import Specifier, SpecifierSet
from packaging.version import Version
from pydantic import BaseModel, Field

from models import EcosystemEnum


class VersionConstraintType(str, Enum):
    EXACT = "exact"          # =1.0.0
    GREATER_THAN = "gt"      # >1.0.0
    GREATER_EQUAL = "gte"    # >=1.0.0
    LESS_THAN = "lt"         # <1.0.0
    LESS_EQUAL = "lte"       # <=1.0.0
    COMPATIBLE = "compatible" # ~1.0.0
    CARET = "caret"          # ^1.0.0
    RANGE = "range"          # >=1.0.0,<2.0.0


@dataclass
class VersionConstraint:
    """Represents a version constraint with ecosystem-specific formatting"""
    constraint_type: VersionConstraintType
    version: str
    original: str
    ecosystem: EcosystemEnum
    
    def __str__(self) -> str:
        return self.original


class VersionRange(BaseModel):
    """Represents a complex version range with multiple constraints"""
    constraints: List[VersionConstraint] = Field(description="List of version constraints")
    ecosystem: EcosystemEnum = Field(description="Package ecosystem")
    original_string: str = Field(description="Original version range string")
    
    def satisfies(self, version_str: str) -> bool:
        """Check if a version satisfies this range"""
        try:
            target_version = pkg_version.parse(version_str)
            
            for constraint in self.constraints:
                if not self._check_constraint(target_version, constraint):
                    return False
            return True
        except Exception:
            return False
    
    def _check_constraint(self, version: Version, constraint: VersionConstraint) -> bool:
        """Check if version satisfies a single constraint"""
        try:
            constraint_version = pkg_version.parse(constraint.version)
            
            if constraint.constraint_type == VersionConstraintType.EXACT:
                return version == constraint_version
            elif constraint.constraint_type == VersionConstraintType.GREATER_THAN:
                return version > constraint_version
            elif constraint.constraint_type == VersionConstraintType.GREATER_EQUAL:
                return version >= constraint_version
            elif constraint.constraint_type == VersionConstraintType.LESS_THAN:
                return version < constraint_version
            elif constraint.constraint_type == VersionConstraintType.LESS_EQUAL:
                return version <= constraint_version
            elif constraint.constraint_type == VersionConstraintType.COMPATIBLE:
                return self._check_compatible(version, constraint_version)
            elif constraint.constraint_type == VersionConstraintType.CARET:
                return self._check_caret(version, constraint_version)
            else:
                return True
        except Exception:
            return False
    
    def _check_compatible(self, version: Version, constraint_version: Version) -> bool:
        """Check tilde constraint (~1.2.3 allows >=1.2.3, <1.3.0)"""
        if version < constraint_version:
            return False
        
        # For ~1.2.3, allow 1.2.x but not 1.3.x
        if len(constraint_version.release) >= 2:
            return (version.release[0] == constraint_version.release[0] and 
                   version.release[1] == constraint_version.release[1])
        return version.release[0] == constraint_version.release[0]
    
    def _check_caret(self, version: Version, constraint_version: Version) -> bool:
        """Check caret constraint (^1.2.3 allows >=1.2.3, <2.0.0)"""
        if version < constraint_version:
            return False
        
        # For ^1.2.3, allow 1.x.x but not 2.x.x
        return version.release[0] == constraint_version.release[0]


class VersionExtractor:
    """
    Extracts and normalizes version constraints across different ecosystems
    """
    
    def __init__(self):
        self.ecosystem_patterns = self._initialize_ecosystem_patterns()
    
    def _initialize_ecosystem_patterns(self) -> Dict[EcosystemEnum, Dict[str, str]]:
        """Initialize ecosystem-specific version patterns"""
        return {
            EcosystemEnum.NPM: {
                "exact": r"^(\d+\.\d+\.\d+)$",
                "caret": r"^\^(\d+\.\d+\.\d+)$",
                "tilde": r"^~(\d+\.\d+\.\d+)$",
                "range": r"^([\>\<\=\!\~\^]+)(\d+\.\d+\.\d+)$",
                "complex": r"^([\>\<\=\!\~\^]+\d+\.\d+\.\d+(?:\s*\|\|\s*[\>\<\=\!\~\^]+\d+\.\d+\.\d+)*)$"
            },
            EcosystemEnum.PYPI: {
                "exact": r"^==(\d+\.\d+(?:\.\d+)?)$",
                "range": r"^([\>\<\=\!\~]+)(\d+\.\d+(?:\.\d+)?)$",
                "complex": r"^([\>\<\=\!\~]+\d+\.\d+(?:\.\d+)?(?:\s*,\s*[\>\<\=\!\~]+\d+\.\d+(?:\.\d+)?)*)$"
            },
            EcosystemEnum.MAVEN: {
                "exact": r"^(\d+\.\d+(?:\.\d+)?)$",
                "range": r"^[\[\(]([^,]+),([^\]\)]+)[\]\)]$",
                "complex": r"^[\[\(][^,\]\)]*,?[^,\]\)]*[\]\)]$"
            },
            EcosystemEnum.NUGET: {
                "exact": r"^(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)$",
                "range": r"^[\[\(]([^,]+),([^\]\)]+)[\]\)]$",
                "float": r"^(\d+\.\d+)\*$"
            },
            EcosystemEnum.COMPOSER: {
                "exact": r"^(\d+\.\d+\.\d+)$",
                "caret": r"^\^(\d+\.\d+\.\d+)$",
                "tilde": r"^~(\d+\.\d+\.\d+)$",
                "range": r"^([\>\<\=]+)(\d+\.\d+\.\d+)$"
            },
            EcosystemEnum.RUBYGEMS: {
                "exact": r"^(\d+\.\d+\.\d+)$",
                "pessimistic": r"^~>(\d+\.\d+(?:\.\d+)?)$",
                "range": r"^([\>\<\=]+)(\d+\.\d+\.\d+)$"
            },
            EcosystemEnum.GO: {
                "exact": r"^v?(\d+\.\d+\.\d+)$",
                "range": r"^([\>\<\=]+)v?(\d+\.\d+\.\d+)$"
            },
            EcosystemEnum.CARGO: {
                "exact": r"^(\d+\.\d+\.\d+)$",
                "caret": r"^\^?(\d+\.\d+\.\d+)$",
                "tilde": r"^~(\d+\.\d+\.\d+)$",
                "range": r"^([\>\<\=]+)(\d+\.\d+\.\d+)$"
            }
        }
    
    def parse_version_constraint(self, constraint_str: str, 
                               ecosystem: EcosystemEnum) -> List[VersionConstraint]:
        """Parse a version constraint string into structured constraints"""
        
        constraint_str = constraint_str.strip()
        constraints = []
        
        # Handle complex constraints (comma-separated or OR-separated)
        if ',' in constraint_str:
            parts = [part.strip() for part in constraint_str.split(',')]
        elif '||' in constraint_str:
            parts = [part.strip() for part in constraint_str.split('||')]
        else:
            parts = [constraint_str]
        
        for part in parts:
            constraint = self._parse_single_constraint(part, ecosystem)
            if constraint:
                constraints.append(constraint)
        
        return constraints
    
    def _parse_single_constraint(self, constraint_str: str, 
                                ecosystem: EcosystemEnum) -> Optional[VersionConstraint]:
        """Parse a single version constraint"""
        
        constraint_str = constraint_str.strip()
        patterns = self.ecosystem_patterns.get(ecosystem, {})
        
        # Try exact match first
        if re.match(patterns.get("exact", ""), constraint_str):
            version = re.match(patterns["exact"], constraint_str).group(1)
            return VersionConstraint(
                VersionConstraintType.EXACT, version, constraint_str, ecosystem
            )
        
        # Try caret constraint (^1.0.0)
        caret_match = re.match(patterns.get("caret", ""), constraint_str)
        if caret_match:
            version = caret_match.group(1)
            return VersionConstraint(
                VersionConstraintType.CARET, version, constraint_str, ecosystem
            )
        
        # Try tilde/compatible constraint (~1.0.0, ~>1.0.0)
        tilde_patterns = [patterns.get("tilde", ""), patterns.get("pessimistic", "")]
        for pattern in tilde_patterns:
            if pattern:
                tilde_match = re.match(pattern, constraint_str)
                if tilde_match:
                    version = tilde_match.group(1)
                    return VersionConstraint(
                        VersionConstraintType.COMPATIBLE, version, constraint_str, ecosystem
                    )
        
        # Try range constraints (>=1.0.0, <2.0.0, etc.)
        range_match = re.match(patterns.get("range", ""), constraint_str)
        if range_match:
            operator = range_match.group(1).strip()
            version = range_match.group(2)
            
            constraint_type_map = {
                ">": VersionConstraintType.GREATER_THAN,
                ">=": VersionConstraintType.GREATER_EQUAL,
                "<": VersionConstraintType.LESS_THAN,
                "<=": VersionConstraintType.LESS_EQUAL,
                "=": VersionConstraintType.EXACT,
                "==": VersionConstraintType.EXACT,
            }
            
            constraint_type = constraint_type_map.get(operator, VersionConstraintType.GREATER_EQUAL)
            return VersionConstraint(constraint_type, version, constraint_str, ecosystem)
        
        # Try Maven/NuGet range format [1.0,2.0)
        bracket_match = re.match(patterns.get("complex", ""), constraint_str)
        if bracket_match and ('[' in constraint_str or '(' in constraint_str):
            return self._parse_bracket_range(constraint_str, ecosystem)
        
        # Fallback: treat as exact version if it looks like a version
        if re.match(r"\d+\.\d+", constraint_str):
            clean_version = re.sub(r"[^0-9\.]", "", constraint_str)
            return VersionConstraint(
                VersionConstraintType.EXACT, clean_version, constraint_str, ecosystem
            )
        
        return None
    
    def _parse_bracket_range(self, constraint_str: str, 
                           ecosystem: EcosystemEnum) -> Optional[VersionConstraint]:
        """Parse bracket notation ranges like [1.0,2.0) or (1.0,2.0]"""
        
        # Maven/NuGet style ranges
        match = re.match(r'^([\[\(])([^,]+),([^\]\)]+)([\]\)])$', constraint_str)
        if not match:
            return None
        
        start_bracket, min_version, max_version, end_bracket = match.groups()
        
        # This is a complex range - for now, treat as a range constraint
        # In a full implementation, you'd create multiple constraints
        return VersionConstraint(
            VersionConstraintType.RANGE, 
            f"{min_version},{max_version}", 
            constraint_str, 
            ecosystem
        )
    
    def create_version_range(self, constraint_str: str, 
                           ecosystem: EcosystemEnum) -> VersionRange:
        """Create a VersionRange from constraint string"""
        
        constraints = self.parse_version_constraint(constraint_str, ecosystem)
        
        return VersionRange(
            constraints=constraints,
            ecosystem=ecosystem,
            original_string=constraint_str
        )
    
    def normalize_version(self, version_str: str, ecosystem: EcosystemEnum) -> str:
        """Normalize version string for ecosystem"""
        
        # Remove ecosystem-specific prefixes
        if ecosystem == EcosystemEnum.GO and version_str.startswith('v'):
            version_str = version_str[1:]
        
        # Ensure semantic versioning format
        try:
            parsed = pkg_version.parse(version_str)
            return str(parsed)
        except Exception:
            # Fallback normalization
            parts = version_str.split('.')
            while len(parts) < 3:
                parts.append('0')
            return '.'.join(parts[:3])
    
    def extract_versions_from_text(self, text: str, 
                                 ecosystem: Optional[EcosystemEnum] = None) -> List[str]:
        """Extract version numbers from free text"""
        
        # Common version patterns
        patterns = [
            r'\b\d+\.\d+\.\d+(?:\.\d+)?\b',  # Standard semver
            r'\bv?\d+\.\d+(?:\.\d+)?\b',     # With optional 'v' prefix
            r'\b\d+\.\d+(?:\-\w+)?\b'        # With pre-release tags
        ]
        
        versions = set()
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            versions.update(matches)
        
        # Clean and validate versions
        clean_versions = []
        for version in versions:
            try:
                # Remove 'v' prefix if present
                clean_version = version.lstrip('v')
                # Validate it parses correctly
                pkg_version.parse(clean_version)
                clean_versions.append(clean_version)
            except Exception:
                continue
        
        return sorted(list(set(clean_versions)))
    
    def compare_versions(self, version1: str, version2: str) -> int:
        """Compare two versions (-1: v1 < v2, 0: v1 == v2, 1: v1 > v2)"""
        try:
            v1 = pkg_version.parse(version1)
            v2 = pkg_version.parse(version2)
            
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            else:
                return 0
        except Exception:
            return 0
    
    def get_ecosystem_patterns(self, ecosystem: EcosystemEnum) -> Dict[str, str]:
        """Get version patterns for specific ecosystem"""
        return self.ecosystem_patterns.get(ecosystem, {})
    
    def validate_version_format(self, version: str, ecosystem: EcosystemEnum) -> bool:
        """Validate if version format is correct for ecosystem"""
        try:
            normalized = self.normalize_version(version, ecosystem)
            pkg_version.parse(normalized)
            return True
        except Exception:
            return False