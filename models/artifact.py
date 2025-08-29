from typing import List, Optional

from pydantic import Field, field_validator

from .base import EcosystemEnum, SecurityBaseModel, validate_version_format


class VersionRange(SecurityBaseModel):
    constraint: str = Field(
        ..., description="Version constraint (>=1.0.0, ~1.2.0, etc.)"
    )
    ecosystem: EcosystemEnum = Field(..., description="Package ecosystem")

    @field_validator("constraint")
    @classmethod
    def validate_constraint(cls, v: str) -> str:
        import re

        constraint_patterns = [
            r"^>=?\s*v?\d+(\.\d+)*",  # >=1.0.0, > 1.0.0, >= v1.0.0
            r"^<=?\s*v?\d+(\.\d+)*",  # <=1.0.0, < 1.0.0, <= v1.0.0
            r"^~\s*v?\d+(\.\d+)*",  # ~1.2.0, ~ v1.2.0
            r"^\^\s*v?\d+(\.\d+)*",  # ^1.2.0, ^ v1.2.0
            r"^=\s*v?\d+(\.\d+)*",  # =1.2.0, = v1.2.0
            r"^v?\d+(\.\d+)*$",  # 1.2.0, v1.2.0
        ]

        if not any(re.match(pattern, v.strip()) for pattern in constraint_patterns):
            raise ValueError(f"Invalid version constraint format: {v}")
        return v.strip()


class Component(SecurityBaseModel):
    name: str = Field(..., description="Component name")
    type: str = Field(..., description="Component type (class, function, module, etc.)")
    file_path: Optional[str] = Field(
        default=None, description="File path containing the component"
    )
    line_range: Optional[tuple[int, int]] = Field(
        default=None, description="Line range (start, end)"
    )
    description: Optional[str] = Field(
        default=None, description="Component description"
    )

    @field_validator("line_range")
    @classmethod
    def validate_line_range(
        cls, v: Optional[tuple[int, int]]
    ) -> Optional[tuple[int, int]]:
        if v is not None:
            start, end = v
            if start <= 0 or end <= 0:
                raise ValueError("Line numbers must be positive")
            if start > end:
                raise ValueError("Start line must be less than or equal to end line")
        return v


class AffectedArtifact(SecurityBaseModel):
    package_name: str = Field(..., description="Package or artifact name")
    ecosystem: EcosystemEnum = Field(..., description="Package ecosystem")
    affected_versions: List[VersionRange] = Field(
        ..., description="Affected version ranges"
    )
    fixed_versions: List[str] = Field(
        default_factory=list, description="Fixed version numbers"
    )
    components: List[Component] = Field(
        default_factory=list, description="Affected components"
    )
    repository_url: Optional[str] = Field(
        default=None, description="Source repository URL"
    )

    @field_validator("fixed_versions")
    @classmethod
    def validate_fixed_versions(cls, v: List[str]) -> List[str]:
        for version in v:
            validate_version_format(version)
        return v

    def is_version_affected(self, version: str) -> bool:
        """Check if a specific version is affected"""
        from packaging import version as pkg_version
        from packaging.specifiers import SpecifierSet

        try:
            target_version = pkg_version.parse(version)

            for version_range in self.affected_versions:
                spec = SpecifierSet(version_range.constraint)
                if target_version in spec:
                    return True
            return False
        except Exception:
            return False
