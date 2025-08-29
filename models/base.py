from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, HttpUrl, field_validator
from pydantic.types import PositiveFloat


class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NodeType(str, Enum):
    ENTRY_POINT = "entry_point"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_PROCESSING = "data_processing"
    OUTPUT = "output"
    IMPACT = "impact"


class EcosystemEnum(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    NUGET = "nuget"
    COMPOSER = "composer"
    RUBYGEMS = "rubygems"
    GO = "go"
    CARGO = "cargo"


class SecurityBaseModel(BaseModel):
    id: UUID = Field(default_factory=uuid4, description="Unique identifier")
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="Creation timestamp"
    )
    updated_at: Optional[datetime] = Field(
        default=None, description="Last update timestamp"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    class Config:
        validate_assignment = True
        use_enum_values = True
        json_encoders = {datetime: lambda v: v.isoformat(), UUID: lambda v: str(v)}

    def update_timestamp(self) -> None:
        self.updated_at = datetime.utcnow()


class Reference(SecurityBaseModel):
    url: HttpUrl = Field(..., description="Reference URL")
    source: str = Field(..., description="Source attribution")
    description: Optional[str] = Field(
        default=None, description="Reference description"
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: Union[str, HttpUrl]) -> HttpUrl:
        if isinstance(v, str):
            if not v.startswith(("http://", "https://")):
                raise ValueError("URL must start with http:// or https://")
            return HttpUrl(v)
        return v


def validate_version_format(version: str) -> str:
    if not version or not isinstance(version, str):
        raise ValueError("Version must be a non-empty string")

    import re

    semver_pattern = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"

    if not re.match(semver_pattern, version):
        if not re.match(r"^\d+(\.\d+)*", version):
            raise ValueError(f"Invalid version format: {version}")

    return version


def validate_confidence_score(score: float) -> float:
    if not 0.0 <= score <= 1.0:
        raise ValueError("Confidence score must be between 0.0 and 1.0")
    return score
