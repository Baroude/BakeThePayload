from enum import Enum
from typing import Dict, List, Optional

from pydantic import Field, field_validator

from .base import SecurityBaseModel, SeverityEnum, validate_confidence_score


class ImpactLevel(str, Enum):
    NONE = "none"
    PARTIAL = "partial"
    COMPLETE = "complete"


class RiskFactor(SecurityBaseModel):
    name: str = Field(..., description="Risk factor name")
    value: str = Field(..., description="Risk factor value")
    weight: float = Field(..., description="Weight of this factor in overall assessment")
    description: Optional[str] = Field(default=None, description="Risk factor description")
    
    @field_validator('weight')
    @classmethod
    def validate_weight(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("Weight must be between 0.0 and 1.0")
        return v


class Impact(SecurityBaseModel):
    confidentiality: ImpactLevel = Field(..., description="Confidentiality impact")
    integrity: ImpactLevel = Field(..., description="Integrity impact")
    availability: ImpactLevel = Field(..., description="Availability impact")
    scope: str = Field(default="unchanged", description="Scope of impact (changed/unchanged)")
    
    @field_validator('scope')
    @classmethod
    def validate_scope(cls, v: str) -> str:
        if v.lower() not in ["changed", "unchanged"]:
            raise ValueError("Scope must be 'changed' or 'unchanged'")
        return v.lower()


class Mitigation(SecurityBaseModel):
    type: str = Field(..., description="Mitigation type (patch, workaround, configuration)")
    description: str = Field(..., description="Mitigation description")
    effectiveness: float = Field(..., description="Effectiveness score")
    complexity: str = Field(..., description="Implementation complexity (low, medium, high)")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    
    @field_validator('effectiveness')
    @classmethod
    def validate_effectiveness(cls, v: float) -> float:
        return validate_confidence_score(v)
    
    @field_validator('complexity')
    @classmethod
    def validate_complexity(cls, v: str) -> str:
        if v.lower() not in ["low", "medium", "high"]:
            raise ValueError("Complexity must be 'low', 'medium', or 'high'")
        return v.lower()


class RiskAssessment(SecurityBaseModel):
    vulnerability_id: str = Field(..., description="Associated vulnerability ID")
    cvss_vector: Optional[str] = Field(default=None, description="CVSS vector string")
    base_score: Optional[float] = Field(default=None, description="CVSS base score")
    temporal_score: Optional[float] = Field(default=None, description="CVSS temporal score")
    environmental_score: Optional[float] = Field(default=None, description="CVSS environmental score")
    derived_score: float = Field(..., description="Calculated risk score")
    severity: SeverityEnum = Field(..., description="Derived severity level")
    confidence: float = Field(..., description="Confidence in the assessment")
    factors: List[RiskFactor] = Field(default_factory=list, description="Contributing risk factors")
    impact: Impact = Field(..., description="Impact assessment")
    mitigations: List[Mitigation] = Field(default_factory=list, description="Available mitigations")
    reasoning: str = Field(..., description="Assessment reasoning and methodology")
    
    @field_validator('base_score', 'temporal_score', 'environmental_score')
    @classmethod
    def validate_cvss_scores(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            if not 0.0 <= v <= 10.0:
                raise ValueError("CVSS scores must be between 0.0 and 10.0")
        return v
    
    @field_validator('derived_score')
    @classmethod
    def validate_derived_score(cls, v: float) -> float:
        if not 0.0 <= v <= 10.0:
            raise ValueError("Derived score must be between 0.0 and 10.0")
        return v
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        return validate_confidence_score(v)
    
    def calculate_overall_risk(self) -> float:
        """Calculate overall risk based on score, confidence, and mitigations"""
        risk = self.derived_score
        
        # Adjust for confidence
        risk *= self.confidence
        
        # Adjust for available mitigations
        if self.mitigations:
            mitigation_factor = sum(m.effectiveness for m in self.mitigations) / len(self.mitigations)
            risk *= (1.0 - mitigation_factor * 0.5)  # Mitigations can reduce risk by up to 50%
        
        return min(10.0, max(0.0, risk))