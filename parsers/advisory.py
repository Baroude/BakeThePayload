import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator

from models import VulnerabilityReport, Evidence, Reference, SeverityEnum


class AdvisoryFormat(str, Enum):
    GHSA = "ghsa"  # GitHub Security Advisory
    OSV = "osv"    # Open Source Vulnerability
    NVD = "nvd"    # National Vulnerability Database
    UNKNOWN = "unknown"


class ParsedAdvisory(BaseModel):
    """Intermediate representation for parsed advisory data"""
    format: AdvisoryFormat
    raw_data: Dict[str, Any]
    confidence: float = Field(description="Confidence in parsing accuracy")


class AdvisoryParseError(Exception):
    """Exception raised when advisory parsing fails"""
    pass


class MultiFormatAdvisoryParser:
    """
    Parser that handles multiple advisory formats and converts them to VulnerabilityReport
    """
    
    def __init__(self):
        self.format_detectors = {
            AdvisoryFormat.GHSA: self._detect_ghsa_format,
            AdvisoryFormat.OSV: self._detect_osv_format, 
            AdvisoryFormat.NVD: self._detect_nvd_format
        }
        
        self.format_parsers = {
            AdvisoryFormat.GHSA: self._parse_ghsa,
            AdvisoryFormat.OSV: self._parse_osv,
            AdvisoryFormat.NVD: self._parse_nvd
        }
    
    def parse(self, advisory_data: Union[str, Dict[str, Any]]) -> VulnerabilityReport:
        """Parse advisory data into VulnerabilityReport"""
        
        # Convert string to dict if needed
        if isinstance(advisory_data, str):
            try:
                advisory_data = json.loads(advisory_data)
            except json.JSONDecodeError as e:
                raise AdvisoryParseError(f"Invalid JSON format: {e}")
        
        # Detect format
        detected_format = self._detect_format(advisory_data)
        
        # Parse using appropriate parser
        parser = self.format_parsers.get(detected_format)
        if not parser:
            raise AdvisoryParseError(f"No parser available for format: {detected_format}")
        
        try:
            return parser(advisory_data)
        except Exception as e:
            raise AdvisoryParseError(f"Failed to parse {detected_format} format: {e}")
    
    def _detect_format(self, data: Dict[str, Any]) -> AdvisoryFormat:
        """Auto-detect advisory format based on structure"""
        
        # Validate input data
        if not data or not isinstance(data, dict):
            return AdvisoryFormat.UNKNOWN
        
        # Check each format detector
        for format_type, detector in self.format_detectors.items():
            try:
                if detector(data):
                    return format_type
            except (TypeError, AttributeError, KeyError):
                # Skip detector if it fails
                continue
        
        return AdvisoryFormat.UNKNOWN
    
    def _detect_ghsa_format(self, data: Dict[str, Any]) -> bool:
        """Detect GitHub Security Advisory format"""
        if not data or not isinstance(data, dict):
            return False
            
        try:
            ghsa_indicators = [
                "ghsa_id" in data,
                "security_advisory" in data,
                "identifiers" in data and isinstance(data["identifiers"], list) and any(
                    isinstance(ident, dict) and ident.get("type") == "GHSA" 
                    for ident in data["identifiers"]
                ),
                data.get("database_specific", {}).get("github_reviewed") is not None
            ]
            return any(ghsa_indicators)
        except (TypeError, AttributeError):
            return False
    
    def _detect_osv_format(self, data: Dict[str, Any]) -> bool:
        """Detect Open Source Vulnerability format"""
        if not data or not isinstance(data, dict):
            return False
            
        try:
            osv_indicators = [
                "schema_version" in data,
                "id" in data and "affected" in data,
                "database_specific" in data and isinstance(data.get("affected"), list) and 
                len(data["affected"]) > 0 and "ecosystem" in data["affected"][0],
                isinstance(data.get("schema_version", ""), str) and data["schema_version"].startswith("1.")
            ]
            return all(osv_indicators[:2]) or any(osv_indicators[2:])
        except (TypeError, AttributeError, IndexError):
            return False
    
    def _detect_nvd_format(self, data: Dict[str, Any]) -> bool:
        """Detect NVD format"""
        if not data or not isinstance(data, dict):
            return False
            
        try:
            nvd_indicators = [
                "cve" in data,
                "CVE_data_meta" in data,
                "impact" in data and isinstance(data["impact"], dict) and "baseMetricV3" in data["impact"],
                "problemtype" in data,
                data.get("data_type") == "CVE"
            ]
            return any(nvd_indicators)
        except (TypeError, AttributeError):
            return False
    
    def _parse_ghsa(self, data: Dict[str, Any]) -> VulnerabilityReport:
        """Parse GitHub Security Advisory format"""
        
        # Extract basic information
        advisory_id = (
            data.get("ghsa_id") or 
            data.get("id") or
            self._extract_identifier(data.get("identifiers", []), "GHSA")
        )
        
        title = (
            data.get("summary") or
            data.get("title") or
            "GitHub Security Advisory"
        )
        
        description = (
            data.get("details") or
            data.get("description") or
            data.get("summary", "")
        )
        
        # Extract severity
        severity_str = (
            data.get("severity") or
            data.get("database_specific", {}).get("severity")
        )
        severity = self._map_severity(severity_str)
        
        # Extract CVSS information
        cvss_score = None
        cvss_vector = None
        
        if "cvss" in data:
            cvss_score = data["cvss"].get("score")
            cvss_vector = data["cvss"].get("vector_string")
        elif "database_specific" in data:
            db_specific = data["database_specific"]
            cvss_score = db_specific.get("cvss_score")
            cvss_vector = db_specific.get("cvss_vector")
        
        # Extract CWE information
        cwe_ids = []
        if "cwe_ids" in data:
            cwe_ids = [f"CWE-{cwe}" if not str(cwe).startswith("CWE-") else str(cwe) 
                      for cwe in data["cwe_ids"]]
        
        # Extract references
        references = self._extract_references(data.get("references", []))
        
        # Extract publication date
        published_at = None
        if "published" in data:
            published_at = self._parse_date(data["published"])
        elif "published_at" in data:
            published_at = self._parse_date(data["published_at"])
        
        return VulnerabilityReport(
            advisory_id=advisory_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            references=references,
            published_at=published_at,
            summary=data.get("summary"),
            evidence=[Evidence(
                type="advisory",
                content=f"Parsed from GHSA format",
                confidence=0.9
            )]
        )
    
    def _parse_osv(self, data: Dict[str, Any]) -> VulnerabilityReport:
        """Parse Open Source Vulnerability format"""
        
        advisory_id = data.get("id", "Unknown")
        title = data.get("summary", advisory_id)
        description = data.get("details", data.get("summary", ""))
        
        # OSV doesn't have severity in standard format, infer from CVSS if available
        severity = SeverityEnum.MEDIUM  # Default
        cvss_score = None
        cvss_vector = None
        
        if "severity" in data:
            severity_data = data["severity"][0] if isinstance(data["severity"], list) else data["severity"]
            if "score" in severity_data:
                cvss_score = float(severity_data["score"])
                severity = self._cvss_to_severity(cvss_score)
        
        # Extract references
        references = self._extract_references(data.get("references", []))
        
        # Extract publication date
        published_at = None
        if "published" in data:
            published_at = self._parse_date(data["published"])
        
        return VulnerabilityReport(
            advisory_id=advisory_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            references=references,
            published_at=published_at,
            evidence=[Evidence(
                type="advisory",
                content=f"Parsed from OSV format",
                confidence=0.85
            )]
        )
    
    def _parse_nvd(self, data: Dict[str, Any]) -> VulnerabilityReport:
        """Parse NVD format"""
        
        # NVD has complex nested structure
        cve_data = data.get("cve", data)
        
        advisory_id = (
            cve_data.get("CVE_data_meta", {}).get("ID") or
            data.get("id", "Unknown")
        )
        
        # Extract description
        descriptions = cve_data.get("description", {}).get("description_data", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        title = f"CVE {advisory_id}"
        
        # Extract CVSS information
        cvss_score = None
        cvss_vector = None
        severity = SeverityEnum.MEDIUM
        
        impact = data.get("impact", {})
        if "baseMetricV3" in impact:
            cvss_v3 = impact["baseMetricV3"]["cvssV3"]
            cvss_score = cvss_v3.get("baseScore")
            cvss_vector = cvss_v3.get("vectorString")
            severity = self._cvss_to_severity(cvss_score)
        elif "baseMetricV2" in impact:
            cvss_v2 = impact["baseMetricV2"]["cvssV2"]
            cvss_score = cvss_v2.get("baseScore")
            cvss_vector = cvss_v2.get("vectorString")
            severity = self._cvss_to_severity(cvss_score)
        
        # Extract CWE information
        cwe_ids = []
        problemtype = cve_data.get("problemtype", {}).get("problemtype_data", [])
        for problem in problemtype:
            for desc in problem.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])
        
        # Extract publication date
        published_at = None
        if "publishedDate" in data:
            published_at = self._parse_date(data["publishedDate"])
        
        # Extract references
        references = []
        ref_data = cve_data.get("references", {}).get("reference_data", [])
        for ref in ref_data:
            references.append(Reference(
                url=ref["url"],
                source="NVD",
                description=", ".join(ref.get("tags", []))
            ))
        
        return VulnerabilityReport(
            advisory_id=advisory_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            references=references,
            published_at=published_at,
            evidence=[Evidence(
                type="advisory",
                content=f"Parsed from NVD format",
                confidence=0.95
            )]
        )
    
    def _extract_identifier(self, identifiers: List[Dict[str, Any]], id_type: str) -> str:
        """Extract specific identifier type from identifiers list"""
        for ident in identifiers:
            if ident.get("type") == id_type:
                return ident.get("value", "Unknown")
        return "Unknown"
    
    def _extract_references(self, refs_data: List[Dict[str, Any]]) -> List[Reference]:
        """Extract references from various formats"""
        references = []
        for ref in refs_data:
            url = ref.get("url") or ref.get("reference")
            if url:
                references.append(Reference(
                    url=url,
                    source=ref.get("source", "External"),
                    description=ref.get("comment") or ref.get("type", "")
                ))
        return references
    
    def _map_severity(self, severity_str: Optional[str]) -> SeverityEnum:
        """Map string severity to SeverityEnum"""
        if not severity_str:
            return SeverityEnum.MEDIUM
        
        severity_str = severity_str.upper()
        mapping = {
            "CRITICAL": SeverityEnum.CRITICAL,
            "HIGH": SeverityEnum.HIGH,
            "MODERATE": SeverityEnum.MEDIUM,
            "MEDIUM": SeverityEnum.MEDIUM,
            "LOW": SeverityEnum.LOW,
            "INFORMATIONAL": SeverityEnum.INFO,
            "INFO": SeverityEnum.INFO
        }
        return mapping.get(severity_str, SeverityEnum.MEDIUM)
    
    def _cvss_to_severity(self, cvss_score: Optional[float]) -> SeverityEnum:
        """Convert CVSS score to severity enum"""
        if cvss_score is None:
            return SeverityEnum.MEDIUM
        
        if cvss_score >= 9.0:
            return SeverityEnum.CRITICAL
        elif cvss_score >= 7.0:
            return SeverityEnum.HIGH
        elif cvss_score >= 4.0:
            return SeverityEnum.MEDIUM
        elif cvss_score > 0.0:
            return SeverityEnum.LOW
        else:
            return SeverityEnum.INFO
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string to datetime object"""
        if not date_str:
            return None
        
        # Common date formats
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",      # ISO 8601 with Z
            "%Y-%m-%dT%H:%M:%S.%fZ",   # ISO 8601 with microseconds
            "%Y-%m-%dT%H:%M:%S",       # ISO 8601 without Z
            "%Y-%m-%d",                # Date only
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        return None
    
    def get_supported_formats(self) -> List[str]:
        """Return list of supported advisory formats"""
        return [fmt.value for fmt in self.format_parsers.keys()]