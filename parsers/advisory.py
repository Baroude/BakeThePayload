import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, HttpUrl, field_validator

from models import Evidence, Reference, SeverityEnum, VulnerabilityReport
from models.artifact import AffectedArtifact, VersionRange
from models.base import EcosystemEnum


class AdvisoryFormat(str, Enum):
    GHSA = "ghsa"  # GitHub Security Advisory
    OSV = "osv"  # Open Source Vulnerability
    NVD = "nvd"  # National Vulnerability Database
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

    def __init__(self) -> None:
        self.format_detectors = {
            AdvisoryFormat.GHSA: self._detect_ghsa_format,
            AdvisoryFormat.OSV: self._detect_osv_format,
            AdvisoryFormat.NVD: self._detect_nvd_format,
        }

        self.format_parsers = {
            AdvisoryFormat.GHSA: self._parse_ghsa,
            AdvisoryFormat.OSV: self._parse_osv,
            AdvisoryFormat.NVD: self._parse_nvd,
        }

    def parse(self, advisory_data: Union[str, Dict[str, Any]]) -> VulnerabilityReport:
        """Parse advisory data into VulnerabilityReport"""

        # Convert string to dict if needed
        parsed_data: Dict[str, Any]
        if isinstance(advisory_data, str):
            try:
                parsed_data = json.loads(advisory_data)
            except json.JSONDecodeError as e:
                raise AdvisoryParseError(f"Invalid JSON format: {e}")
        else:
            parsed_data = advisory_data

        # Detect format
        detected_format = self._detect_format(parsed_data)

        # Parse using appropriate parser
        parser = self.format_parsers.get(detected_format)
        if not parser:
            raise AdvisoryParseError(
                f"No parser available for format: {detected_format}"
            )

        try:
            return parser(parsed_data)
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
                "identifiers" in data
                and isinstance(data["identifiers"], list)
                and any(
                    isinstance(ident, dict) and ident.get("type") == "GHSA"
                    for ident in data["identifiers"]
                ),
                data.get("database_specific", {}).get("github_reviewed") is not None,
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
                "database_specific" in data
                and isinstance(data.get("affected"), list)
                and len(data["affected"]) > 0
                and "ecosystem" in data["affected"][0],
                isinstance(data.get("schema_version", ""), str)
                and data["schema_version"].startswith("1."),
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
                "impact" in data
                and isinstance(data["impact"], dict)
                and "baseMetricV3" in data["impact"],
                "problemtype" in data,
                data.get("data_type") == "CVE",
            ]
            return any(nvd_indicators)
        except (TypeError, AttributeError):
            return False

    def _parse_ghsa(self, data: Dict[str, Any]) -> VulnerabilityReport:
        """Parse GitHub Security Advisory format"""

        # Extract basic information
        advisory_id = (
            data.get("ghsa_id")
            or data.get("id")
            or self._extract_identifier(data.get("identifiers", []), "GHSA")
        )

        title = data.get("summary") or data.get("title") or "GitHub Security Advisory"

        description = str(
            data.get("details") or data.get("description") or data.get("summary") or ""
        )

        # Extract severity
        severity_str = data.get("severity") or data.get("database_specific", {}).get(
            "severity"
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
            cwe_ids = [
                f"CWE-{cwe}" if not str(cwe).startswith("CWE-") else str(cwe)
                for cwe in data["cwe_ids"]
            ]
        elif "cwes" in data:
            # Extract from cwes array (GitHub format)
            for cwe in data["cwes"]:
                if isinstance(cwe, dict) and "cwe_id" in cwe:
                    cwe_ids.append(cwe["cwe_id"])
                elif isinstance(cwe, str):
                    cwe_ids.append(cwe)

        # Extract affected artifacts (packages)
        affected_artifacts = []
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                if "package" in vuln:
                    package = vuln["package"]
                    package_name = package.get("name", "Unknown")
                    ecosystem_str = package.get("ecosystem", "unknown")

                    # Map ecosystem string to enum
                    try:
                        ecosystem = EcosystemEnum(ecosystem_str.lower())
                    except ValueError:
                        # Handle unknown ecosystems
                        if ecosystem_str.lower() in ["rubygems", "gem"]:
                            ecosystem = EcosystemEnum.RUBYGEMS
                        else:
                            continue  # Skip unknown ecosystems

                    # Extract version ranges
                    version_ranges = []
                    if "vulnerable_version_range" in vuln:
                        version_ranges.append(
                            VersionRange(
                                constraint=vuln["vulnerable_version_range"],
                                ecosystem=ecosystem,
                            )
                        )

                    # Extract fixed versions
                    fixed_versions = []
                    if "first_patched_version" in vuln:
                        fixed_versions.append(vuln["first_patched_version"])

                    affected_artifacts.append(
                        AffectedArtifact(
                            package_name=package_name,
                            ecosystem=ecosystem,
                            affected_versions=version_ranges,
                            fixed_versions=fixed_versions,
                            repository_url=data.get("source_code_location"),
                        )
                    )

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
            affected_artifacts=affected_artifacts,
            evidence=[
                Evidence(
                    type="advisory", content=f"Parsed from GHSA format", confidence=0.9
                )
            ],
        )

    def _parse_osv(self, data: Dict[str, Any]) -> VulnerabilityReport:
        """Parse Open Source Vulnerability format"""

        advisory_id = data.get("id", "Unknown")
        title = data.get("summary", advisory_id)
        description = str(data.get("details") or data.get("summary") or "")

        # OSV doesn't have severity in standard format, infer from CVSS if available
        severity = SeverityEnum.MEDIUM  # Default
        cvss_score = None
        cvss_vector = None

        if "severity" in data:
            severity_data = (
                data["severity"][0]
                if isinstance(data["severity"], list)
                else data["severity"]
            )
            if "score" in severity_data:
                cvss_score = float(severity_data["score"])
                severity = self._cvss_to_severity(cvss_score)

        # Extract affected artifacts from affected array
        affected_artifacts = []
        if "affected" in data:
            for affected in data["affected"]:
                # Extract package info if available
                package_name = "Unknown"
                ecosystem = EcosystemEnum.NPM  # Default

                if "package" in affected:
                    package_info = affected["package"]
                    package_name = package_info.get("name", "Unknown")
                    ecosystem_str = package_info.get("ecosystem", "npm")
                    try:
                        ecosystem = EcosystemEnum(ecosystem_str.lower())
                    except ValueError:
                        # Handle unknown ecosystems
                        if ecosystem_str.lower() in ["rubygems", "gem"]:
                            ecosystem = EcosystemEnum.RUBYGEMS
                        else:
                            continue
                elif "ranges" in affected and affected["ranges"]:
                    # Infer from repository URL if no package info
                    range_data = affected["ranges"][0]
                    repo_url = range_data.get("repo", "")
                    if "github.com" in repo_url:
                        # Extract package name from repo URL
                        parts = repo_url.rstrip("/").split("/")
                        if len(parts) >= 2:
                            package_name = parts[-1]
                        # Try to infer ecosystem from repo content or name
                        if any(ext in repo_url.lower() for ext in ["ruby", "gem"]):
                            ecosystem = EcosystemEnum.RUBYGEMS
                        elif any(ext in repo_url.lower() for ext in ["python", "py"]):
                            ecosystem = EcosystemEnum.PYPI
                        elif any(
                            ext in repo_url.lower()
                            for ext in ["javascript", "js", "node"]
                        ):
                            ecosystem = EcosystemEnum.NPM

                # Extract version ranges
                version_ranges = []
                fixed_versions = []

                if "versions" in affected:
                    # Extract affected versions
                    affected_versions = affected["versions"]
                    if affected_versions:
                        # Create a version constraint from the versions list
                        version_constraint = (
                            f"<= {max(affected_versions)}" if affected_versions else ""
                        )
                        if version_constraint:
                            version_ranges.append(
                                VersionRange(
                                    constraint=version_constraint, ecosystem=ecosystem
                                )
                            )

                # Extract fixed versions from ranges
                if "ranges" in affected:
                    for range_data in affected["ranges"]:
                        for event in range_data.get("events", []):
                            if "fixed" in event:
                                fixed_versions.append(event["fixed"])

                # Extract repository URL
                repository_url = None
                if "ranges" in affected and affected["ranges"]:
                    repository_url = affected["ranges"][0].get("repo")

                affected_artifacts.append(
                    AffectedArtifact(
                        package_name=package_name,
                        ecosystem=ecosystem,
                        affected_versions=version_ranges,
                        fixed_versions=fixed_versions,
                        repository_url=repository_url,
                    )
                )

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
            affected_artifacts=affected_artifacts,
            evidence=[
                Evidence(
                    type="advisory", content=f"Parsed from OSV format", confidence=0.85
                )
            ],
        )

    def _parse_nvd(self, data: Union[Dict[str, Any], str]) -> VulnerabilityReport:
        """Parse NVD format"""

        # Handle both new and old NVD formats
        if isinstance(data, str):
            raise AdvisoryParseError("NVD data must be a dictionary, not a string")

        cve_data = data.get("cve", data)

        # Handle case where cve_data might be a string
        if isinstance(cve_data, str):
            raise AdvisoryParseError("CVE data must be a dictionary, not a string")

        advisory_id = (
            cve_data.get("id")
            or cve_data.get("CVE_data_meta", {}).get("ID")
            or "Unknown"
        )

        # Extract description (new NVD format)
        description = ""
        title = f"CVE {advisory_id}"

        if "descriptions" in cve_data:
            # New NVD format
            for desc in cve_data["descriptions"]:
                if desc.get("lang") == "en":
                    description = str(desc.get("value") or "")
                    break
        else:
            # Old NVD format fallback
            descriptions = cve_data.get("description", {}).get("description_data", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = str(desc.get("value") or "")
                    break

        # Extract CVSS information (new format)
        cvss_score = None
        cvss_vector = None
        severity = SeverityEnum.MEDIUM

        # Try new format first
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = self._cvss_to_severity(cvss_score)
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = self._cvss_to_severity(cvss_score)
        else:
            # Old format fallback
            impact = data.get("impact", {})
            if "baseMetricV3" in impact:
                cvss_v3 = impact["baseMetricV3"]["cvssV3"]
                cvss_score = cvss_v3.get("baseScore")
                cvss_vector = cvss_v3.get("vectorString")
                severity = self._cvss_to_severity(cvss_score)

        # Extract CWE information (new format)
        cwe_ids = []
        if "weaknesses" in cve_data:
            # New NVD format
            for weakness in cve_data["weaknesses"]:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        value = desc.get("value", "")
                        if value.startswith("CWE-"):
                            cwe_ids.append(value)
        else:
            # Old format fallback
            problemtype = cve_data.get("problemtype", {}).get("problemtype_data", [])
            for problem in problemtype:
                for desc in problem.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwe_ids.append(desc["value"])

        # Extract publication date
        published_at = None
        if "published" in cve_data:
            published_at = self._parse_date(cve_data["published"])
        elif "publishedDate" in data:
            published_at = self._parse_date(data["publishedDate"])

        # Extract references (new format)
        references = []
        if "references" in cve_data and isinstance(cve_data["references"], list):
            # New NVD format - list of reference objects
            for ref in cve_data["references"]:
                if isinstance(ref, dict):
                    url = ref.get("url")
                    if (
                        url
                        and isinstance(url, str)
                        and url.startswith(("http://", "https://"))
                    ):
                        references.append(
                            Reference(
                                url=HttpUrl(url),
                                source=ref.get("source", "NVD"),
                                description="",
                            )
                        )
                elif isinstance(ref, str) and ref.startswith(("http://", "https://")):
                    # Handle string URLs
                    references.append(
                        Reference(
                            url=HttpUrl(ref),
                            source="NVD",
                            description="",
                        )
                    )
        # Check for old format references structure at data level (not in cve_data)
        if not references and "references" in data:
            ref_data = data["references"]
            if isinstance(ref_data, dict) and "reference_data" in ref_data:
                for ref in ref_data["reference_data"]:
                    if isinstance(ref, dict) and "url" in ref:
                        url = ref["url"]
                        if isinstance(url, str) and url.startswith(
                            ("http://", "https://")
                        ):
                            references.append(
                                Reference(
                                    url=HttpUrl(url),
                                    source="NVD",
                                    description=", ".join(ref.get("tags", [])),
                                )
                            )

        # Also check if cve_data has references in old format
        if not references and "references" in cve_data:
            ref_data = cve_data["references"]
            if isinstance(ref_data, dict) and "reference_data" in ref_data:
                for ref in ref_data["reference_data"]:
                    if isinstance(ref, dict) and "url" in ref:
                        url = ref["url"]
                        if isinstance(url, str) and url.startswith(
                            ("http://", "https://")
                        ):
                            references.append(
                                Reference(
                                    url=HttpUrl(url),
                                    source="NVD",
                                    description=", ".join(ref.get("tags", [])),
                                )
                            )

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
            evidence=[
                Evidence(
                    type="advisory", content=f"Parsed from NVD format", confidence=0.95
                )
            ],
        )

    def _extract_identifier(
        self, identifiers: List[Dict[str, Any]], id_type: str
    ) -> str:
        """Extract specific identifier type from identifiers list"""
        for ident in identifiers:
            if ident.get("type") == id_type:
                return str(ident.get("value", "Unknown"))
        return "Unknown"

    def _extract_references(
        self, refs_data: List[Union[Dict[str, Any], str]]
    ) -> List[Reference]:
        """Extract references from various formats"""
        references = []
        for ref in refs_data:
            # Handle string URLs (common in GHSA)
            if isinstance(ref, str):
                references.append(
                    Reference(
                        url=HttpUrl(ref),
                        source="GHSA",
                        description="",
                    )
                )
            # Handle dict format (OSV/NVD)
            elif isinstance(ref, dict):
                url = ref.get("url") or ref.get("reference")
                if url:
                    references.append(
                        Reference(
                            url=HttpUrl(url),
                            source=ref.get("source", "External"),
                            description=ref.get("comment") or ref.get("type", ""),
                        )
                    )
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
            "INFO": SeverityEnum.INFO,
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
            "%Y-%m-%dT%H:%M:%SZ",  # ISO 8601 with Z
            "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO 8601 with microseconds
            "%Y-%m-%dT%H:%M:%S",  # ISO 8601 without Z
            "%Y-%m-%d",  # Date only
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
