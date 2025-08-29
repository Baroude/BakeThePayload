# ABOUTME: Format adapters for normalizing data from different sources (GitHub, GHSA, OSV, NVD)
# ABOUTME: Provides consistent data structure transformation with fallback mappings

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional


class FormatAdapter(ABC):
    """Base class for data format adapters."""

    @abstractmethod
    def adapt(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt raw data to normalized format."""
        pass


class GitHubAdapter(FormatAdapter):
    """Adapter for GitHub API data."""

    def adapt(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt GitHub data to normalized format."""
        if "commit" in raw_data:
            return self._adapt_commit(raw_data)
        elif "tag_name" in raw_data:
            return self._adapt_release(raw_data)
        else:
            return {"type": "github_unknown", "raw_data": raw_data}

    def _adapt_commit(self, commit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt GitHub commit data."""
        commit = commit_data.get("commit", {})

        return {
            "type": "github_commit",
            "sha": commit_data.get("sha"),
            "message": commit.get("message"),
            "author": commit.get("author", {}).get("name"),
            "date": commit.get("author", {}).get("date"),
            "url": commit_data.get("html_url"),
        }

    def _adapt_release(self, release_data: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt GitHub release data."""
        return {
            "type": "github_release",
            "tag_name": release_data.get("tag_name"),
            "name": release_data.get("name"),
            "published_at": release_data.get("published_at"),
            "url": release_data.get("html_url"),
            "body": release_data.get("body"),
        }


class GHSAAdapter(FormatAdapter):
    """Adapter for GitHub Security Advisory data."""

    def adapt(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt GHSA data to normalized format."""
        return {
            "type": "ghsa_advisory",
            "ghsa_id": raw_data.get("ghsaId"),
            "cve_id": raw_data.get("cveId"),
            "severity": raw_data.get("severity"),
            "summary": raw_data.get("summary"),
            "description": raw_data.get("description"),
            "published_at": raw_data.get("publishedAt"),
            "vulnerabilities": raw_data.get("vulnerabilities", []),
        }


class OSVAdapter(FormatAdapter):
    """Adapter for OSV database data."""

    def adapt(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt OSV data to normalized format."""
        return {
            "type": "osv_vulnerability",
            "vulnerability_id": raw_data.get("id"),
            "summary": raw_data.get("summary"),
            "details": raw_data.get("details"),
            "published": raw_data.get("published"),
            "modified": raw_data.get("modified"),
            "affected_packages": self._extract_affected_packages(
                raw_data.get("affected", [])
            ),
            "references": raw_data.get("references", []),
            "severity": self._extract_severity(raw_data.get("severity", [])),
        }

    def _extract_affected_packages(
        self, affected: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Extract affected package information."""
        packages = []

        for item in affected:
            package = item.get("package", {})
            packages.append(
                {
                    "name": package.get("name"),
                    "ecosystem": package.get("ecosystem"),
                    "ranges": item.get("ranges", []),
                }
            )

        return packages

    def _extract_severity(
        self, severity_list: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Extract severity information."""
        if not severity_list:
            return None

        # Use first severity entry
        severity = severity_list[0]
        return {"type": severity.get("type"), "score": severity.get("score")}


class NVDAdapter(FormatAdapter):
    """Adapter for NVD database data."""

    def adapt(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt NVD data to normalized format."""
        cve_data = raw_data.get("cve", {})

        return {
            "type": "nvd_vulnerability",
            "cve_id": cve_data.get("id"),
            "source_identifier": cve_data.get("sourceIdentifier"),
            "published": cve_data.get("published"),
            "last_modified": cve_data.get("lastModified"),
            "vuln_status": cve_data.get("vulnStatus"),
            "descriptions": self._extract_descriptions(
                cve_data.get("descriptions", [])
            ),
            "cvss_metrics": self._extract_cvss_metrics(cve_data.get("metrics", {})),
            "configurations": cve_data.get("configurations", []),
            "references": self._extract_references(cve_data.get("references", [])),
        }

    def _extract_descriptions(
        self, descriptions: List[Dict[str, Any]]
    ) -> Dict[str, str]:
        """Extract descriptions by language."""
        desc_dict = {}
        for desc in descriptions:
            lang = desc.get("lang", "en")
            desc_dict[lang] = desc.get("value", "")
        return desc_dict

    def _extract_cvss_metrics(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CVSS metrics."""
        cvss_data = {}

        # Extract CVSS v3.1 metrics
        if "cvssMetricV31" in metrics:
            v31_metrics = metrics["cvssMetricV31"]
            if v31_metrics:
                cvss_data["v31"] = {
                    "source": v31_metrics[0].get("source"),
                    "base_score": v31_metrics[0].get("cvssData", {}).get("baseScore"),
                    "base_severity": v31_metrics[0]
                    .get("cvssData", {})
                    .get("baseSeverity"),
                    "vector_string": v31_metrics[0]
                    .get("cvssData", {})
                    .get("vectorString"),
                }

        # Extract CVSS v3.0 metrics
        if "cvssMetricV30" in metrics:
            v30_metrics = metrics["cvssMetricV30"]
            if v30_metrics:
                cvss_data["v30"] = {
                    "source": v30_metrics[0].get("source"),
                    "base_score": v30_metrics[0].get("cvssData", {}).get("baseScore"),
                    "base_severity": v30_metrics[0]
                    .get("cvssData", {})
                    .get("baseSeverity"),
                }

        return cvss_data

    def _extract_references(
        self, references: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Extract reference information."""
        ref_list = []

        for ref in references:
            ref_list.append(
                {
                    "url": ref.get("url"),
                    "source": ref.get("source"),
                    "tags": ref.get("tags", []),
                }
            )

        return ref_list
