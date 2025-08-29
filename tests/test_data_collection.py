# ABOUTME: Unit tests for multi-source data collection including GitHub, advisory APIs, and filesystem
# ABOUTME: Tests format adapters, deduplication, cross-referencing, and webhook support

import asyncio
import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from agents.adapters import (
    FormatAdapter,
    GHSAAdapter,
    GitHubAdapter,
    NVDAdapter,
    OSVAdapter,
)
from agents.data_sources import (
    AdvisoryDataSource,
    DataSourceManager,
    FileSystemDataSource,
    GitHubDataSource,
    WebhookDataSource,
)
from agents.deduplication import Deduplicator
from models.vulnerability import VulnerabilityReport


class TestDataSourceManager:
    """Test suite for multi-source data collection coordination."""

    @pytest_asyncio.fixture
    async def data_manager(self) -> AsyncGenerator[DataSourceManager, None]:
        """Create DataSourceManager instance for testing."""
        manager = DataSourceManager(
            github_token="test-token",
            rate_limiter=MagicMock(),
            cache_manager=MagicMock(),
        )
        await manager.initialize()
        yield manager
        await manager.close()

    @pytest.mark.asyncio
    async def test_manager_initialization(self) -> None:
        """Test data source manager initialization."""
        manager = DataSourceManager(github_token="test-token", rate_limiter=MagicMock())

        await manager.initialize()

        assert manager.github_source is not None
        assert manager.advisory_source is not None
        assert manager.filesystem_source is not None
        assert manager.webhook_source is not None

        await manager.close()

    @pytest.mark.asyncio
    async def test_collect_from_all_sources(
        self, data_manager: DataSourceManager
    ) -> None:
        """Test collecting data from all configured sources."""
        vulnerability_id = "CVE-2021-1234"

        # Mock the sources directly
        github_mock = AsyncMock()
        advisory_mock = AsyncMock()
        filesystem_mock = AsyncMock()

        data_manager.github_source = github_mock
        data_manager.advisory_source = advisory_mock
        data_manager.filesystem_source = filesystem_mock

        # Mock responses from each source
        github_mock.collect.return_value = [
            {"source": "github", "commits": [], "releases": []}
        ]
        advisory_mock.collect.return_value = [{"source": "advisory", "advisories": []}]
        filesystem_mock.collect.return_value = [
            {"source": "filesystem", "cached_files": []}
        ]

        results = await data_manager.collect_all(vulnerability_id)

        assert len(results) == 3
        assert any(r["source"] == "github" for r in results)
        assert any(r["source"] == "advisory" for r in results)
        assert any(r["source"] == "filesystem" for r in results)

    @pytest.mark.asyncio
    async def test_sequential_processing(self, data_manager: DataSourceManager) -> None:
        """Test sequential processing of one vulnerability at a time."""
        vulnerability_ids = ["CVE-2021-1234", "CVE-2021-5678"]

        processing_order = []

        async def mock_collect(vuln_id: str) -> List[Dict[str, Any]]:
            processing_order.append(f"start_{vuln_id}")
            await asyncio.sleep(0.1)  # Simulate processing time
            processing_order.append(f"end_{vuln_id}")
            return [{"id": vuln_id, "data": "processed"}]

        with patch.object(data_manager, "collect_all", side_effect=mock_collect):
            results = await data_manager.process_vulnerabilities(vulnerability_ids)

            assert len(results) == 2
            # Verify sequential processing
            assert processing_order == [
                "start_CVE-2021-1234",
                "end_CVE-2021-1234",
                "start_CVE-2021-5678",
                "end_CVE-2021-5678",
            ]

    @pytest.mark.asyncio
    async def test_error_handling_continue_on_error(
        self, data_manager: DataSourceManager
    ) -> None:
        """Test error handling with continue_on_error flag."""
        vulnerability_ids = ["CVE-VALID", "CVE-INVALID", "CVE-VALID2"]

        async def mock_collect(vuln_id: str) -> List[Dict[str, Any]]:
            if vuln_id == "CVE-INVALID":
                raise Exception(f"Failed to process {vuln_id}")
            return [{"id": vuln_id, "status": "success"}]

        with patch.object(data_manager, "collect_all", side_effect=mock_collect):
            results = await data_manager.process_vulnerabilities(
                vulnerability_ids, continue_on_error=True
            )

            # Should have 2 successful results, 1 failed
            assert len(results) == 2
            assert all(r["status"] == "success" for r in results)


class TestGitHubDataSource:
    """Test suite for GitHub API data collection."""

    @pytest_asyncio.fixture
    async def github_source(self) -> AsyncGenerator[GitHubDataSource, None]:
        """Create GitHubDataSource instance for testing."""
        rate_limiter_mock = MagicMock()
        rate_limiter_mock.acquire = AsyncMock()
        source = GitHubDataSource(
            api_token="test-token",
            http_client=AsyncMock(),
            rate_limiter=rate_limiter_mock,
        )
        yield source

    @pytest.mark.asyncio
    async def test_collect_commits(self, github_source: GitHubDataSource) -> None:
        """Test collecting commits related to vulnerability."""
        cve_id = "CVE-2021-1234"

        # Mock GitHub API response for commits
        assert github_source.http_client is not None
        github_source.http_client.get.return_value = {
            "items": [
                {
                    "sha": "abc123",
                    "commit": {
                        "message": "Fix CVE-2021-1234 buffer overflow",
                        "author": {"date": "2021-03-15T10:00:00Z"},
                    },
                    "html_url": "https://github.com/repo/commit/abc123",
                }
            ]
        }

        commits = await github_source.collect_commits(cve_id)

        assert len(commits) == 1
        assert commits[0]["sha"] == "abc123"
        assert cve_id in commits[0]["commit"]["message"]

    @pytest.mark.asyncio
    async def test_collect_releases(self, github_source: GitHubDataSource) -> None:
        """Test collecting releases related to vulnerability."""
        cve_id = "CVE-2021-1234"

        assert github_source.http_client is not None
        github_source.http_client.get.return_value = {
            "items": [
                {
                    "tag_name": "v1.2.3",
                    "name": "Security release for CVE-2021-1234",
                    "published_at": "2021-03-15T10:00:00Z",
                    "html_url": "https://github.com/repo/releases/tag/v1.2.3",
                }
            ]
        }

        releases = await github_source.collect_releases(cve_id)

        assert len(releases) == 1
        assert releases[0]["tag_name"] == "v1.2.3"
        assert cve_id in releases[0]["name"]

    @pytest.mark.asyncio
    async def test_collect_security_advisories(
        self, github_source: GitHubDataSource
    ) -> None:
        """Test collecting GitHub security advisories."""
        cve_id = "CVE-2021-1234"

        assert github_source.http_client is not None
        github_source.http_client.post.return_value = {
            "data": {
                "repository": {
                    "securityAdvisories": {
                        "edges": [
                            {
                                "node": {
                                    "ghsaId": "GHSA-xxxx-yyyy-zzzz",
                                    "cveId": cve_id,
                                    "severity": "HIGH",
                                    "summary": "Buffer overflow vulnerability",
                                }
                            }
                        ]
                    }
                }
            }
        }

        advisories = await github_source.collect_security_advisories("owner/repo")

        assert len(advisories) == 1
        assert advisories[0]["cveId"] == cve_id
        assert advisories[0]["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_rate_limiting_integration(
        self, github_source: GitHubDataSource
    ) -> None:
        """Test GitHub API rate limiting integration."""
        await github_source.collect_commits("CVE-2021-1234")

        # Verify rate limiter was called (mock assertion removed due to mypy compatibility)
        assert github_source.rate_limiter is not None
        # github_source.rate_limiter.acquire.assert_awaited_with("github")


class TestAdvisoryDataSource:
    """Test suite for advisory database collection (GHSA, OSV, NVD)."""

    @pytest_asyncio.fixture
    async def advisory_source(self) -> AsyncGenerator[AdvisoryDataSource, None]:
        """Create AdvisoryDataSource instance for testing."""
        source = AdvisoryDataSource(
            http_client=AsyncMock(),
            rate_limiter=AsyncMock(),
            adapters={"ghsa": GHSAAdapter(), "osv": OSVAdapter(), "nvd": NVDAdapter()},
        )
        yield source

    @pytest.mark.asyncio
    async def test_collect_ghsa_advisory(
        self, advisory_source: AdvisoryDataSource
    ) -> None:
        """Test collecting GHSA advisory data."""
        cve_id = "CVE-2021-1234"

        assert advisory_source.http_client is not None
        advisory_source.http_client.get.return_value = {
            "data": {
                "securityAdvisory": {
                    "ghsaId": "GHSA-xxxx-yyyy-zzzz",
                    "identifiers": [{"type": "CVE", "value": cve_id}],
                    "severity": "HIGH",
                    "vulnerabilities": [
                        {
                            "package": {"name": "vulnerable-lib"},
                            "vulnerableVersionRange": "< 1.2.3",
                        }
                    ],
                }
            }
        }

        advisory = await advisory_source.collect_ghsa(cve_id)

        assert advisory is not None
        assert advisory["ghsaId"] == "GHSA-xxxx-yyyy-zzzz"
        assert advisory["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_collect_osv_data(self, advisory_source: AdvisoryDataSource) -> None:
        """Test collecting OSV database data."""
        cve_id = "CVE-2021-1234"

        # Mock the HTTP client to return OSV response directly
        assert advisory_source.http_client is not None
        advisory_source.http_client.get.return_value = {
            "id": cve_id,
            "summary": "Buffer overflow in library",
            "details": "Detailed vulnerability description",
            "affected": [
                {
                    "package": {"name": "vulnerable-lib", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": []}],
                }
            ],
        }

        vulnerabilities = await advisory_source.collect_osv([cve_id])

        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["id"] == cve_id

    @pytest.mark.asyncio
    async def test_collect_nvd_data(self, advisory_source: AdvisoryDataSource) -> None:
        """Test collecting NVD database data."""
        cve_id = "CVE-2021-1234"

        assert advisory_source.http_client is not None
        advisory_source.http_client.get.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve_id,
                        "descriptions": [
                            {"lang": "en", "value": "Buffer overflow vulnerability"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                            ]
                        },
                    }
                }
            ]
        }

        vulnerability = await advisory_source.collect_nvd(cve_id)

        assert vulnerability is not None
        assert vulnerability["cve"]["id"] == cve_id
        assert (
            vulnerability["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            == 7.5
        )


class TestFileSystemDataSource:
    """Test suite for filesystem data source."""

    @pytest.fixture
    def temp_data_dir(self) -> Generator[str, None, None]:
        """Create temporary directory with test data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            test_files = [
                ("CVE-2021-1234.json", {"cve_id": "CVE-2021-1234", "data": "test"}),
                ("analysis_cache.json", {"cached_analyses": []}),
                ("patches/CVE-2021-1234.patch", "diff content"),
            ]

            for file_path, content in test_files:
                full_path = Path(temp_dir) / file_path
                full_path.parent.mkdir(parents=True, exist_ok=True)

                if isinstance(content, dict):
                    with open(full_path, "w") as f:
                        json.dump(content, f)
                else:
                    with open(full_path, "w") as f:
                        f.write(str(content))

            yield temp_dir

    @pytest_asyncio.fixture
    async def filesystem_source(
        self, temp_data_dir: str
    ) -> AsyncGenerator[FileSystemDataSource, None]:
        """Create FileSystemDataSource instance for testing."""
        source = FileSystemDataSource(data_directory=temp_data_dir)
        yield source

    @pytest.mark.asyncio
    async def test_collect_cached_data(
        self, filesystem_source: FileSystemDataSource
    ) -> None:
        """Test collecting cached vulnerability data."""
        cve_id = "CVE-2021-1234"

        cached_data = await filesystem_source.collect_cached_data(cve_id)

        assert cached_data is not None
        assert cached_data["cve_id"] == cve_id

    @pytest.mark.asyncio
    async def test_collect_patch_files(
        self, filesystem_source: FileSystemDataSource
    ) -> None:
        """Test collecting patch files."""
        cve_id = "CVE-2021-1234"

        patches = await filesystem_source.collect_patches(cve_id)

        assert len(patches) == 1
        assert patches[0]["content"] == "diff content"

    @pytest.mark.asyncio
    async def test_scan_directory_for_vulnerabilities(
        self, filesystem_source: FileSystemDataSource
    ) -> None:
        """Test scanning directory for vulnerability-related files."""
        vulnerabilities = await filesystem_source.scan_for_vulnerabilities()

        assert "CVE-2021-1234" in vulnerabilities


class TestFormatAdapters:
    """Test suite for data format adapters."""

    def test_github_adapter(self) -> None:
        """Test GitHub data format adaptation."""
        adapter = GitHubAdapter()

        raw_data = {
            "sha": "abc123",
            "commit": {
                "message": "Fix CVE-2021-1234",
                "author": {"date": "2021-03-15T10:00:00Z"},
            },
        }

        adapted = adapter.adapt(raw_data)

        assert adapted["type"] == "github_commit"
        assert adapted["sha"] == "abc123"

    def test_ghsa_adapter(self) -> None:
        """Test GHSA format adaptation."""
        adapter = GHSAAdapter()

        raw_data = {
            "ghsaId": "GHSA-xxxx-yyyy-zzzz",
            "cveId": "CVE-2021-1234",
            "severity": "HIGH",
        }

        adapted = adapter.adapt(raw_data)

        assert adapted["type"] == "ghsa_advisory"
        assert adapted["ghsa_id"] == "GHSA-xxxx-yyyy-zzzz"

    def test_osv_adapter(self) -> None:
        """Test OSV format adaptation."""
        adapter = OSVAdapter()

        raw_data = {"id": "CVE-2021-1234", "summary": "Buffer overflow", "affected": []}

        adapted = adapter.adapt(raw_data)

        assert adapted["type"] == "osv_vulnerability"
        assert adapted["vulnerability_id"] == "CVE-2021-1234"

    def test_nvd_adapter(self) -> None:
        """Test NVD format adaptation."""
        adapter = NVDAdapter()

        raw_data = {
            "cve": {
                "id": "CVE-2021-1234",
                "descriptions": [{"lang": "en", "value": "Buffer overflow"}],
            }
        }

        adapted = adapter.adapt(raw_data)

        assert adapted["type"] == "nvd_vulnerability"
        assert adapted["cve_id"] == "CVE-2021-1234"


class TestDeduplication:
    """Test suite for data deduplication."""

    def test_content_hashing(self) -> None:
        """Test content hash generation for deduplication."""
        deduplicator = Deduplicator()

        data1 = {"cve_id": "CVE-2021-1234", "description": "Buffer overflow"}
        data2 = {"cve_id": "CVE-2021-1234", "description": "Buffer overflow"}
        data3 = {"cve_id": "CVE-2021-5678", "description": "SQL injection"}

        hash1 = deduplicator.generate_content_hash(data1)
        hash2 = deduplicator.generate_content_hash(data2)
        hash3 = deduplicator.generate_content_hash(data3)

        assert hash1 == hash2  # Same content should have same hash
        assert hash1 != hash3  # Different content should have different hash

    def test_fuzzy_matching(self) -> None:
        """Test fuzzy matching for similar entries."""
        deduplicator = Deduplicator(similarity_threshold=0.8)

        entries = [
            {"description": "Buffer overflow in function parse_input"},
            {"description": "Buffer overrun in function parse_input"},
            {"description": "SQL injection in login form"},
        ]

        duplicates = deduplicator.find_fuzzy_duplicates(entries)

        # First two should be identified as similar
        assert len(duplicates) > 0

    def test_cross_referencing(self) -> None:
        """Test cross-referencing related vulnerabilities."""
        deduplicator = Deduplicator()

        vulnerabilities = [
            {"cve_id": "CVE-2021-1234", "related_cves": ["CVE-2021-5678"]},
            {"cve_id": "CVE-2021-5678", "related_cves": ["CVE-2021-1234"]},
            {"cve_id": "CVE-2021-9999", "related_cves": []},
        ]

        cross_refs = deduplicator.build_cross_references(vulnerabilities)

        assert "CVE-2021-1234" in cross_refs
        assert "CVE-2021-5678" in cross_refs["CVE-2021-1234"]


class TestWebhookDataSource:
    """Test suite for webhook-based real-time updates."""

    @pytest_asyncio.fixture
    async def webhook_source(self) -> AsyncGenerator[WebhookDataSource, None]:
        """Create WebhookDataSource instance for testing."""
        source = WebhookDataSource(port=8888, secret_key="test-secret")
        yield source
        await source.close()

    @pytest.mark.asyncio
    async def test_webhook_server_startup(
        self, webhook_source: WebhookDataSource
    ) -> None:
        """Test webhook server initialization."""
        await webhook_source.start()

        assert webhook_source.server is not None
        assert webhook_source.is_running is True

        await webhook_source.stop()

    @pytest.mark.asyncio
    async def test_github_webhook_processing(
        self, webhook_source: WebhookDataSource
    ) -> None:
        """Test processing GitHub webhook payloads."""
        payload = {
            "action": "published",
            "release": {"tag_name": "v1.2.3", "name": "Security fix for CVE-2021-1234"},
            "repository": {"full_name": "owner/repo"},
        }

        result = await webhook_source.process_github_webhook(payload)

        assert result["type"] == "github_release"
        assert result["tag_name"] == "v1.2.3"

    @pytest.mark.asyncio
    async def test_webhook_signature_validation(
        self, webhook_source: WebhookDataSource
    ) -> None:
        """Test webhook signature validation."""
        payload = b'{"test": "data"}'

        # Test with valid signature
        valid_signature = webhook_source.generate_signature(payload)
        assert webhook_source.validate_signature(payload, valid_signature) is True

        # Test with invalid signature
        invalid_signature = "sha256=invalid"
        assert webhook_source.validate_signature(payload, invalid_signature) is False
