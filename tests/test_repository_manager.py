# ABOUTME: Tests for Repository Manager with full clone, history context, and cleanup functionality
# ABOUTME: Covers TDD implementation of repository cloning, file filtering, and integration testing

import asyncio
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from integration.repo import RepositoryManager


class TestRepositoryManager:
    """Test Repository Manager implementation with TDD approach"""

    @pytest.fixture
    def temp_dir(self) -> Generator[Path, None, None]:
        """Create temporary directory for test repositories"""
        temp_path = tempfile.mkdtemp()
        yield Path(temp_path)
        shutil.rmtree(temp_path, ignore_errors=True)

    @pytest.fixture
    def repo_manager(self, temp_dir: Path) -> RepositoryManager:
        """Create Repository Manager instance with temporary storage"""
        return RepositoryManager(base_path=temp_dir, max_size_gb=5)

    @pytest.mark.asyncio
    async def test_clone_public_repository_success(
        self, repo_manager: RepositoryManager, temp_dir: Path
    ) -> None:
        """Test successful cloning of public repository under size limit"""
        # This test should fail initially - Repository Manager doesn't exist yet
        repo_url = "https://github.com/octocat/Hello-World.git"

        result = await repo_manager.clone_repository(repo_url)

        assert result.success is True
        assert result.local_path.exists()
        assert result.local_path.is_dir()
        assert result.size_gb <= 5
        assert result.commit_count > 0

    @pytest.mark.asyncio
    async def test_clone_repository_size_limit_exceeded(
        self, repo_manager: RepositoryManager
    ) -> None:
        """Test fast-fail when repository exceeds 5GB limit"""
        # Mock a large repository
        large_repo_url = "https://github.com/large/repository.git"

        with patch("integration.repo.get_repository_size") as mock_size:
            mock_size.return_value = 6.0  # 6GB - exceeds limit

            result = await repo_manager.clone_repository(large_repo_url)

            assert result.success is False
            # Ensure error_message is present before using it
            assert result.error_message is not None
            assert "exceeds limit" in result.error_message.lower()
            assert not result.local_path.exists()

    @pytest.mark.asyncio
    async def test_get_commit_history_with_context(
        self, repo_manager: RepositoryManager, temp_dir: Path
    ) -> None:
        """Test fetching 100 commits before/after patch for temporal context"""
        repo_url = "https://github.com/octocat/Hello-World.git"

        # First clone repository
        clone_result = await repo_manager.clone_repository(repo_url)

        # Use the first commit from the repository as patch commit
        history = await repo_manager.get_commit_history(
            clone_result.local_path,
            "HEAD",  # Use HEAD as patch commit for testing
            context_commits=10,  # Reduce for faster testing
        )

        assert len(history.before) <= 10
        assert len(history.after) <= 10
        assert history.patch_commit is not None
        assert history.patch_commit.sha is not None

    @pytest.mark.asyncio
    async def test_filter_non_code_files(
        self, repo_manager: RepositoryManager, temp_dir: Path
    ) -> None:
        """Test post-clone filtering of binaries, docs, tests"""
        # Create mock repository structure
        mock_repo = temp_dir / "test_repo"
        mock_repo.mkdir()

        # Create various file types
        (mock_repo / "src" / "main.py").parent.mkdir(exist_ok=True)
        (mock_repo / "src" / "main.py").write_text("print('hello')")
        (mock_repo / "README.md").write_text("# Documentation")
        (mock_repo / "tests" / "test_main.py").parent.mkdir(exist_ok=True)
        (mock_repo / "tests" / "test_main.py").write_text("def test(): pass")
        (mock_repo / "binary.exe").write_bytes(b"\x00\x01\x02")

        filtered_size = await repo_manager.filter_repository_files(mock_repo)

        assert (mock_repo / "src" / "main.py").exists()  # Keep source
        assert not (mock_repo / "README.md").exists()  # Remove docs
        assert not (mock_repo / "tests").exists()  # Remove tests
        assert not (mock_repo / "binary.exe").exists()  # Remove binaries
        assert filtered_size < 5.0  # Under size limit

    @pytest.mark.asyncio
    async def test_cleanup_after_analysis_pipeline(
        self, repo_manager: RepositoryManager, temp_dir: Path
    ) -> None:
        """Test repository cleanup only after complete analysis pipeline"""
        repo_url = "https://github.com/octocat/Hello-World.git"

        clone_result = await repo_manager.clone_repository(repo_url)
        original_path = clone_result.local_path
        repo_id = clone_result.repo_id

        # Repository should exist during analysis
        assert original_path.exists()
        assert clone_result.success is True

        # Cleanup should only happen when explicitly called
        cleanup_success = await repo_manager.cleanup_repository(repo_id)

        assert cleanup_success is True
        assert not original_path.exists()

    @pytest.mark.asyncio
    async def test_checksum_validation(
        self, repo_manager: RepositoryManager, temp_dir: Path
    ) -> None:
        """Test checksum validation for data integrity"""
        repo_url = "https://github.com/octocat/Hello-World.git"

        clone_result = await repo_manager.clone_repository(repo_url)

        # Validate repository integrity
        is_valid = await repo_manager.validate_repository_integrity(
            clone_result.local_path
        )

        assert is_valid is True
        assert clone_result.checksum is not None
        assert len(clone_result.checksum) > 0

    @pytest.mark.asyncio
    async def test_manual_intervention_on_failure(
        self, repo_manager: RepositoryManager
    ) -> None:
        """Test manual intervention trigger on repository failures"""
        invalid_repo_url = "https://github.com/nonexistent/repository.git"

        result = await repo_manager.clone_repository(invalid_repo_url)

        assert result.success is False
        assert result.requires_manual_intervention is True
        # Ensure error_message is present before using it
        assert result.error_message is not None
        assert "manual intervention" in result.error_message.lower()
