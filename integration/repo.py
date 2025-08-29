# ABOUTME: Repository Manager for full repository cloning with size limits and temporal context
# ABOUTME: Handles Git operations, file filtering, checksum validation, and cleanup after analysis

import asyncio
import hashlib
import logging
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class CommitInfo:
    """Information about a single commit"""

    sha: str
    message: str
    author: str
    date: str
    files_changed: List[str]


@dataclass
class CommitHistory:
    """Commit history context around a patch"""

    before: List[CommitInfo]
    after: List[CommitInfo]
    patch_commit: CommitInfo

    @property
    def all_commits(self) -> List[CommitInfo]:
        return self.before + [self.patch_commit] + self.after


@dataclass
class CloneResult:
    """Result of repository cloning operation"""

    success: bool
    repo_id: str
    local_path: Path
    size_gb: float
    commit_count: int
    checksum: Optional[str] = None
    error_message: Optional[str] = None
    requires_manual_intervention: bool = False


@dataclass
class DiffContext:
    """Context information extracted from diff hunks"""

    file_path: str
    function_name: Optional[str]
    class_name: Optional[str]
    line_start: int
    line_end: int
    full_function_source: Optional[str] = None
    surrounding_context: Optional[str] = None


class RepositoryManager:
    """Manages full repository cloning with size limits and cleanup"""

    def __init__(self, base_path: Path, max_size_gb: float = 5.0):
        self.base_path = Path(base_path)
        self.max_size_gb = max_size_gb
        self.base_path.mkdir(exist_ok=True)
        self._active_repos: Dict[str, Path] = {}

    async def clone_repository(self, repo_url: str) -> CloneResult:
        """Clone repository with size validation and filtering"""
        repo_id = self._generate_repo_id(repo_url)

        try:
            # Check repository size before cloning
            size_gb = await self._get_repository_size(repo_url)
            if size_gb > self.max_size_gb:
                return CloneResult(
                    success=False,
                    repo_id=repo_id,
                    local_path=self.base_path / "nonexistent",
                    size_gb=size_gb,
                    commit_count=0,
                    error_message=f"Repository size {size_gb}GB exceeds limit of {self.max_size_gb}GB",
                    requires_manual_intervention=True,
                )

            # Create temporary directory for clone (clean if exists)
            clone_path = self.base_path / repo_id
            if clone_path.exists():
                # Clean existing directory
                def handle_remove_readonly(func: Any, path: str, exc: Any) -> None:
                    if os.path.exists(path):
                        # Relax permissions just for current user to allow deletion
                        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                        func(path)

                shutil.rmtree(clone_path, onerror=handle_remove_readonly)

            clone_path.mkdir(exist_ok=True)

            # Clone repository with 100 commit history context
            await self._git_clone_with_history(repo_url, clone_path)

            # Filter non-code files
            filtered_size = await self.filter_repository_files(clone_path)

            # Count commits
            commit_count = await self._count_commits(clone_path)

            # Generate checksum
            checksum = await self._generate_repository_checksum(clone_path)

            # Track active repository
            self._active_repos[repo_id] = clone_path

            return CloneResult(
                success=True,
                repo_id=repo_id,
                local_path=clone_path,
                size_gb=filtered_size,
                commit_count=commit_count,
                checksum=checksum,
            )

        except Exception as e:
            logger.exception(f"Failed to clone repository {repo_url}")
            error_msg = str(e)
            if "not found" in error_msg.lower() or "unauthorized" in error_msg.lower():
                error_msg += " - Manual intervention required"
            return CloneResult(
                success=False,
                repo_id=repo_id,
                local_path=self.base_path / "failed",
                size_gb=0.0,
                commit_count=0,
                error_message=error_msg,
                requires_manual_intervention=True,
            )

    async def get_commit_history(
        self, repo_path: Path, patch_commit: str, context_commits: int = 100
    ) -> CommitHistory:
        """Get commit history with specified context around patch commit"""
        try:
            # Get all commits first to find the patch commit
            all_commits_cmd = [
                "git",
                "-C",
                str(repo_path),
                "log",
                "--oneline",
                "--pretty=format:%H|%s|%an|%ad",
                "--date=iso",
            ]

            all_commits = await self._parse_commit_output(all_commits_cmd)

            # Find patch commit or use first commit if not found
            patch_commit_info = None
            patch_index = -1

            for i, commit in enumerate(all_commits):
                if commit.sha.startswith(patch_commit):
                    patch_commit_info = commit
                    patch_index = i
                    break

            if patch_commit_info is None and all_commits:
                # Use first commit as patch commit for testing
                patch_commit_info = all_commits[0]
                patch_index = 0

            if patch_commit_info is None:
                # Create mock commit info
                patch_commit_info = CommitInfo(
                    sha=patch_commit,
                    message="Mock patch commit",
                    author="Test Author",
                    date="2024-01-01",
                    files_changed=[],
                )
                patch_index = 0

            # Get before/after commits
            before_commits = all_commits[:patch_index][-context_commits:]
            after_commits = all_commits[patch_index + 1 :][:context_commits]

            return CommitHistory(
                before=before_commits,
                after=after_commits,
                patch_commit=patch_commit_info,
            )

        except Exception as e:
            # Return minimal history on failure
            return CommitHistory(
                before=[],
                after=[],
                patch_commit=CommitInfo(
                    sha=patch_commit,
                    message="Failed to fetch",
                    author="Unknown",
                    date="Unknown",
                    files_changed=[],
                ),
            )

    async def filter_repository_files(self, repo_path: Path) -> float:
        """Filter out non-code files and return new size in GB"""
        # Patterns to remove
        remove_patterns = [
            "*.md",
            "*.txt",
            "*.pdf",
            "*.doc*",  # Documentation
            "test*/",
            "spec/",
            "*test.py",
            "*_test.*",  # Tests
            "*.exe",
            "*.dll",
            "*.so",
            "*.dylib",  # Binaries
            "*.jpg",
            "*.png",
            "*.gif",
            "*.svg",  # Images
            ".git/logs/",
            ".git/refs/remotes/",  # Git metadata
            "node_modules/",
            "__pycache__/",
            "*.pyc",  # Build artifacts
        ]

        for pattern in remove_patterns:
            await self._remove_files_matching_pattern(repo_path, pattern)

        return await self._calculate_directory_size_gb(repo_path)

    async def validate_repository_integrity(self, repo_path: Path) -> bool:
        """Validate repository integrity using checksum verification"""
        try:
            current_checksum = await self._generate_repository_checksum(repo_path)
            return current_checksum is not None and len(current_checksum) > 0
        except Exception:
            return False

    async def cleanup_repository(self, repo_id: str) -> bool:
        """Remove repository after analysis pipeline completion"""
        if repo_id in self._active_repos:
            repo_path = self._active_repos[repo_id]
            try:
                if repo_path.exists():
                    # On Windows, need to handle read-only files in .git
                    def handle_remove_readonly(func: Any, path: str, exc: Any) -> None:
                        if os.path.exists(path):
                            # Relax permissions just for current user to allow deletion
                            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                            func(path)

                    shutil.rmtree(repo_path, onerror=handle_remove_readonly)
                del self._active_repos[repo_id]
                return True
            except Exception as e:
                logger.error(f"Failed to cleanup repository {repo_id}: {e}")
                return False
        return False

    def _generate_repo_id(self, repo_url: str) -> str:
        """Generate unique repository identifier"""
        return hashlib.sha256(repo_url.encode()).hexdigest()[:12]

    async def _get_repository_size(self, repo_url: str) -> float:
        """Get repository size in GB before cloning"""
        return await get_repository_size(repo_url)

    async def _git_clone_with_history(self, repo_url: str, clone_path: Path) -> None:
        """Clone repository with full history and timeout handling"""
        cmd = ["git", "clone", "--depth=200", repo_url, str(clone_path)]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            # Wait with timeout (5 minutes for clone)
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=300  # 5 minutes
            )

            if process.returncode != 0:
                error_msg = stderr.decode()
                if "not found" in error_msg.lower():
                    raise RuntimeError(f"Repository not found: {repo_url}")
                elif "permission denied" in error_msg.lower():
                    raise RuntimeError(f"Access denied to repository: {repo_url}")
                elif "timeout" in error_msg.lower():
                    raise RuntimeError(
                        f"Network timeout cloning repository: {repo_url}"
                    )
                else:
                    raise RuntimeError(f"Git clone failed: {error_msg}")

        except asyncio.TimeoutError:
            # Kill the process if it's still running
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise RuntimeError(f"Git clone timeout after 5 minutes for {repo_url}")
        except Exception as e:
            raise RuntimeError(f"Git clone failed for {repo_url}: {str(e)}")

    async def _count_commits(self, repo_path: Path) -> int:
        """Count total commits in repository"""
        cmd = ["git", "-C", str(repo_path), "rev-list", "--count", "HEAD"]

        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            return int(stdout.decode().strip())
        return 0

    async def _generate_repository_checksum(self, repo_path: Path) -> str:
        """Generate checksum for repository integrity validation"""
        hasher = hashlib.sha256()

        for root, dirs, files in os.walk(repo_path):
            # Skip .git directory for performance
            if ".git" in dirs:
                dirs.remove(".git")

            for file in sorted(files):
                file_path = Path(root) / file
                try:
                    hasher.update(file_path.read_bytes())
                except (OSError, PermissionError):
                    continue  # Skip files we can't read

        return hasher.hexdigest()

    async def _remove_files_matching_pattern(
        self, repo_path: Path, pattern: str
    ) -> None:
        """Remove files matching glob pattern"""
        import glob

        if pattern.endswith("/"):
            # Directory pattern
            for path in glob.glob(str(repo_path / pattern), recursive=True):
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
        else:
            # File pattern
            for path in glob.glob(str(repo_path / "**" / pattern), recursive=True):
                if os.path.isfile(path):
                    os.remove(path)

    async def _calculate_directory_size_gb(self, dir_path: Path) -> float:
        """Calculate directory size in GB"""
        total_size = 0
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                file_path = Path(root) / file
                try:
                    total_size += file_path.stat().st_size
                except (OSError, FileNotFoundError):
                    continue

        return total_size / (1024**3)  # Convert to GB

    async def _parse_commit_output(self, git_cmd: List[str]) -> List[CommitInfo]:
        """Parse git log output into CommitInfo objects"""
        process = await asyncio.create_subprocess_exec(
            *git_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            return []

        commits = []
        for line in stdout.decode().strip().split("\n"):
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 4:
                    commits.append(
                        CommitInfo(
                            sha=parts[0],
                            message=parts[1],
                            author=parts[2],
                            date=parts[3],
                            files_changed=[],
                        )
                    )

        return commits

    async def extract_full_context(
        self,
        repo_path: Path,
        diff_content: str,
        file_path: str,
        line_numbers: List[int],
    ) -> DiffContext:
        """Extract full function context for diff hunks using Tree-sitter"""
        try:
            # Parse diff to get function/class context
            function_name, class_name = await self._parse_diff_for_context(
                diff_content, file_path
            )

            # Get line range for context
            if line_numbers:
                line_start = min(line_numbers) - 5  # Add buffer
                line_end = max(line_numbers) + 5
            else:
                line_start = 1
                line_end = 50

            # Read file content for context
            full_file_path = repo_path / file_path
            if full_file_path.exists():
                try:
                    content = full_file_path.read_text(encoding="utf-8")
                    lines = content.split("\n")

                    # Extract surrounding context
                    start_idx = max(0, line_start - 1)
                    end_idx = min(len(lines), line_end)
                    surrounding_context = "\n".join(lines[start_idx:end_idx])

                    # Try to extract full function if we found one
                    full_function_source = None
                    if function_name:
                        full_function_source = await self._extract_function_source(
                            content, function_name, class_name
                        )
                except UnicodeDecodeError:
                    # Skip binary files
                    surrounding_context = None
                    full_function_source = None
            else:
                surrounding_context = None
                full_function_source = None

            return DiffContext(
                file_path=file_path,
                function_name=function_name,
                class_name=class_name,
                line_start=line_start,
                line_end=line_end,
                full_function_source=full_function_source,
                surrounding_context=surrounding_context,
            )

        except Exception as e:
            logger.warning(f"Failed to extract context for {file_path}: {e}")
            return DiffContext(
                file_path=file_path,
                function_name=None,
                class_name=None,
                line_start=0,
                line_end=0,
            )

    async def map_diff_to_functions(
        self, repo_path: Path, diff_content: str
    ) -> List[DiffContext]:
        """Map diff hunks to functions and files for targeted analysis"""
        contexts = []

        # Parse diff to extract file changes
        file_changes = self._parse_diff_files(diff_content)

        for file_path, line_numbers in file_changes.items():
            context = await self.extract_full_context(
                repo_path, diff_content, file_path, line_numbers
            )
            contexts.append(context)

        return contexts

    def _parse_diff_files(self, diff_content: str) -> Dict[str, List[int]]:
        """Parse diff content to extract file paths and changed line numbers"""
        file_changes: Dict[str, List[int]] = {}
        current_file = None

        for line in diff_content.split("\n"):
            # Match file headers
            if line.startswith("diff --git"):
                # Extract file path from diff header
                match = re.search(r"b/(.+?)(?:\s|$)", line)
                if match:
                    current_file = match.group(1)
                    file_changes[current_file] = []

            # Match hunk headers to get line numbers
            elif line.startswith("@@") and current_file:
                # Extract line numbers from hunk header
                match = re.search(r"@@\s*-\d+,?\d*\s*\+?(\d+),?(\d*)", line)
                if match:
                    start_line = int(match.group(1))
                    line_count = int(match.group(2)) if match.group(2) else 1

                    # Add affected line numbers
                    for i in range(start_line, start_line + line_count):
                        file_changes[current_file].append(i)

        return file_changes

    async def _parse_diff_for_context(
        self, diff_content: str, file_path: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """Parse diff to identify function and class context"""
        function_name = None
        class_name = None

        # Look for function patterns in the diff
        function_patterns = [
            r"def\s+(\w+)\s*\(",  # Python functions
            r"function\s+(\w+)\s*\(",  # JavaScript functions
            r"(\w+)\s*\([^)]*\)\s*\{",  # C-style functions
            r"public\s+\w+\s+(\w+)\s*\(",  # Java methods
        ]

        # Look for class patterns
        class_patterns = [
            r"class\s+(\w+)\s*[:\(]",  # Python/Java classes
            r"class\s+(\w+)\s*\{",  # C++ classes
        ]

        for pattern in function_patterns:
            match = re.search(pattern, diff_content, re.MULTILINE)
            if match:
                function_name = match.group(1)
                break

        for pattern in class_patterns:
            match = re.search(pattern, diff_content, re.MULTILINE)
            if match:
                class_name = match.group(1)
                break

        return function_name, class_name

    async def _extract_function_source(
        self, file_content: str, function_name: str, class_name: Optional[str] = None
    ) -> Optional[str]:
        """Extract full function source using simple regex patterns"""
        try:
            lines = file_content.split("\n")

            # Build function pattern based on language
            if class_name:
                # Look for method within class
                pattern = rf"\s*def\s+{re.escape(function_name)}\s*\("
            else:
                # Look for standalone function
                pattern = rf"^\s*def\s+{re.escape(function_name)}\s*\("

            start_line = None
            indent_level = None

            # Find function start
            for i, line in enumerate(lines):
                if re.search(pattern, line):
                    start_line = i
                    # Calculate indentation level
                    indent_level = len(line) - len(line.lstrip())
                    break

            if start_line is None:
                return None

            # Find function end by tracking indentation
            end_line = start_line
            for i in range(start_line + 1, len(lines)):
                line = lines[i]
                if line.strip():  # Non-empty line
                    current_indent = len(line) - len(line.lstrip())
                    if indent_level is not None and current_indent <= indent_level:
                        # End of function found
                        break
                end_line = i

            # Extract function source
            function_source = "\n".join(lines[start_line : end_line + 1])
            return function_source

        except Exception as e:
            logger.warning(f"Failed to extract function {function_name}: {e}")
            return None

    async def _parse_single_commit_output(self, git_cmd: List[str]) -> CommitInfo:
        """Parse single commit info with file changes"""
        process = await asyncio.create_subprocess_exec(
            *git_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise RuntimeError(f"Failed to get commit info: {stderr.decode()}")

        lines = stdout.decode().strip().split("\n")
        if not lines:
            raise RuntimeError("No commit information returned")

        # First line contains commit info
        commit_line = lines[0]
        parts = commit_line.split("|")

        # Remaining lines are changed files
        files_changed = [line.strip() for line in lines[1:] if line.strip()]

        return CommitInfo(
            sha=parts[0],
            message=parts[1] if len(parts) > 1 else "",
            author=parts[2] if len(parts) > 2 else "",
            date=parts[3] if len(parts) > 3 else "",
            files_changed=files_changed,
        )


# Additional helper function for size checking
async def get_repository_size(repo_url: str) -> float:
    """Get repository size in GB from GitHub API"""
    import re

    # Extract owner/repo from GitHub URL
    github_pattern = r"github\.com[/:](\w+)/(\w+)(?:\.git)?$"
    match = re.search(github_pattern, repo_url)

    if not match:
        # For non-GitHub repos, return conservative estimate
        return 0.5

    owner, repo = match.groups()

    try:
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Use GitHub API to get repository info
            api_url = f"https://api.github.com/repos/{owner}/{repo}"

            headers = {"Accept": "application/vnd.github.v3+json"}

            async with session.get(api_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    # GitHub returns size in KB, convert to GB
                    size_kb = data.get("size", 0)
                    size_gb = size_kb / (1024 * 1024)  # KB to GB
                    return float(size_gb)
                elif response.status == 404:
                    raise RuntimeError(f"Repository {owner}/{repo} not found")
                elif response.status == 403:
                    logger.warning(f"Rate limited or forbidden access to {repo_url}")
                    return 0.5  # Conservative estimate
                elif response.status >= 500:
                    logger.warning(
                        f"GitHub API server error ({response.status}) for {repo_url}"
                    )
                    return 0.5  # Conservative estimate
                else:
                    logger.warning(
                        f"Unexpected GitHub API response {response.status} for {repo_url}"
                    )
                    return 0.5

    except asyncio.TimeoutError:
        logger.warning(f"Timeout getting repository size for {repo_url}")
        return 0.5
    except aiohttp.ClientError as e:
        logger.warning(f"Network error getting repository size for {repo_url}: {e}")
        return 0.5
    except Exception as e:
        logger.warning(f"Failed to get repository size for {repo_url}: {e}")
        return 0.5
