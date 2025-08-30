# ABOUTME: Main execution flow for generalized GHSA advisory vulnerability analysis
# ABOUTME: CLI interface to analyze any GHSA advisory with multi-language Tree-sitter support

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Load environment variables from .env file
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from agents.collector import AsyncHTTPClient
from agents.data_sources import AdvisoryDataSource, GitHubDataSource
from agents.rate_limiter import (
    APIRateLimiter,
    GitHubRateLimiter,
    NVDRateLimiter,
    RateLimiter,
)
from analysis.callgraph import CallGraphBuilder
from analysis.context import CodeContextExtractor
from integration.repo import RepositoryManager
from models import VulnerabilityReport
from parsers.advisory import MultiFormatAdvisoryParser
from parsers.diff import UnifiedDiffParser


def detect_primary_language(file_paths: List[str]) -> str:
    """Detect primary programming language from file paths"""
    language_counts = {}

    # Language mapping based on file extensions
    language_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "javascript",
        ".jsx": "javascript",
        ".tsx": "javascript",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
        ".go": "go",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".cs": "csharp",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
    }

    # Special files that indicate language
    special_files = {
        "Gemfile": "ruby",
        "Rakefile": "ruby",
        "package.json": "javascript",
        "pom.xml": "java",
        "build.gradle": "java",
        "Cargo.toml": "rust",
        "go.mod": "go",
        "requirements.txt": "python",
        "setup.py": "python",
        "pyproject.toml": "python",
    }

    for file_path in file_paths:
        file_name = Path(file_path).name
        file_ext = Path(file_path).suffix.lower()

        # Check special files first
        if file_name in special_files:
            lang = special_files[file_name]
            language_counts[lang] = language_counts.get(lang, 0) + 2  # Higher weight

        # Check file extensions
        elif file_ext in language_map:
            lang = language_map[file_ext]
            language_counts[lang] = language_counts.get(lang, 0) + 1

    if not language_counts:
        return "unknown"

    # Return language with highest count
    return max(language_counts.items(), key=lambda x: x[1])[0]


class VulnerabilityAnalyzer:
    """Generalized vulnerability analyzer for any GHSA advisory"""

    def __init__(self, github_token: str, output_dir: Optional[Path] = None, include_raw_advisory: bool = False):
        self.github_token = github_token
        self.output_dir = output_dir or Path(".")
        self.include_raw_advisory = include_raw_advisory

        # Initialize components
        self.http_client = AsyncHTTPClient(max_retries=2, timeout=30.0)
        self.rate_limiter = APIRateLimiter(
            {
                "github": GitHubRateLimiter(requests_per_hour=5000),
                "ghsa": GitHubRateLimiter(requests_per_hour=5000),
                "nvd": NVDRateLimiter(requests_per_30_seconds=50),
                "osv": RateLimiter(requests_per_second=10, burst_size=20),
            }
        )
        self.advisory_parser = MultiFormatAdvisoryParser()
        self.diff_parser = UnifiedDiffParser()
        
        # Initialize GitHub data source
        self.github_source = GitHubDataSource(
            api_token=github_token,
            http_client=self.http_client,
            rate_limiter=self.rate_limiter
        )

    async def analyze(self, ghsa_id: str) -> Dict[str, Any]:
        """Analyze a GHSA advisory and return structured results"""
        print(f"Analyzing GHSA Advisory: {ghsa_id}")
        print("=" * 60)

        try:
            # Step 1: Fetch GHSA Advisory
            print(f"\n1. Fetching GHSA Advisory: {ghsa_id}")
            ghsa_data = await self._fetch_ghsa_advisory(ghsa_id)
            if not ghsa_data:
                return {
                    "ghsa_id": ghsa_id,
                    "status": "error",
                    "error": "Failed to fetch GHSA advisory",
                }

            print(
                f"   [OK] GHSA fetched: {ghsa_data.get('summary', 'No summary')[:80]}..."
            )

            # Step 2: Discover related data sources
            print("\n2. Discovering Related Data Sources...")
            cve_id, commit_urls = await self._discover_related_data(ghsa_data)
            print(f"   [OK] CVE ID: {cve_id or 'Not found'}")
            print(f"   [OK] Commit URLs: {len(commit_urls)} found")

            # Step 3: Collect additional advisory data
            nvd_data = None
            osv_data = []

            if cve_id:
                print(f"\n3. Fetching Additional Advisory Data for {cve_id}")
                advisory_source = AdvisoryDataSource(
                    http_client=self.http_client, rate_limiter=self.rate_limiter
                )

                nvd_data = await advisory_source.collect_nvd(cve_id)
                if nvd_data:
                    print(f"   [OK] NVD data retrieved")

                osv_data = await advisory_source.collect_osv([cve_id])
                print(f"   [OK] OSV entries: {len(osv_data)}")

            # Step 4: Analyze repository context
            print(f"\n4. Analyzing Repository Context")
            repository_context = await self._analyze_repository_context(commit_urls)

            # Step 5: Collect and parse commit data
            print(f"\n5. Fetching and Parsing Commit Data")
            commits, parsed_diffs = await self._process_commits(commit_urls)

            # Step 6: Parse all collected data
            print(f"\n6. Parsing Collected Data...")
            parsed_advisory, parsed_nvd, parsed_osv = await self._parse_advisory_data(
                ghsa_data, nvd_data, osv_data
            )

            # Step 7: Create structured output
            print(f"\n7. Creating Structured Output...")
            full_output = await self._create_full_output(
                ghsa_id,
                ghsa_data,
                nvd_data,
                osv_data,
                commits,
                parsed_diffs,
                parsed_advisory,
                repository_context,
            )

            # Step 8: Create optimized AI context
            optimized_context = await self._optimize_context_for_ai(
                ghsa_id, ghsa_data, parsed_diffs, parsed_advisory, repository_context
            )

            # Step 9: Save outputs
            await self._save_outputs(ghsa_id, full_output, optimized_context)

            print(f"\n8. Analysis Complete")
            return {
                "ghsa_id": ghsa_id,
                "status": "success",
                "full_output": full_output,
                "optimized_context": optimized_context,
            }

        except Exception as e:
            print(f"ERROR during analysis: {e}")
            import traceback

            traceback.print_exc()
            return {"ghsa_id": ghsa_id, "status": "error", "error": str(e)}

        finally:
            await self.http_client.close()

    async def _fetch_ghsa_advisory(self, ghsa_id: str) -> Optional[Dict[str, Any]]:
        """Fetch GHSA advisory data"""
        advisory_url = f"https://api.github.com/advisories/{ghsa_id}"
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            return await self.http_client.get(advisory_url, headers=headers)
        except Exception as e:
            print(f"   [!] Failed to fetch GHSA advisory: {e}")
            return None

    async def _discover_related_data(
        self, ghsa_data: Dict[str, Any]
    ) -> Tuple[Optional[str], List[str]]:
        """Extract CVE ID and commit references from GHSA advisory"""
        # Extract CVE ID
        cve_id = ghsa_data.get("cve_id")
        if not cve_id:
            identifiers = ghsa_data.get("identifiers", [])
            for ident in identifiers:
                if isinstance(ident, dict) and ident.get("type") == "CVE":
                    cve_id = ident.get("value")
                    break

        # Extract commit URLs using GitHubDataSource
        commit_urls = self.github_source.extract_github_urls(ghsa_data)

        return cve_id, commit_urls

    async def _analyze_repository_context(
        self, commit_urls: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Analyze repository context using Tree-sitter"""
        if not commit_urls:
            return None

        commit_url = commit_urls[0]
        if "/commit/" not in commit_url and "/pull/" not in commit_url:
            return None

        # Extract repo URL from either commit or pull request URL
        if "/commit/" in commit_url:
            repo_url = commit_url.split("/commit/")[0] + ".git"
        elif "/pull/" in commit_url:
            repo_url = commit_url.split("/pull/")[0] + ".git"
        else:
            return None
        print(f"   [INFO] Analyzing repository context for: {repo_url}")

        temp_dir = Path("temp_repos")
        repo_manager = RepositoryManager(temp_dir, max_size_gb=2.0)
        context_extractor = CodeContextExtractor()
        call_graph_builder = CallGraphBuilder()

        try:
            # Clone repository
            clone_result = await repo_manager.clone_repository(repo_url)
            if not clone_result.success:
                print(f"   [!] Repository cloning failed: {clone_result.error_message}")
                return None

            print(
                f"   [OK] Repository cloned: {clone_result.size_gb:.2f}GB, {clone_result.commit_count} commits"
            )

            # Get modified files from commits
            modified_files = await self._get_modified_files(
                commit_urls, clone_result.local_path
            )

            # Detect primary language
            language = detect_primary_language(modified_files)
            print(f"   [OK] Detected language: {language}")

            # Filter files by detected language
            filtered_files = self._filter_files_by_language(
                modified_files, language, clone_result.local_path
            )
            print(f"   [OK] Found {len(filtered_files)} {language} files to analyze")

            # Build call graph
            call_graph = call_graph_builder.build_call_graph(
                filtered_files, max_depth=2
            )
            graph_stats = call_graph_builder.get_graph_statistics(call_graph)

            print(
                f"   [OK] Call graph built: {graph_stats['total_functions']} functions, {graph_stats['resolution_rate']:.1%} call resolution"
            )

            # Extract vulnerable functions
            vulnerable_functions = await self._extract_vulnerable_functions(
                filtered_files,
                context_extractor,
                call_graph_builder,
                call_graph,
                clone_result.local_path,
            )

            # Cleanup
            await repo_manager.cleanup_repository(clone_result.repo_id)

            return {
                "repository_url": repo_url,
                "language": language,
                "clone_stats": {
                    "size_gb": clone_result.size_gb,
                    "commit_count": clone_result.commit_count,
                    "files_analyzed": len(filtered_files),
                },
                "call_graph_stats": graph_stats,
                "vulnerable_functions": vulnerable_functions,
            }

        except Exception as e:
            print(f"   [!] Repository analysis failed: {e}")
            try:
                await repo_manager.cleanup_repository(
                    clone_result.repo_id if "clone_result" in locals() else "unknown"
                )
            except:
                pass
            return None

    async def _get_modified_files(
        self, commit_urls: List[str], repo_path: Path
    ) -> List[str]:
        """Get list of modified files from commit URLs"""
        modified_files = []

        for commit_url in commit_urls[:3]:  # Limit to first 3 commits
            # Use GitHubDataSource to get commit data (handles both commits and PRs)
            commit_data = await self.github_source.fetch_commit_data(commit_url)
            if not commit_data:
                continue
                
            sha = commit_data["commit"]["sha"]

            cmd = ["git", "-C", str(repo_path), "diff-tree", "--name-only", "-r", sha]
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()

            if process.returncode == 0:
                files = [
                    line.strip() for line in stdout.decode().split("\n") if line.strip()
                ]
                modified_files.extend(files)

        return list(set(modified_files))  # Remove duplicates

    def _filter_files_by_language(
        self, files: List[str], language: str, repo_path: Path
    ) -> List[str]:
        """Filter files based on detected language"""
        language_extensions = {
            "ruby": [".rb"],
            "python": [".py"],
            "javascript": [".js", ".ts", ".jsx", ".tsx"],
            "java": [".java"],
            "php": [".php"],
            "go": [".go"],
            "rust": [".rs"],
            "c": [".c", ".h"],
            "cpp": [".cpp", ".cc", ".cxx", ".hpp"],
            "csharp": [".cs"],
            "swift": [".swift"],
            "kotlin": [".kt"],
            "scala": [".scala"],
        }

        if language not in language_extensions:
            return [
                str(repo_path / f) for f in files
            ]  # Return all files if unknown language

        extensions = language_extensions[language]
        filtered = []

        for file_path in files:
            if any(file_path.endswith(ext) for ext in extensions):
                full_path = str(repo_path / file_path)
                if Path(full_path).exists():
                    filtered.append(full_path)

        return filtered

    async def _extract_vulnerable_functions(
        self,
        file_paths: List[str],
        context_extractor: CodeContextExtractor,
        call_graph_builder: CallGraphBuilder,
        call_graph: Dict[str, Any],
        repo_path: Path,
    ) -> List[Dict[str, Any]]:
        """Extract vulnerable functions with context"""
        vulnerable_functions = []

        for file_path in file_paths:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                context = context_extractor.extract_context(file_path, content)

                for func in context.primary_functions:
                    callers = call_graph_builder.get_function_callers(
                        call_graph, func.name, file_path
                    )
                    caller_info = [
                        {
                            "name": c.function_name,
                            "file": c.file_path,
                            "lines": f"{c.start_line}-{c.end_line}",
                        }
                        for c in callers
                    ]

                    vulnerable_functions.append(
                        {
                            "name": func.name,
                            "file": file_path.replace(str(repo_path) + os.sep, ""),
                            "lines": f"{func.start_line}-{func.end_line}",
                            "parameters": func.parameters,
                            "calls_made": func.calls_made,
                            "variables_used": func.variables_used,
                            "full_text": func.full_text,
                            "callers": caller_info,
                        }
                    )
            except Exception as e:
                print(f"   [!] Failed to analyze {file_path}: {e}")
                continue

        return vulnerable_functions

    async def _process_commits(
        self, commit_urls: List[str]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Process commit data and parse diffs"""
        commits = []
        parsed_diffs = []

        print(f"   Processing {len(commit_urls)} commits...")

        for i, commit_url in enumerate(commit_urls[:3]):
            commit_data = await self.github_source.fetch_commit_data(commit_url)
            if commit_data:
                commits.append(commit_data)

                # Parse diff
                diff_text = commit_data.get("diff", "")
                if diff_text:
                    analysis_result = self.diff_parser.parse_and_analyze(diff_text)
                    parsed_diffs.append(
                        {
                            "commit_sha": commit_data["commit"].get("sha", "Unknown")[
                                :8
                            ],
                            "parsed_hunks": analysis_result["hunks"],
                            "security_matches": analysis_result["security_matches"],
                            "summary": analysis_result["summary"],
                            "raw_diff": diff_text,
                        }
                    )

                print(
                    f"   [OK] Commit {i+1}: {commit_data['commit'].get('sha', 'Unknown')[:8]}..."
                )

        return commits, parsed_diffs


    async def _parse_advisory_data(
        self,
        ghsa_data: Dict[str, Any],
        nvd_data: Optional[Dict[str, Any]],
        osv_data: List[Dict[str, Any]],
    ) -> Tuple[
        Optional[VulnerabilityReport],
        Optional[VulnerabilityReport],
        List[VulnerabilityReport],
    ]:
        """Parse advisory data from all sources"""
        parsed_advisory = None
        parsed_nvd = None
        parsed_osv = []

        try:
            parsed_advisory = self.advisory_parser.parse(ghsa_data)
            print(f"   [OK] GHSA parsed: {parsed_advisory.advisory_id}")
        except Exception as e:
            print(f"   [!] GHSA parsing failed: {e}")

        if nvd_data:
            try:
                parsed_nvd = self.advisory_parser.parse(nvd_data)
                print(f"   [OK] NVD parsed: {parsed_nvd.advisory_id}")
            except Exception as e:
                print(f"   [!] NVD parsing failed: {e}")

        for i, osv_entry in enumerate(osv_data):
            try:
                parsed_entry = self.advisory_parser.parse(osv_entry)
                parsed_osv.append(parsed_entry)
                print(f"   [OK] OSV entry {i+1} parsed: {parsed_entry.advisory_id}")
            except Exception as e:
                print(f"   [!] OSV entry {i+1} parsing failed: {e}")

        return parsed_advisory, parsed_nvd, parsed_osv

    async def _create_full_output(
        self,
        ghsa_id: str,
        ghsa_data: Dict[str, Any],
        nvd_data: Optional[Dict[str, Any]],
        osv_data: List[Dict[str, Any]],
        commits: List[Dict[str, Any]],
        parsed_diffs: List[Dict[str, Any]],
        parsed_advisory: Optional[VulnerabilityReport],
        repository_context: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Create complete structured output"""
        return {
            "collection_metadata": {
                "ghsa_id": ghsa_id,
                "timestamp": datetime.now().isoformat(),
                "sources_collected": {
                    "ghsa": ghsa_data is not None,
                    "nvd": nvd_data is not None,
                    "osv": len(osv_data),
                    "commits": len(commits),
                    "repository_context": repository_context is not None,
                },
                "parsing_success": {
                    "advisory_parsed": parsed_advisory is not None,
                    "diffs_parsed": len(parsed_diffs),
                },
                "detected_language": (
                    repository_context.get("language")
                    if repository_context
                    else "unknown"
                ),
            },
            "vulnerability": {
                "id": ghsa_id,
                "title": (
                    parsed_advisory.title
                    if parsed_advisory
                    else ghsa_data.get("summary", "")
                ),
                "severity": (
                    parsed_advisory.severity
                    if parsed_advisory
                    else ghsa_data.get("severity", "unknown")
                ),
                "cwe_ids": parsed_advisory.cwe_ids if parsed_advisory else [],
                "description": (
                    parsed_advisory.description
                    if parsed_advisory
                    else ghsa_data.get("description", "")
                ),
            },
            "security_analysis": {
                "patterns_detected": [
                    self._extract_pattern_info(match)
                    for diff in parsed_diffs
                    for match in diff.get("security_matches", [])
                ],
                "key_functions": (
                    repository_context.get("vulnerable_functions", [])
                    if repository_context
                    else []
                ),
                "call_graph_summary": (
                    repository_context.get("call_graph_stats", {})
                    if repository_context
                    else {}
                ),
                "raw_diffs": [
                    {
                        "commit_sha": diff.get("commit_sha", "unknown"),
                        "raw_diff": diff.get("raw_diff", ""),
                        "files_changed": [h.file_path for h in diff.get("parsed_hunks", [])],
                        "summary": diff.get("summary", {})
                    }
                    for diff in parsed_diffs
                ],
            },
            "cross_references": {
                "cve_id": ghsa_data.get("cve_id"),
                "commit_count": len(commits),
                "nvd_available": nvd_data is not None,
                "osv_count": len(osv_data),
            },
            "diff_summary": {
                "hunks_analyzed": sum(
                    len(d.get("parsed_hunks", [])) for d in parsed_diffs
                ),
                "security_issues_found": sum(
                    len(d.get("security_matches", [])) for d in parsed_diffs
                ),
                "files_modified": len(
                    set(
                        h.file_path
                        for d in parsed_diffs
                        for h in d.get("parsed_hunks", [])
                    )
                ),
            },
        }

    async def _optimize_context_for_ai(
        self,
        ghsa_id: str,
        ghsa_data: Dict[str, Any],
        parsed_diffs: List[Dict[str, Any]],
        parsed_advisory: Optional[VulnerabilityReport],
        repository_context: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Create optimized context for AI analysis"""
        # Filter key functions (exclude modules/classes)
        key_functions = []
        if repository_context:
            all_functions = repository_context.get("vulnerable_functions", [])

            for func in all_functions:
                if func["name"].startswith(("module_", "class_")):
                    continue
                if not func["parameters"] and len(func["calls_made"]) < 3:
                    continue

                generic_calls = ["attr_writer", "extend", "send", "for", "new"]
                real_calls = [
                    call
                    for call in func["calls_made"]
                    if not any(g in call for g in generic_calls)
                ]

                if len(real_calls) == 0 and not func["callers"]:
                    continue

                key_functions.append(
                    {
                        "name": func["name"],
                        "file": Path(func["file"]).name,
                        "lines": func["lines"],
                        "parameters": func["parameters"],
                        "key_calls": real_calls[:8],
                        "callers": [
                            {"name": c["name"], "file": Path(c["file"]).name}
                            for c in func["callers"]
                        ],
                        "full_source": func["full_text"],  # Include FULL source for AI analysis
                        "source_preview": (
                            func["full_text"][:200] + "..."
                            if len(func["full_text"]) > 200
                            else func["full_text"]
                        ),
                    }
                )

        # Enhanced security patterns with code context
        security_issues = []
        for diff in parsed_diffs:
            for match in diff.get("security_matches", []):
                pattern_info = self._extract_pattern_info(match)
                security_issues.append(pattern_info)

        # Collect all raw diffs for exploit generation
        raw_diffs = []
        for diff in parsed_diffs:
            raw_diffs.append({
                "commit_sha": diff.get("commit_sha", "unknown"),
                "raw_diff": diff.get("raw_diff", ""),
                "files_changed": [h.file_path for h in diff.get("parsed_hunks", [])],
                "summary": diff.get("summary", {})
            })
        
        # Build base context data
        context_data = {
            "vulnerability": {
                "id": ghsa_id,
                "title": (
                    parsed_advisory.title
                    if parsed_advisory
                    else ghsa_data.get("summary", "")
                ),
                "severity": (
                    parsed_advisory.severity
                    if parsed_advisory
                    else ghsa_data.get("severity", "unknown")
                ),
                "cwe_ids": parsed_advisory.cwe_ids if parsed_advisory else [],
                "description": (
                    parsed_advisory.description
                    if parsed_advisory
                    else ghsa_data.get("description", "")
                ),
            },
            "security_analysis": {
                "patterns_detected": security_issues,
                "key_functions": key_functions,
                "call_graph_summary": (
                    repository_context.get("call_graph_stats", {})
                    if repository_context
                    else {}
                ),
            },
            "raw_diffs": raw_diffs,  # Essential for exploit generation per updated-plan.md
            "cross_references": {
                "cve_id": ghsa_data.get("cve_id"),
                "commit_count": len(parsed_diffs),
                "nvd_available": False,  # Will be set properly in full implementation
                "osv_count": 0,
            },
            "diff_summary": {
                "hunks_analyzed": sum(
                    len(d.get("parsed_hunks", [])) for d in parsed_diffs
                ),
                "security_issues_found": len(security_issues),
                "files_modified": len(
                    set(
                        h.file_path
                        for d in parsed_diffs
                        for h in d.get("parsed_hunks", [])
                    )
                ),
            },
        }
        
        # Add raw advisory only if flag is set
        if self.include_raw_advisory:
            context_data["raw_advisory"] = ghsa_data  # Fallback for low confidence cases
        
        return context_data

    def _extract_pattern_info(self, match: Any) -> Dict[str, Any]:
        """Extract pattern information from security match"""
        pattern_name = "unknown"
        confidence = 0.0
        description = ""
        line_number = 0
        line_content = ""

        if hasattr(match, "pattern_type"):
            pattern_name = (
                match.pattern_type.value
                if hasattr(match.pattern_type, "value")
                else str(match.pattern_type)
            )
            confidence = match.confidence
            description = match.description
            line_number = match.line_number
            line_content = getattr(match, "line_content", "")
        else:
            # Parse from string representation
            match_str = str(match)

            if "pattern_type=" in match_str and "'" in match_str:
                pattern_name = match_str.split("pattern_type=")[1].split("'")[1]

            if "confidence=" in match_str:
                try:
                    confidence = float(match_str.split("confidence=")[1].split()[0])
                except:
                    pass

        return {
            "pattern": pattern_name,
            "confidence": confidence,
            "description": description,
            "location": {
                "file": getattr(match, "file_path", "unknown"),
                "line": line_number,
                "code_context": line_content or "No context available",
            },
            "vulnerability_type": pattern_name.replace("_", " ").title(),
        }

    async def _save_outputs(
        self,
        ghsa_id: str,
        full_output: Dict[str, Any],
        optimized_context: Dict[str, Any],
    ) -> None:
        """Save analysis outputs to files"""
        # Save full output
        full_file = self.output_dir / f"{ghsa_id}-vulnerability-collection.json"
        with open(full_file, "w", encoding="utf-8") as f:
            json.dump(full_output, f, indent=2, default=str)

        # Save optimized context
        ai_file = self.output_dir / f"{ghsa_id}-ai-context.json"
        with open(ai_file, "w", encoding="utf-8") as f:
            json.dump(optimized_context, f, indent=2, default=str)

        # Show size comparison
        full_size = full_file.stat().st_size / 1024
        ai_size = ai_file.stat().st_size / 1024
        reduction = (1 - ai_size / full_size) * 100 if full_size > 0 else 0

        print(f"   [OK] Full results saved to: {full_file}")
        print(f"   [OK] AI-optimized context saved to: {ai_file}")
        print(
            f"   [INFO] Size reduction: {full_size:.1f}KB -> {ai_size:.1f}KB ({reduction:.1f}% smaller)"
        )


def validate_ghsa_id(ghsa_id: str) -> bool:
    """Validate GHSA ID format"""
    import re

    pattern = r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$"
    return bool(re.match(pattern, ghsa_id))


async def main() -> int:
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Analyze GHSA vulnerabilities with Tree-sitter context"
    )
    parser.add_argument("ghsa_id", help="GHSA advisory ID (e.g., GHSA-c7p4-hx26-pr73)")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Output directory for results",
    )
    parser.add_argument(
        "--skip-repo-analysis",
        action="store_true",
        help="Skip repository context analysis",
    )
    parser.add_argument(
        "--include-raw-advisory",
        action="store_true",
        help="Include raw advisory JSON in AI context (for low confidence cases)",
    )

    args = parser.parse_args()

    # Validate GHSA ID format
    if not validate_ghsa_id(args.ghsa_id):
        print(f"ERROR: Invalid GHSA ID format: {args.ghsa_id}")
        print("Expected format: GHSA-xxxx-xxxx-xxxx")
        return 1

    # Check for GitHub token
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("ERROR: GITHUB_TOKEN environment variable not set")
        print("Please set it with: export GITHUB_TOKEN=your_personal_access_token")
        return 1

    # Create output directory
    args.output_dir.mkdir(exist_ok=True)

    # Run analysis
    analyzer = VulnerabilityAnalyzer(github_token, args.output_dir, args.include_raw_advisory)
    result = await analyzer.analyze(args.ghsa_id)

    if result["status"] == "success":
        print(f"\nAnalysis completed successfully for {args.ghsa_id}")
        return 0
    else:
        print(
            f"\nAnalysis failed for {args.ghsa_id}: {result.get('error', 'Unknown error')}"
        )
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
