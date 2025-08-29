"""Test script for GitHub advisory GHSA-c7p4-hx26-pr73 using collector agent."""

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Load environment variables from .env file
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass  # dotenv not available

from agents.collector import AsyncHTTPClient, CollectorAgent
from agents.data_sources import AdvisoryDataSource, GitHubDataSource
from agents.rate_limiter import APIRateLimiter
from analysis.callgraph import CallGraphBuilder
from analysis.context import CodeContextExtractor
from integration.repo import RepositoryManager
from models import VulnerabilityReport
from parsers.advisory import MultiFormatAdvisoryParser
from parsers.diff import UnifiedDiffParser


class VulnerabilityCollectionResult:
    """Container for collected vulnerability data from all sources"""

    def __init__(self) -> None:
        self.ghsa_data: Optional[Dict[str, Any]] = None
        self.nvd_data: Optional[Dict[str, Any]] = None
        self.osv_data: List[Dict[str, Any]] = []
        self.commits: List[Dict[str, Any]] = []
        self.parsed_advisory: Optional[VulnerabilityReport] = None
        self.raw_content: Dict[str, Any] = {}
        self.metadata: Dict[str, Any] = {}
        self.repository_context: Optional[Dict[str, Any]] = None
        self.call_graph: Optional[Dict[str, Any]] = None


async def discover_related_cve_data(
    advisory_data: Dict[str, Any]
) -> Tuple[Optional[str], List[str]]:
    """Extract CVE ID and commit references from GHSA advisory"""

    # Extract CVE ID
    cve_id = advisory_data.get("cve_id")
    if not cve_id:
        # Check identifiers array
        identifiers = advisory_data.get("identifiers", [])
        for ident in identifiers:
            if isinstance(ident, dict) and ident.get("type") == "CVE":
                cve_id = ident.get("value")
                break

    # Extract commit references from references
    commit_urls = []
    references = advisory_data.get("references", [])

    for ref in references:
        # Handle both string URLs and dict objects
        if isinstance(ref, str):
            url = ref
        elif isinstance(ref, dict):
            url = ref.get("url", "")
        else:
            continue

        if "github.com" in url and "/commit/" in url:
            commit_urls.append(url)

    return cve_id, commit_urls


async def analyze_repository_context(
    commit_urls: List[str], github_token: str
) -> Optional[Dict[str, Any]]:
    """Clone repository and analyze code context around vulnerable functions"""
    if not commit_urls:
        return None
    
    # Extract repository URL from first commit
    commit_url = commit_urls[0]
    if "/commit/" not in commit_url:
        return None
    
    # Convert commit URL to repo URL
    repo_url = commit_url.split("/commit/")[0] + ".git"
    
    print(f"   [INFO] Analyzing repository context for: {repo_url}")
    
    # Initialize repository manager and Tree-sitter components
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
        
        print(f"   [OK] Repository cloned: {clone_result.size_gb:.2f}GB, {clone_result.commit_count} commits")
        
        # Extract file paths from commit URLs
        modified_files = []
        for commit_url in commit_urls[:3]:  # Analyze first 3 commits
            # Get commit SHA
            sha = commit_url.split("/commit/")[-1]
            
            # Get modified files for this commit
            cmd = ["git", "-C", str(clone_result.local_path), "diff-tree", "--name-only", "-r", sha]
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if process.returncode == 0:
                files = [line.strip() for line in stdout.decode().split('\n') if line.strip()]
                # Filter for Ruby files
                ruby_files = [f for f in files if f.endswith('.rb')]
                modified_files.extend(ruby_files)
        
        # Remove duplicates and get full paths
        unique_files = list(set(modified_files))
        full_file_paths = [str(clone_result.local_path / f) for f in unique_files]
        
        print(f"   [OK] Found {len(unique_files)} Ruby files to analyze")
        
        # Build call graph for modified files
        call_graph = call_graph_builder.build_call_graph(full_file_paths, max_depth=2)
        graph_stats = call_graph_builder.get_graph_statistics(call_graph)
        
        print(f"   [OK] Call graph built: {graph_stats['total_functions']} functions, {graph_stats['total_relationships']} relationships")
        
        # Extract context for vulnerable functions
        vulnerable_functions = []
        for file_path in full_file_paths:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Extract all function contexts
                context = context_extractor.extract_context(file_path, content)
                
                # Look for functions that might be vulnerable
                for func in context.primary_functions:
                    # Find callers of this function
                    callers = call_graph_builder.get_function_callers(call_graph, func.name, file_path)
                    caller_info = [{"name": c.function_name, "file": c.file_path, "lines": f"{c.start_line}-{c.end_line}"} for c in callers]
                    
                    vulnerable_functions.append({
                        "name": func.name,
                        "file": file_path.replace(str(clone_result.local_path) + os.sep, ""),
                        "lines": f"{func.start_line}-{func.end_line}",
                        "parameters": func.parameters,
                        "calls_made": func.calls_made,
                        "variables_used": func.variables_used,
                        "full_source": func.full_text,
                        "callers": caller_info
                    })
            except Exception as e:
                print(f"   [!] Failed to analyze {file_path}: {e}")
                continue
        
        # Cleanup repository
        await repo_manager.cleanup_repository(clone_result.repo_id)
        
        return {
            "repository_url": repo_url,
            "clone_stats": {
                "size_gb": clone_result.size_gb,
                "commit_count": clone_result.commit_count,
                "files_analyzed": len(unique_files)
            },
            "call_graph_stats": graph_stats,
            "vulnerable_functions": vulnerable_functions
        }
        
    except Exception as e:
        print(f"   [!] Repository analysis failed: {e}")
        # Cleanup on failure
        try:
            await repo_manager.cleanup_repository(clone_result.repo_id if 'clone_result' in locals() else "unknown")
        except:
            pass
        return None


async def fetch_commit_data(
    http_client: AsyncHTTPClient, commit_url: str, github_token: str
) -> Optional[Dict[str, Any]]:
    """Fetch commit data and diff from GitHub"""
    try:
        # Convert commit URL to API URL
        if "/commit/" in commit_url:
            # Extract owner/repo/sha from URL
            parts = commit_url.replace("https://github.com/", "").split("/")
            if len(parts) >= 3:
                owner, repo, sha = parts[0], parts[1], parts[3]
                api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"

                headers = {
                    "Authorization": f"token {github_token}",
                    "Accept": "application/vnd.github.v3+json",
                }

                commit_data = await http_client.get(api_url, headers=headers)

                # Fetch the patch/diff from the commit data
                diff_text = ""

                # Try to get patch from files in commit
                if "files" in commit_data:
                    patches = []
                    for file_info in commit_data["files"]:
                        if "patch" in file_info:
                            patches.append(
                                f"diff --git a/{file_info['filename']} b/{file_info['filename']}"
                            )
                            patches.append(file_info["patch"])
                    diff_text = "\n".join(patches)

                # Fallback: try GitHub's .patch endpoint
                if not diff_text:
                    try:
                        patch_url = f"{api_url}.patch"
                        patch_headers = {
                            "Authorization": f"token {github_token}",
                            "Accept": "text/plain",
                        }

                        import aiohttp

                        async with aiohttp.ClientSession() as session:
                            async with session.get(
                                patch_url, headers=patch_headers
                            ) as response:
                                if response.status == 200:
                                    diff_text = await response.text()
                    except Exception:
                        pass

                return {"commit": commit_data, "diff": diff_text}
    except Exception as e:
        print(f"Failed to fetch commit data from {commit_url}: {e}")
        return None

    return None


async def test_github_advisory() -> Optional[Dict[str, Any]]:
    """Test complete vulnerability collection and parsing flow."""

    # Check for GitHub token
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("ERROR: GITHUB_TOKEN environment variable not set")
        print("Please set it with: set GITHUB_TOKEN=your_personal_access_token")
        print("Using test mode without real API calls...")
        github_token = "test_token"

    ghsa_id = "GHSA-c7p4-hx26-pr73"
    print(f"Testing Complete Collection Flow for {ghsa_id}")
    print("=" * 60)

    # Initialize components
    http_client = AsyncHTTPClient(max_retries=2, timeout=30.0)

    # Initialize rate limiters
    from agents.rate_limiter import GitHubRateLimiter, NVDRateLimiter, RateLimiter

    rate_limiter = APIRateLimiter(
        {
            "github": GitHubRateLimiter(requests_per_hour=5000),
            "ghsa": GitHubRateLimiter(requests_per_hour=5000),
            "nvd": NVDRateLimiter(requests_per_30_seconds=50),
            "osv": RateLimiter(requests_per_second=10, burst_size=20),
        }
    )

    # Initialize parsers
    advisory_parser = MultiFormatAdvisoryParser()
    diff_parser = UnifiedDiffParser()

    # Result container
    result = VulnerabilityCollectionResult()

    try:
        # Step 1: Fetch GHSA Advisory
        print(f"\n1. Fetching GHSA Advisory: {ghsa_id}")
        advisory_url = f"https://api.github.com/advisories/{ghsa_id}"
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        result.ghsa_data = await http_client.get(advisory_url, headers=headers)
        print(
            f"   [OK] GHSA fetched: {result.ghsa_data.get('summary', 'No summary')[:80]}..."
        )

        # Step 2: Discover related CVE and commits
        print("\n2. Discovering Related Data Sources...")
        cve_id, commit_urls = await discover_related_cve_data(result.ghsa_data)
        print(f"   [OK] CVE ID: {cve_id or 'Not found'}")
        print(f"   [OK] Commit URLs: {len(commit_urls)} found")

        # Step 3: Collect from NVD if CVE exists
        if cve_id:
            print(f"\n3. Fetching NVD Data for {cve_id}")
            advisory_source = AdvisoryDataSource(
                http_client=http_client, rate_limiter=rate_limiter
            )
            result.nvd_data = await advisory_source.collect_nvd(cve_id)
            if result.nvd_data:
                print(f"   [OK] NVD data retrieved")
            else:
                print(f"   [!] NVD data not found")

        # Step 4: Collect from OSV if CVE exists
        if cve_id:
            print(f"\n4. Fetching OSV Data for {cve_id}")
            result.osv_data = await advisory_source.collect_osv([cve_id])
            print(f"   [OK] OSV entries: {len(result.osv_data)}")

        # Step 5: Collect commit data and diffs
        print(f"\n5. Fetching Commit Data ({len(commit_urls)} commits)")
        for i, commit_url in enumerate(commit_urls[:3]):  # Limit to first 3 commits
            commit_data = await fetch_commit_data(http_client, commit_url, github_token)
            if commit_data:
                result.commits.append(commit_data)
                print(
                    f"   [OK] Commit {i+1}: {commit_data['commit'].get('sha', 'Unknown')[:8]}..."
                )

        # Step 5.5: Repository Context Analysis with Tree-sitter
        print(f"\n5.5. Analyzing Repository Context with Tree-sitter")
        result.repository_context = await analyze_repository_context(commit_urls, github_token)
        if result.repository_context:
            stats = result.repository_context["clone_stats"]
            graph_stats = result.repository_context["call_graph_stats"]
            func_count = len(result.repository_context["vulnerable_functions"])
            print(f"   [OK] Repository analysis: {stats['files_analyzed']} files, {func_count} functions analyzed")
            print(f"   [OK] Call graph: {graph_stats['total_functions']} functions, {graph_stats['resolution_rate']:.1%} call resolution")
        else:
            print(f"   [!] Repository context analysis failed")

        # Step 6: Parse the collected data
        print(f"\n6. Parsing Collected Data...")

        # Parse GHSA advisory
        try:
            result.parsed_advisory = advisory_parser.parse(result.ghsa_data)
            print(f"   [OK] GHSA parsed: {result.parsed_advisory.advisory_id}")
        except Exception as e:
            print(f"   [!] GHSA parsing failed: {e}")

        # Parse NVD data if available
        parsed_nvd = None
        if result.nvd_data:
            try:
                parsed_nvd = advisory_parser.parse(result.nvd_data)
                print(f"   [OK] NVD parsed: {parsed_nvd.advisory_id}")
            except Exception as e:
                print(f"   [!] NVD parsing failed: {e}")

        # Parse OSV data if available
        parsed_osv = []
        for i, osv_entry in enumerate(result.osv_data):
            try:
                parsed_entry = advisory_parser.parse(osv_entry)
                parsed_osv.append(parsed_entry)
                print(f"   [OK] OSV entry {i+1} parsed: {parsed_entry.advisory_id}")
            except Exception as e:
                print(f"   [!] OSV entry {i+1} parsing failed: {e}")

        # Parse commit diffs with security analysis
        parsed_diffs = []
        for i, commit_data in enumerate(result.commits):
            try:
                diff_text = commit_data.get("diff", "")
                if diff_text and isinstance(diff_text, str):
                    # Use parse_and_analyze to get both hunks and security matches
                    analysis_result = diff_parser.parse_and_analyze(diff_text)
                    parsed_hunks = analysis_result["hunks"]
                    security_matches = analysis_result["security_matches"]
                    summary = analysis_result["summary"]

                    parsed_diffs.append(
                        {
                            "commit_sha": commit_data["commit"].get("sha", "Unknown")[
                                :8
                            ],
                            "parsed_hunks": parsed_hunks,
                            "security_matches": security_matches,
                            "summary": summary,
                            "raw_diff": diff_text,
                        }
                    )
                    security_count = len(security_matches)
                    high_conf_count = len(
                        [
                            m
                            for m in security_matches
                            if hasattr(m, "confidence") and m.confidence >= 0.8
                        ]
                    )
                    print(
                        f"   [OK] Diff {i+1} parsed: {len(parsed_hunks)} hunks, {security_count} security issues ({high_conf_count} high confidence)"
                    )
            except Exception as e:
                print(f"   [!] Diff {i+1} parsing failed: {e}")

        # Step 7: Create structured output
        print(f"\n7. Creating Structured Output...")
        output_data = await create_structured_output(
            result, parsed_diffs, parsed_nvd, parsed_osv, ghsa_id
        )

        # Save to temporary file
        output_file = f"{ghsa_id}-vulnerability-collection.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, default=str)

        print(f"   [OK] Results saved to: {output_file}")

        # Display summary
        print(f"\n8. Collection Summary")
        print(
            f"   Sources collected: GHSA [OK], NVD {'[OK]' if result.nvd_data else '[!]'}, OSV ({len(result.osv_data)}), Commits ({len(result.commits)}), Repository {'[OK]' if result.repository_context else '[!]'}"
        )
        print(
            f"   Parsing results: GHSA {'[OK]' if result.parsed_advisory else '[!]'}, NVD {'[OK]' if parsed_nvd else '[!]'}, OSV ({len(parsed_osv)})"
        )
        print(f"   Diffs analyzed: {len(parsed_diffs)} with security pattern detection")
        
        if result.repository_context:
            func_count = len(result.repository_context["vulnerable_functions"])
            print(f"   Repository analysis: {func_count} vulnerable functions with caller context")

        if result.parsed_advisory:
            print(f"\n   Advisory Details:")
            print(f"   Title: {result.parsed_advisory.title}")
            print(f"   Severity: {result.parsed_advisory.severity}")
            print(f"   CVE: {result.parsed_advisory.advisory_id}")
            print(f"   CWEs: {result.parsed_advisory.cwe_ids}")

        return output_data

    except Exception as e:
        print(f"ERROR during collection flow: {e}")
        import traceback

        traceback.print_exc()
        return None

    finally:
        # Cleanup
        await http_client.close()
        print("\nCleanup completed")


async def create_structured_output(
    result: VulnerabilityCollectionResult,
    parsed_diffs: List[Dict[str, Any]],
    parsed_nvd: Optional[VulnerabilityReport],
    parsed_osv: List[VulnerabilityReport],
    ghsa_id: str,
) -> Dict[str, Any]:
    """Create structured output with raw and parsed data organized by source"""

    return {
        "collection_metadata": {
            "ghsa_id": ghsa_id,
            "timestamp": datetime.now().isoformat(),
            "sources_collected": {
                "ghsa": result.ghsa_data is not None,
                "nvd": result.nvd_data is not None,
                "osv": len(result.osv_data),
                "commits": len(result.commits),
                "repository_context": result.repository_context is not None,
            },
            "parsing_success": {
                "advisory_parsed": result.parsed_advisory is not None,
                "nvd_parsed": parsed_nvd is not None,
                "osv_parsed": len(parsed_osv),
                "diffs_parsed": len(parsed_diffs),
            },
        },
        "sources": {
            "ghsa": {
                "metadata": {
                    "source_type": "advisory",
                    "format": "GitHub Security Advisory",
                    "api_endpoint": f"https://api.github.com/advisories/{ghsa_id}",
                },
                "raw_content": result.ghsa_data,
                "parsed_data": result.parsed_advisory.model_dump()
                if result.parsed_advisory
                else None,
                "ai_ready_content": {
                    "structured_metadata": result.parsed_advisory.model_dump()
                    if result.parsed_advisory
                    else None,
                    "raw_advisory": result.ghsa_data,
                },
            },
            "nvd": {
                "metadata": {
                    "source_type": "advisory",
                    "format": "National Vulnerability Database",
                    "api_endpoint": f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                },
                "raw_content": result.nvd_data,
                "parsed_data": parsed_nvd.model_dump() if parsed_nvd else None,
                "ai_ready_content": {
                    "structured_metadata": parsed_nvd.model_dump()
                    if parsed_nvd
                    else None,
                    "raw_advisory": result.nvd_data,
                },
            }
            if result.nvd_data
            else None,
            "osv": {
                "metadata": {
                    "source_type": "advisory",
                    "format": "Open Source Vulnerability",
                    "api_endpoint": "https://api.osv.dev/v1/vulns/",
                    "entries_found": len(result.osv_data),
                },
                "raw_content": result.osv_data,
                "parsed_data": [osv.model_dump() for osv in parsed_osv]
                if parsed_osv
                else None,
                "ai_ready_content": {
                    "structured_metadata": [osv.model_dump() for osv in parsed_osv]
                    if parsed_osv
                    else None,
                    "raw_advisories": result.osv_data,
                },
            }
            if result.osv_data
            else None,
            "commits": [
                {
                    "metadata": {
                        "source_type": "code_change",
                        "format": "Git commit with unified diff",
                        "commit_sha": commit_data["commit"].get("sha", "Unknown"),
                        "api_endpoint": commit_data["commit"].get("url", ""),
                        "author": commit_data["commit"]
                        .get("author", {})
                        .get("name", "Unknown"),
                        "date": commit_data["commit"].get("author", {}).get("date"),
                    },
                    "raw_content": {
                        "commit_data": commit_data["commit"],
                        "diff_content": commit_data.get("diff", ""),
                    },
                    "parsed_data": {
                        "hunks": next(
                            (
                                d["parsed_hunks"]
                                for d in parsed_diffs
                                if d["commit_sha"]
                                == commit_data["commit"].get("sha", "")[:8]
                            ),
                            [],
                        ),
                        "security_matches": next(
                            (
                                d["security_matches"]
                                for d in parsed_diffs
                                if d["commit_sha"]
                                == commit_data["commit"].get("sha", "")[:8]
                            ),
                            [],
                        ),
                        "summary": next(
                            (
                                d["summary"]
                                for d in parsed_diffs
                                if d["commit_sha"]
                                == commit_data["commit"].get("sha", "")[:8]
                            ),
                            {},
                        ),
                    },
                    "ai_ready_content": {
                        "structured_diff": next(
                            (
                                [h.model_dump() for h in d["parsed_hunks"]]
                                for d in parsed_diffs
                                if d["commit_sha"]
                                == commit_data["commit"].get("sha", "")[:8]
                            ),
                            None,
                        ),
                        "security_analysis": next(
                            (
                                [m.model_dump() for m in d["security_matches"]]
                                for d in parsed_diffs
                                if d["commit_sha"]
                                == commit_data["commit"].get("sha", "")[:8]
                            ),
                            None,
                        ),
                        "diff_summary": next(
                            (
                                d["summary"]
                                for d in parsed_diffs
                                if d["commit_sha"]
                                == commit_data["commit"].get("sha", "")[:8]
                            ),
                            None,
                        ),
                        "raw_diff": commit_data.get("diff", ""),
                        "diff_metadata": {
                            "files_changed": commit_data["commit"].get("files", []),
                            "author": commit_data["commit"].get("author", {}),
                            "message": commit_data["commit"].get("message", ""),
                            "stats": commit_data["commit"].get("stats", {}),
                        },
                    },
                }
                for commit_data in result.commits
            ],
            "repository_context": {
                "metadata": {
                    "source_type": "code_analysis",
                    "format": "Tree-sitter static analysis with call graph",
                    "analysis_tool": "Tree-sitter + Ruby grammar",
                },
                "raw_content": result.repository_context,
                "ai_ready_content": {
                    "vulnerable_functions": result.repository_context.get("vulnerable_functions", []) if result.repository_context else [],
                    "call_graph_stats": result.repository_context.get("call_graph_stats", {}) if result.repository_context else {},
                    "clone_stats": result.repository_context.get("clone_stats", {}) if result.repository_context else {},
                },
            } if result.repository_context else None,
        },
        # Summary for AI consumption
        "ai_analysis_ready": {
            "primary_advisory": {
                "structured": result.parsed_advisory.model_dump()
                if result.parsed_advisory
                else None,
                "raw": result.ghsa_data,
            },
            "code_changes": [
                {
                    "structured_diff": [h.model_dump() for h in d["parsed_hunks"]],
                    "security_analysis": [
                        m.model_dump() for m in d["security_matches"]
                    ],
                    "diff_summary": d["summary"],
                    "raw_diff": d["raw_diff"],
                    "commit_metadata": next(
                        (
                            c["commit"]
                            for c in result.commits
                            if c["commit"].get("sha", "")[:8] == d["commit_sha"]
                        ),
                        None,
                    ),
                }
                for d in parsed_diffs
            ],
            "repository_analysis": {
                "vulnerable_functions": result.repository_context.get("vulnerable_functions", []) if result.repository_context else [],
                "call_graph_stats": result.repository_context.get("call_graph_stats", {}) if result.repository_context else {},
                "repository_url": result.repository_context.get("repository_url", "") if result.repository_context else "",
            },
            "cross_references": {
                "nvd_available": result.nvd_data is not None,
                "osv_entries": len(result.osv_data),
                "commit_count": len(result.commits),
                "repository_context_available": result.repository_context is not None,
            },
        },
    }


if __name__ == "__main__":
    asyncio.run(test_github_advisory())
