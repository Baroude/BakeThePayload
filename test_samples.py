#!/usr/bin/env python3
"""
Sample data and examples for testing the parsers
Run this file to see the parsers in action, or import the samples for your own tests
"""

import json
from typing import Any, Dict, List, Union, cast

from models import EcosystemEnum
from parsers import MultiFormatAdvisoryParser, UnifiedDiffParser, VersionExtractor

# Sample diff with security issues
SAMPLE_DIFF = """--- a/src/auth/login.py
+++ b/src/auth/login.py
@@ -12,8 +12,7 @@ def authenticate_user(username, password):
     if not username or not password:
         return {"error": "Missing credentials"}

-    # Validate and sanitize input
-    if not validate_input(username) or not sanitize_input(password):
-        return {"error": "Invalid input format"}
+    # TODO: Add validation later

     # Check user credentials
@@ -25,7 +24,7 @@ def authenticate_user(username, password):

     # Build SQL query
-    query = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
-    result = db.execute(query, (username, hash_password(password)))
+    query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}'"
+    result = db.execute(query)

     if result:
         return {"success": True, "user_id": result[0]["id"]}
"""

# Sample GHSA advisory
SAMPLE_GHSA = {
    "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
    "summary": "SQL Injection vulnerability in authentication module",
    "details": "The authentication module is vulnerable to SQL injection attacks due to improper input validation. An attacker can bypass authentication by injecting malicious SQL code.",
    "severity": "HIGH",
    "cvss": {
        "score": 8.1,
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    },
    "cwe_ids": [89, 20],
    "references": [
        {
            "url": "https://github.com/example/repo/security/advisories/GHSA-xxxx-xxxx-xxxx",
            "source": "GHSA",
        },
        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345", "source": "NVD"},
    ],
    "published": "2024-01-15T10:30:00Z",
    "identifiers": [
        {"type": "GHSA", "value": "GHSA-xxxx-xxxx-xxxx"},
        {"type": "CVE", "value": "CVE-2024-12345"},
    ],
}

# Sample OSV advisory
SAMPLE_OSV = {
    "schema_version": "1.4.0",
    "id": "PYSEC-2024-12345",
    "summary": "Remote code execution in deserialization",
    "details": "Unsafe deserialization allows remote code execution when processing untrusted data.",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "vulnerable-package"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.5"}],
                }
            ],
        }
    ],
    "references": [
        {"type": "ADVISORY", "url": "https://example.com/advisory"},
        {"type": "FIX", "url": "https://github.com/example/commit/abc123"},
    ],
    "published": "2024-02-01T12:00:00Z",
}

# Sample NVD advisory
SAMPLE_NVD = {
    "cve": {
        "CVE_data_meta": {"ID": "CVE-2024-98765"},
        "description": {
            "description_data": [
                {
                    "lang": "en",
                    "value": "Buffer overflow in network parsing function allows remote code execution",
                }
            ]
        },
        "problemtype": {
            "problemtype_data": [{"description": [{"lang": "en", "value": "CWE-119"}]}]
        },
        "references": {
            "reference_data": [
                {
                    "url": "https://example.com/security-bulletin",
                    "tags": ["Vendor Advisory"],
                }
            ]
        },
    },
    "impact": {
        "baseMetricV3": {
            "cvssV3": {
                "baseScore": 9.8,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        }
    },
    "publishedDate": "2024-03-01T08:00:00Z",
}


def demo_diff_parser() -> None:
    """Demo the unified diff parser"""
    print("=" * 50)
    print("DIFF PARSER DEMO")
    print("=" * 50)

    parser = UnifiedDiffParser()
    result = parser.parse_and_analyze(SAMPLE_DIFF)

    print(f"Summary:")
    summary = cast(Dict[str, int], result["summary"])
    print(f"  Files modified: {summary['files_modified']}")
    print(f"  Total hunks: {summary['total_hunks']}")
    print(f"  Security issues: {summary['security_issues_found']}")
    print(f"  High confidence issues: {summary['high_confidence_issues']}")

    print(f"\nSecurity Issues Found:")
    from parsers import SecurityMatch  # ensure type available for casts

    security_matches = cast(List[SecurityMatch], result["security_matches"])
    for i, match in enumerate(security_matches, 1):
        print(f"  {i}. {match.pattern_type}")
        print(f"     Line {match.line_number}: {match.line_content[:60]}...")
        print(f"     {match.description} (confidence: {match.confidence})")

    print(f"\nFile Changes:")
    from parsers import DiffHunk  # ensure type available for casts

    for hunk in cast(List[DiffHunk], result["hunks"]):
        print(f"  {hunk.file_path}:")
        print(f"    Lines added: {len(hunk.added_lines)}")
        print(f"    Lines removed: {len(hunk.removed_lines)}")


def demo_advisory_parser() -> None:
    """Demo the advisory parser"""
    print("\n" + "=" * 50)
    print("ADVISORY PARSER DEMO")
    print("=" * 50)

    parser = MultiFormatAdvisoryParser()

    # Test different formats
    formats: List[tuple[str, Dict[str, Any]]] = [
        ("GHSA", SAMPLE_GHSA),
        ("OSV", SAMPLE_OSV),
        ("NVD", SAMPLE_NVD),
    ]

    for format_name, sample_data in formats:
        print(f"\n--- {format_name} Format ---")
        try:
            vuln = parser.parse(sample_data)
            print(f"Advisory ID: {vuln.advisory_id}")
            print(f"Title: {vuln.title}")
            print(f"Severity: {vuln.severity}")
            print(f"CVSS Score: {vuln.cvss_score}")
            print(f"CWE IDs: {vuln.cwe_ids}")
            print(f"References: {len(vuln.references)}")
            print(f"Evidence: {len(vuln.evidence)} items")
        except Exception as e:
            print(f"Error parsing {format_name}: {e}")


def demo_version_extractor() -> None:
    """Demo the version extractor"""
    print("\n" + "=" * 50)
    print("VERSION EXTRACTOR DEMO")
    print("=" * 50)

    extractor = VersionExtractor()

    # Test different ecosystems and constraints
    test_cases = [
        ("NPM", "^1.2.3", ["1.2.3", "1.2.9", "1.9.0", "2.0.0"]),
        ("NPM", "~1.2.0", ["1.2.0", "1.2.9", "1.3.0", "2.0.0"]),
        ("PyPI", ">=1.0.0,<2.0.0", ["0.9.0", "1.0.0", "1.5.0", "2.0.0"]),
        ("Maven", "[1.0,2.0)", ["0.9", "1.0", "1.5", "2.0"]),
        ("RubyGems", "~>2.1.0", ["2.0.9", "2.1.0", "2.1.5", "2.2.0"]),
    ]

    for ecosystem_name, constraint_str, test_versions in test_cases:
        print(f"\n--- {ecosystem_name}: {constraint_str} ---")

        # Map string to enum
        ecosystem = getattr(
            EcosystemEnum, ecosystem_name.upper().replace("GEMS", "GEMS")
        )

        try:
            version_range = extractor.create_version_range(constraint_str, ecosystem)
            print(f"Parsed constraints: {len(version_range.constraints)}")

            print("Version satisfaction test:")
            for version in test_versions:
                satisfies = version_range.satisfies(version)
                status = "MATCH" if satisfies else "NO MATCH"
                print(f"  {version:8} -> {status}")

        except Exception as e:
            print(f"Error: {e}")


def interactive_test() -> None:
    """Interactive testing function"""
    print("\n" + "=" * 50)
    print("INTERACTIVE TESTING")
    print("=" * 50)
    print("Available parsers:")
    print("1. Diff Parser - paste a git diff")
    print("2. Advisory Parser - paste JSON advisory")
    print("3. Version Parser - test version constraints")
    print("4. Exit")

    while True:
        choice = input("\nSelect parser (1-4): ").strip()

        if choice == "1":
            print("Paste your git diff (press Enter twice when done):")
            lines = []
            empty_count = 0
            while empty_count < 2:
                line = input()
                if line.strip() == "":
                    empty_count += 1
                else:
                    empty_count = 0
                lines.append(line)

            diff_content = "\n".join(lines)
            diff_parser = UnifiedDiffParser()
            result = diff_parser.parse_and_analyze(diff_content)
            summary2 = cast(Dict[str, int], result["summary"])
            print(f"Found {summary2['security_issues_found']} security issues")

        elif choice == "2":
            print("Paste your JSON advisory:")
            json_str = input()
            try:
                advisory_data = json.loads(json_str)
                adv_parser = MultiFormatAdvisoryParser()
                vuln = adv_parser.parse(advisory_data)
                print(f"Parsed: {vuln.advisory_id} - {vuln.severity}")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "3":
            constraint = input("Enter version constraint: ")
            ecosystem_name = input("Enter ecosystem (npm/pypi/maven/etc): ")
            version_to_test = input("Enter version to test: ")

            try:
                ecosystem = getattr(EcosystemEnum, ecosystem_name.upper())
                extractor = VersionExtractor()
                version_range = extractor.create_version_range(constraint, ecosystem)
                satisfies = version_range.satisfies(version_to_test)
                print(
                    f"Result: {version_to_test} {'MATCHES' if satisfies else 'does NOT match'} {constraint}"
                )
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "4":
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    print("VULNERABILITY ANALYZER - PARSER TESTING")
    print("Run the demos to see parsers in action")
    print("Or call interactive_test() for hands-on testing")

    demo_diff_parser()
    demo_advisory_parser()
    demo_version_extractor()

    # Uncomment to enable interactive testing
    # interactive_test()
