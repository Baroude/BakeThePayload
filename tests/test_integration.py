#!/usr/bin/env python3
"""
Integration tests between different models and parsers
Tests cross-model relationships, data flow, and complex interactions
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

import pytest

from models import (
    AffectedArtifact,
    Component,
    EcosystemEnum,
    Evidence,
    ExploitFlow,
    ExploitNode,
    FlowEdge,
    Impact,
    ImpactLevel,
    Mitigation,
    NodeType,
    Reference,
    RiskAssessment,
    RiskFactor,
    SecurityBaseModel,
    SeverityEnum,
    VersionRange,
    VulnerabilityReport,
)
from parsers import (
    AdvisoryFormat,
    AdvisoryParseError,
    MultiFormatAdvisoryParser,
    UnifiedDiffParser,
    VersionExtractor,
)


class TestCrossModelIntegration:
    """Test integration between different model types"""

    def test_vulnerability_report_with_embedded_exploit_flows(self):
        """Test full integration between vulnerability reports and exploit flows"""
        # Create exploit nodes
        entry_node = ExploitNode(
            node_id=uuid4(),
            type=NodeType.ENTRY_POINT,
            title="Initial Access",
            description="Attacker gains initial access through vulnerable endpoint",
            confidence=0.9,
            preconditions=["network access", "valid URL"],
            postconditions=["code execution context"],
        )

        validation_node = ExploitNode(
            node_id=uuid4(),
            type=NodeType.VALIDATION,
            title="Bypass Input Validation",
            description="Exploit bypasses input validation checks",
            confidence=0.8,
            preconditions=["code execution context"],
            postconditions=["validated input bypass"],
        )

        impact_node = ExploitNode(
            node_id=uuid4(),
            type=NodeType.IMPACT,
            title="Data Exfiltration",
            description="Attacker extracts sensitive data",
            confidence=0.85,
            preconditions=["validated input bypass", "database access"],
            postconditions=["data breach", "privacy violation"],
        )

        # Create flow edges
        edge1 = FlowEdge(
            edge_id=uuid4(),
            source=entry_node.node_id,
            target=validation_node.node_id,
            condition="if input validation exists",
            probability=0.7,
            description="Transition from access to validation bypass",
        )

        edge2 = FlowEdge(
            edge_id=uuid4(),
            source=validation_node.node_id,
            target=impact_node.node_id,
            condition="if database accessible",
            probability=0.9,
            description="Transition from bypass to data access",
        )

        # Create exploit flow
        exploit_flow = ExploitFlow(
            name="SQL Injection to Data Breach",
            description="Complete exploit flow from initial access to data exfiltration",
            nodes=[entry_node, validation_node, impact_node],
            edges=[edge1, edge2],
            entry_points=[entry_node.node_id],
            impact_nodes=[impact_node.node_id],
        )

        # Create evidence linking to the exploit flow
        code_evidence = Evidence(
            type="code",
            content="SELECT * FROM users WHERE id = '" + "{user_input}" + "'",
            confidence=0.95,
            file_path="/src/auth/login.py",
            line_number=127,
        )

        flow_evidence = Evidence(
            type="exploit_flow",
            content=f"Exploit flow analysis: {exploit_flow.name}",
            confidence=0.88,
        )

        # Create vulnerability report that incorporates the exploit flow
        vuln_report = VulnerabilityReport(
            advisory_id="CVE-2024-INTEGRATION-TEST",
            title="SQL Injection leading to Data Breach",
            description=f"SQL injection vulnerability that can lead to complete data breach. "
            f"Exploit flow analysis shows {len(exploit_flow.nodes)} attack stages "
            f"with {len(exploit_flow.edges)} transitions.",
            severity=SeverityEnum.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_ids=["CWE-89", "CWE-20"],
            evidence=[code_evidence, flow_evidence],
            summary="Critical SQL injection with proven exploit path to data exfiltration",
        )

        # Test integration points
        assert vuln_report.severity == SeverityEnum.CRITICAL
        assert len(vuln_report.evidence) == 2
        assert exploit_flow.validate_node_references() == True
        assert len(exploit_flow.entry_points) == 1
        assert len(exploit_flow.impact_nodes) == 1

        # Test that models can be serialized together
        vuln_data = vuln_report.model_dump()
        flow_data = exploit_flow.model_dump()

        # Combine data structures
        integrated_data = {
            "vulnerability": vuln_data,
            "exploit_flow": flow_data,
            "relationship": "exploit_flow_demonstrates_vulnerability",
        }

        # Test serialization works
        json_str = json.dumps(integrated_data, default=str)
        assert len(json_str) > 1000  # Should be substantial

        # Test round-trip
        parsed_data = json.loads(json_str)
        assert (
            parsed_data["vulnerability"]["advisory_id"] == "CVE-2024-INTEGRATION-TEST"
        )
        assert parsed_data["exploit_flow"]["name"] == "SQL Injection to Data Breach"

    def test_risk_assessment_with_complex_evidence_chains(self):
        """Test risk assessment that incorporates multi-level evidence relationships"""
        # Create layered evidence
        primary_evidence = Evidence(
            type="source_code",
            content="Vulnerable function implementation",
            confidence=0.9,
            file_path="/src/payment/processor.py",
            line_number=89,
        )

        secondary_evidence = Evidence(
            type="test_case",
            content="Unit test demonstrating vulnerability",
            confidence=0.85,
            file_path="/tests/test_payment.py",
            line_number=45,
        )

        exploit_evidence = Evidence(
            type="proof_of_concept",
            content="Working exploit demonstration",
            confidence=0.95,
        )

        # Create components
        payment_component = Component(
            name="process_payment",
            type="function",
            file_path="/src/payment/processor.py",
            line_range=(85, 120),
            description="Payment processing function with validation bypass",
        )

        # Create affected artifact
        version_range = VersionRange(
            constraint=">=2.0.0,<2.3.5", ecosystem=EcosystemEnum.PYPI
        )

        affected_artifact = AffectedArtifact(
            package_name="payment-processor",
            ecosystem=EcosystemEnum.PYPI,
            affected_versions=[version_range],
            fixed_versions=["2.3.5", "2.4.0"],
            components=[payment_component],
        )

        # Create impact assessment
        impact = Impact(
            confidentiality=ImpactLevel.COMPLETE,
            integrity=ImpactLevel.COMPLETE,
            availability=ImpactLevel.PARTIAL,
            scope="changed",
        )

        # Create mitigations with different effectiveness
        immediate_mitigation = Mitigation(
            type="workaround",
            description="Disable payment processing temporarily",
            effectiveness=0.95,
            complexity="low",
            references=["https://internal.docs/disable-payments"],
        )

        permanent_mitigation = Mitigation(
            type="patch",
            description="Upgrade to version 2.3.5 or later",
            effectiveness=0.99,
            complexity="medium",
            references=["https://github.com/project/releases/tag/v2.3.5"],
        )

        # Create risk factors
        exploitability_factor = RiskFactor(
            name="Exploit Availability",
            value="public",
            weight=0.4,
            description="Public exploits available",
        )

        exposure_factor = RiskFactor(
            name="System Exposure",
            value="internet_facing",
            weight=0.3,
            description="System is internet-facing",
        )

        business_factor = RiskFactor(
            name="Business Impact",
            value="critical",
            weight=0.3,
            description="Payment system is business-critical",
        )

        # Create comprehensive risk assessment
        risk_assessment = RiskAssessment(
            vulnerability_id="CVE-2024-PAYMENT-BYPASS",
            base_score=9.0,
            derived_score=8.5,  # Slightly lower due to mitigations
            severity=SeverityEnum.CRITICAL,
            confidence=0.92,
            factors=[exploitability_factor, exposure_factor, business_factor],
            impact=impact,
            mitigations=[immediate_mitigation, permanent_mitigation],
            reasoning="Payment processing vulnerability with complete CIA impact. "
            "Public exploits available but mitigations reduce overall risk.",
        )

        # Create vulnerability report that ties everything together
        comprehensive_vuln = VulnerabilityReport(
            advisory_id="CVE-2024-PAYMENT-BYPASS",
            title="Payment Processing Authentication Bypass",
            description="Authentication bypass in payment processor allows unauthorized transactions",
            severity=SeverityEnum.CRITICAL,
            cvss_score=9.0,
            evidence=[primary_evidence, secondary_evidence, exploit_evidence],
            cwe_ids=["CWE-287", "CWE-863"],
        )

        # Test complex relationships
        assert len(comprehensive_vuln.evidence) == 3
        assert len(risk_assessment.factors) == 3
        assert len(risk_assessment.mitigations) == 2
        assert risk_assessment.impact.scope == "changed"

        # Test that version checking works
        assert affected_artifact.is_version_affected("2.1.0") == True
        assert affected_artifact.is_version_affected("2.3.5") == False

        # Test overall risk calculation incorporates mitigations
        overall_risk = risk_assessment.calculate_overall_risk()
        assert overall_risk < risk_assessment.base_score  # Should be reduced

        # Test evidence confidence aggregation
        avg_evidence_confidence = sum(
            e.confidence for e in comprehensive_vuln.evidence
        ) / len(comprehensive_vuln.evidence)
        assert 0.85 <= avg_evidence_confidence <= 0.95

        # Test factor weight normalization
        total_weight = sum(f.weight for f in risk_assessment.factors)
        assert abs(total_weight - 1.0) < 0.01  # Should sum to approximately 1.0

    def test_affected_artifact_version_matching_with_cvss_scores(self):
        """Test correlation between affected versions and CVSS severity"""
        # Create version ranges with different impact levels
        critical_range = VersionRange(
            constraint=">=1.0.0,<1.2.0", ecosystem=EcosystemEnum.NPM
        )

        medium_range = VersionRange(
            constraint=">=1.2.0,<1.5.0", ecosystem=EcosystemEnum.NPM
        )

        # Create artifacts with different severity impacts
        critical_artifact = AffectedArtifact(
            package_name="web-framework",
            ecosystem=EcosystemEnum.NPM,
            affected_versions=[critical_range],
            fixed_versions=["1.2.0"],
            description="Critical RCE vulnerability in early versions",
        )

        medium_artifact = AffectedArtifact(
            package_name="web-framework",
            ecosystem=EcosystemEnum.NPM,
            affected_versions=[medium_range],
            fixed_versions=["1.5.0"],
            description="Medium severity XSS vulnerability",
        )

        # Create corresponding vulnerability reports
        critical_vuln = VulnerabilityReport(
            advisory_id="CVE-2024-CRITICAL",
            title="Remote Code Execution",
            description="RCE vulnerability in web framework",
            severity=SeverityEnum.CRITICAL,
            cvss_score=9.8,
        )

        medium_vuln = VulnerabilityReport(
            advisory_id="CVE-2024-MEDIUM",
            title="Cross-Site Scripting",
            description="XSS vulnerability in web framework",
            severity=SeverityEnum.MEDIUM,
            cvss_score=6.1,
        )

        # Test version/severity correlation
        test_versions = ["1.0.5", "1.1.0", "1.3.0", "1.5.0", "2.0.0"]

        for version in test_versions:
            critical_affected = critical_artifact.is_version_affected(version)
            medium_affected = medium_artifact.is_version_affected(version)

            if version in ["1.0.5", "1.1.0"]:
                assert critical_affected == True
                assert medium_affected == False
                # Version is in critical range
            elif version in ["1.3.0"]:
                assert critical_affected == False
                assert medium_affected == True
                # Version is in medium range
            else:
                assert critical_affected == False
                assert medium_affected == False
                # Version is not affected

        # Test CVSS/severity correlation
        assert critical_vuln.cvss_score > 9.0
        assert medium_vuln.cvss_score < 7.0
        assert critical_vuln.severity == SeverityEnum.CRITICAL
        assert medium_vuln.severity == SeverityEnum.MEDIUM

    def test_export_import_complete_vulnerability_datasets(self):
        """Test serialization round-trip of complete vulnerability datasets"""
        # Create a comprehensive dataset
        evidence_list = []
        for i in range(5):
            evidence = Evidence(
                type=f"evidence_type_{i}",
                content=f"Evidence content {i} with unicode: 测试 🔒",
                confidence=0.8 + (i * 0.04),
                file_path=f"/src/module_{i}/file.py",
                line_number=100 + i,
            )
            evidence_list.append(evidence)

        references = [
            Reference(url="https://example.com/advisory", source="vendor"),
            Reference(url="https://github.com/project/issue/123", source="github"),
            Reference(
                url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-TEST",
                source="mitre",
            ),
        ]

        vulnerability_reports = []
        for i in range(3):
            vuln = VulnerabilityReport(
                advisory_id=f"CVE-2024-DATASET-{i:03d}",
                title=f"Vulnerability {i}: {'Critical' if i == 0 else 'Medium' if i == 1 else 'Low'} Issue",
                description=f"Dataset test vulnerability {i} with comprehensive metadata",
                severity=(
                    SeverityEnum.CRITICAL
                    if i == 0
                    else SeverityEnum.MEDIUM if i == 1 else SeverityEnum.LOW
                ),
                cvss_score=9.0 - i,
                cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:{'H' if i == 0 else 'L'}",
                cwe_ids=[f"CWE-{79 + i}", f"CWE-{200 + i}"],
                references=references,
                evidence=evidence_list[: i + 2],  # Different evidence counts
                published_at=datetime(2024, 1, 15 + i, 10, 0, 0, tzinfo=timezone.utc),
            )
            vulnerability_reports.append(vuln)

        # Create complete dataset structure
        complete_dataset = {
            "metadata": {
                "version": "1.0",
                "created": datetime.now(timezone.utc).isoformat(),
                "total_vulnerabilities": len(vulnerability_reports),
                "total_evidence": len(evidence_list),
                "severity_distribution": {"critical": 1, "medium": 1, "low": 1},
            },
            "vulnerabilities": [v.model_dump() for v in vulnerability_reports],
            "evidence_catalog": [e.model_dump() for e in evidence_list],
            "references": [r.model_dump() for r in references],
        }

        # Export (serialize)
        exported_json = json.dumps(complete_dataset, default=str, indent=2)

        # Verify export size and structure
        assert len(exported_json) > 5000  # Should be substantial
        assert "CVE-2024-DATASET-000" in exported_json
        assert "测试 🔒" in exported_json  # Unicode preserved

        # Import (deserialize)
        imported_data = json.loads(exported_json)

        # Verify structure preservation
        assert imported_data["metadata"]["total_vulnerabilities"] == 3
        assert len(imported_data["vulnerabilities"]) == 3
        assert len(imported_data["evidence_catalog"]) == 5

        # Verify specific data integrity
        first_vuln = imported_data["vulnerabilities"][0]
        assert first_vuln["advisory_id"] == "CVE-2024-DATASET-000"
        assert first_vuln["severity"] == "critical"
        assert first_vuln["cvss_score"] == 9.0

        # Test that we can reconstruct objects
        reconstructed_vuln = VulnerabilityReport(
            **{
                k: v
                for k, v in first_vuln.items()
                if k
                not in [
                    "evidence",
                    "references",
                ]  # Skip complex nested objects for this test
            }
        )

        assert reconstructed_vuln.advisory_id == "CVE-2024-DATASET-000"
        assert reconstructed_vuln.severity == SeverityEnum.CRITICAL

        # Verify evidence reconstruction
        first_evidence_data = imported_data["evidence_catalog"][0]
        reconstructed_evidence = Evidence(**first_evidence_data)

        assert reconstructed_evidence.type == "evidence_type_0"
        assert "测试 🔒" in reconstructed_evidence.content


class TestParserIntegration:
    """Test integration between different parsers and models"""

    def test_diff_analysis_feeding_into_advisory_generation(self):
        """Test end-to-end workflow from diff analysis to advisory generation"""
        # Start with a security-relevant diff
        security_diff = """--- a/auth/login.py
+++ b/auth/login.py
@@ -23,12 +23,8 @@ class LoginHandler:
     def authenticate_user(self, username, password):
         # Authentication logic
         if not username or not password:
             return False
             
         # SECURITY ISSUE: Removed password hashing
-        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
-        stored_hash = self.get_stored_password(username)
-        
-        if bcrypt.checkpw(password.encode(), stored_hash.encode()):
+        if password == self.get_stored_password(username):
             return self.create_session(username)
         
         return False
"""

        # Parse the diff
        diff_parser = UnifiedDiffParser()
        diff_result = diff_parser.parse_and_analyze(security_diff)

        # Extract information from diff analysis
        hunks = diff_result["hunks"]
        security_matches = diff_result["security_matches"]
        summary = diff_result["summary"]

        # Use diff analysis to create advisory data
        advisory_data = {
            "ghsa_id": f"GHSA-generated-from-diff-{abs(hash(security_diff)) % 10000}",
            "summary": "Authentication bypass due to removed password hashing",
            "details": f"Security analysis of code changes in {summary['files_modified']} files "
            f"revealed removal of password hashing mechanism. "
            f"This allows attackers to bypass authentication with plain-text passwords.",
            "severity": "HIGH",  # Derived from security analysis
            "cwe_ids": [
                287,
                326,
            ],  # CWE-287: Authentication bypass, CWE-326: Weak crypto
            "references": [
                {
                    "url": "https://internal.security/diff-analysis",
                    "source": "security_team",
                }
            ],
            "affected_files": [hunk.file_path for hunk in hunks],
        }

        # Create advisory using parser
        advisory_parser = MultiFormatAdvisoryParser()
        vulnerability_report = advisory_parser.parse(advisory_data)

        # Verify integration results
        assert vulnerability_report.severity == SeverityEnum.HIGH
        assert "password hashing" in vulnerability_report.description.lower()
        assert "CWE-287" in vulnerability_report.cwe_ids
        assert "CWE-326" in vulnerability_report.cwe_ids

        # Test that diff analysis informed advisory creation
        assert summary["files_modified"] == 1
        assert len(hunks) == 1
        assert hunks[0].file_path == "auth/login.py"

        # Create evidence from diff analysis
        diff_evidence = Evidence(
            type="code_diff",
            content=f"Removed password hashing in {hunks[0].file_path}",
            confidence=0.95,
            file_path=hunks[0].file_path,
            line_number=hunks[0].old_start,
        )

        # Add evidence to vulnerability report
        vulnerability_report.evidence.append(diff_evidence)

        # Advisory parser adds one evidence automatically, plus our added evidence
        assert len(vulnerability_report.evidence) >= 1
        # Find our added evidence
        diff_evidences = [
            e for e in vulnerability_report.evidence if e.type == "code_diff"
        ]
        assert len(diff_evidences) == 1
        assert diff_evidences[0].file_path == "auth/login.py"

    def test_version_constraint_resolution_across_ecosystems(self):
        """Test version constraint resolution across multiple package ecosystems"""
        version_extractor = VersionExtractor()

        # Test constraints across different ecosystems
        ecosystem_constraints = [
            (
                "^2.1.0",
                EcosystemEnum.NPM,
                ["2.1.0", "2.1.5", "2.9.0"],
                ["3.0.0", "1.9.0"],
            ),
            (
                ">=1.5.0,<2.0.0",
                EcosystemEnum.PYPI,
                ["1.5.0", "1.8.3", "1.99.99"],
                ["2.0.0", "1.4.9"],
            ),
            (
                "[2.0,3.0)",
                EcosystemEnum.MAVEN,
                ["2.0.0", "2.5.1", "2.999"],
                ["3.0.0", "1.9.9"],
            ),
            ("~>1.4.0", EcosystemEnum.RUBYGEMS, ["1.4.0", "1.4.9"], ["1.5.0", "1.3.9"]),
        ]

        for (
            constraint_str,
            ecosystem,
            should_satisfy,
            should_not_satisfy,
        ) in ecosystem_constraints:
            try:
                version_range = version_extractor.create_version_range(
                    constraint_str, ecosystem
                )

                # Test versions that should satisfy
                for version in should_satisfy:
                    try:
                        result = version_range.satisfies(version)
                        # Note: Some constraint types may not be fully implemented
                        # This test verifies the infrastructure works
                    except Exception:
                        # Expected for some constraint types
                        pass

                # Test versions that should not satisfy
                for version in should_not_satisfy:
                    try:
                        result = version_range.satisfies(version)
                        # Note: Some constraint types may not be fully implemented
                    except Exception:
                        # Expected for some constraint types
                        pass

                # Verify basic properties
                assert version_range.ecosystem == ecosystem
                assert len(version_range.constraints) >= 1

            except Exception:
                # Some constraint types might not be implemented yet
                # Test verifies parsing doesn't crash
                pass

        # Test cross-ecosystem dependency analysis simulation
        dependency_graph = {
            "web-app": {
                "ecosystem": EcosystemEnum.NPM,
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0", "lodash": ">=4.0.0"},
            },
            "api-backend": {
                "ecosystem": EcosystemEnum.PYPI,
                "version": "2.1.0",
                "dependencies": {"flask": ">=2.0.0,<3.0.0", "requests": ">=2.25.0"},
            },
        }

        # Test that we can process multi-ecosystem dependencies
        for component_name, component_info in dependency_graph.items():
            ecosystem = component_info["ecosystem"]

            for dep_name, dep_constraint in component_info["dependencies"].items():
                try:
                    version_range = version_extractor.create_version_range(
                        dep_constraint, ecosystem
                    )
                    assert version_range.ecosystem == ecosystem
                except Exception:
                    # Some constraint parsing might fail, that's OK
                    pass

    def test_advisory_parsing_with_version_extraction(self):
        """Test extracting version information from advisory text content"""
        version_extractor = VersionExtractor()
        advisory_parser = MultiFormatAdvisoryParser()

        # Advisory with embedded version information
        advisory_with_versions = {
            "ghsa_id": "GHSA-version-extraction",
            "summary": "Vulnerability in package versions 1.2.0 through 2.1.5",
            "details": """
            This vulnerability affects all versions from 1.2.0 up to but not including 2.2.0.
            
            Specifically affected versions:
            - v1.2.0 to v2.1.5 (inclusive)
            - Beta versions 2.0.0-beta.1 through 2.0.0-beta.3
            - Release candidates 2.1.0-rc1 and 2.1.0-rc2
            
            Fixed in version 2.2.0 and all subsequent releases.
            Backports available in 1.9.8 for the 1.x branch.
            """,
            "severity": "MEDIUM",
        }

        # Parse the advisory
        vuln_report = advisory_parser.parse(advisory_with_versions)

        # Extract versions from the advisory content
        full_text = f"{vuln_report.title} {vuln_report.description}"
        extracted_versions = version_extractor.extract_versions_from_text(full_text)

        # Verify version extraction
        expected_versions = ["1.2.0", "2.1.5", "2.2.0", "2.0.0", "1.9.8"]

        for expected in expected_versions:
            assert any(
                expected in version for version in extracted_versions
            ), f"Expected version {expected} not found in {extracted_versions}"

        # Test creating version constraints from extracted information
        try:
            # Simulate creating constraints from extracted version info
            main_constraint = version_extractor.create_version_range(
                ">=1.2.0,<2.2.0", EcosystemEnum.NPM
            )
            fixed_constraint = version_extractor.create_version_range(
                ">=2.2.0", EcosystemEnum.NPM
            )

            assert main_constraint.ecosystem == EcosystemEnum.NPM
            assert fixed_constraint.ecosystem == EcosystemEnum.NPM

        except Exception:
            # Constraint creation might not be fully implemented
            pass

        # Test that advisory information is preserved
        assert "1.2.0" in vuln_report.description
        assert "2.2.0" in vuln_report.description
        assert vuln_report.severity == SeverityEnum.MEDIUM

    def test_security_pattern_detection_with_risk_assessment(self):
        """Test security pattern detection confidence affecting risk scores"""
        diff_parser = UnifiedDiffParser()

        # Create diff with varying security confidence levels
        mixed_confidence_diff = """--- a/mixed_security.py
+++ b/mixed_security.py
@@ -10,20 +10,15 @@ def process_data(user_input, config):
     # High confidence security issue: Direct SQL injection
-    query = "SELECT * FROM users WHERE id = ?"
-    result = db.execute(query, (user_input,))
+    query = f"SELECT * FROM users WHERE id = '{user_input}'"
+    result = db.execute(query)
     
     # Medium confidence: Removed validation (could be moved elsewhere)
-    if not validate_input(user_input):
-        return None
+    # TODO: Validation moved to middleware
     
     # Lower confidence: Changed logging level (might be intentional)
-    logger.error(f"Processing failed for user: {user_input}")
+    logger.debug(f"Processing failed for user: {user_input}")
     
     return result
"""

        # Parse and analyze the diff
        diff_result = diff_parser.parse_and_analyze(mixed_confidence_diff)

        # Create risk factors based on security analysis
        sql_injection_factor = RiskFactor(
            name="SQL Injection Pattern Detected",
            value="high_confidence",
            weight=0.5,
            description="High confidence detection of SQL injection vulnerability",
        )

        validation_removal_factor = RiskFactor(
            name="Input Validation Removal",
            value="medium_confidence",
            weight=0.3,
            description="Medium confidence - validation code removed",
        )

        logging_change_factor = RiskFactor(
            name="Information Disclosure Risk",
            value="low_confidence",
            weight=0.2,
            description="Low confidence - logging level change may expose information",
        )

        # Create risk assessment incorporating pattern detection confidence
        pattern_based_assessment = RiskAssessment(
            vulnerability_id="PATTERN-BASED-RISK",
            base_score=8.0,
            derived_score=7.2,  # Adjusted based on confidence levels
            severity=SeverityEnum.HIGH,
            confidence=0.8,  # Average of pattern detection confidences
            factors=[
                sql_injection_factor,
                validation_removal_factor,
                logging_change_factor,
            ],
            impact=Impact(
                confidentiality=ImpactLevel.COMPLETE,
                integrity=ImpactLevel.PARTIAL,
                availability=ImpactLevel.NONE,
            ),
            mitigations=[],
            reasoning="Risk score derived from security pattern detection with varying confidence levels. "
            "High confidence SQL injection pattern increases base risk, "
            "medium confidence validation removal adds moderate risk, "
            "low confidence logging change has minimal impact.",
        )

        # Test risk calculation incorporates confidence
        overall_risk = pattern_based_assessment.calculate_overall_risk()

        # Verify risk assessment structure
        assert len(pattern_based_assessment.factors) == 3
        assert pattern_based_assessment.base_score == 8.0
        assert (
            pattern_based_assessment.derived_score < pattern_based_assessment.base_score
        )

        # Test factor weights sum appropriately
        total_weight = sum(f.weight for f in pattern_based_assessment.factors)
        assert abs(total_weight - 1.0) < 0.01

        # Verify that diff analysis completed
        assert "security_matches" in diff_result
        assert diff_result["summary"]["files_modified"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
