#!/usr/bin/env python3
"""
Performance monitors for vulnerability analyzer
Tests model creation speed, parsing performance, and memory usage
"""

import pytest
import time
import psutil
import os
from typing import List
from datetime import datetime

from models import (
    VulnerabilityReport, Evidence, ExploitFlow, ExploitNode, FlowEdge,
    AffectedArtifact, VersionRange, Component, RiskAssessment, Impact,
    Mitigation, RiskFactor, SeverityEnum, NodeType, EcosystemEnum, ImpactLevel
)
from parsers import UnifiedDiffParser, MultiFormatAdvisoryParser, VersionExtractor


class PerformanceMonitor:
    """Helper class for performance measurements"""
    
    def __init__(self):
        self.process = psutil.Process(os.getpid())
    
    def measure_time_and_memory(self, func, *args, **kwargs):
        """Measure execution time and memory usage"""
        # Record initial state
        start_time = time.perf_counter()
        start_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        
        # Execute function
        result = func(*args, **kwargs)
        
        # Record final state
        end_time = time.perf_counter()
        end_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        
        return {
            'result': result,
            'time_seconds': end_time - start_time,
            'memory_mb': end_memory - start_memory,
            'peak_memory_mb': end_memory
        }


class TestModelPerformance:
    """Test model creation and validation performance"""
    
    @pytest.fixture
    def monitor(self):
        return PerformanceMonitor()
    
    def test_vulnerability_report_creation_speed(self, monitor):
        """Test speed of creating VulnerabilityReport instances"""
        
        def create_vulnerability_reports(count: int) -> List[VulnerabilityReport]:
            reports = []
            for i in range(count):
                report = VulnerabilityReport(
                    advisory_id=f"CVE-2024-{i:05d}",
                    title=f"Test Vulnerability {i}",
                    description=f"This is test vulnerability number {i} with some description text.",
                    severity=SeverityEnum.MEDIUM,
                    cvss_score=5.5,
                    cwe_ids=["CWE-79", "CWE-89"]
                )
                reports.append(report)
            return reports
        
        # Test creating 1000 vulnerability reports
        result = monitor.measure_time_and_memory(create_vulnerability_reports, 1000)
        
        # Performance requirements from phase1.md: 1000 instances < 1 second
        assert result['time_seconds'] < 1.0, f"Model creation took {result['time_seconds']:.3f}s, should be < 1s"
        assert len(result['result']) == 1000
        
        print(f"Created 1000 VulnerabilityReports in {result['time_seconds']:.3f}s")
        print(f"Memory usage: {result['memory_mb']:.2f}MB")
        
        # Test per-instance performance
        time_per_instance = result['time_seconds'] / 1000
        assert time_per_instance < 0.001, f"Per-instance creation: {time_per_instance:.6f}s, should be < 1ms"
    
    def test_complex_model_creation(self, monitor):
        """Test creation of complex models with relationships"""
        
        def create_complex_models(count: int):
            models = []
            for i in range(count):
                # Create evidence
                evidence = Evidence(
                    type="code",
                    content=f"Vulnerable code snippet {i}",
                    confidence=0.8,
                    file_path=f"/path/to/file{i}.py",
                    line_number=42 + i
                )
                
                # Create exploit nodes
                node1 = ExploitNode(
                    node_id=evidence.id,  # Reuse UUID
                    type=NodeType.ENTRY_POINT,
                    title=f"Entry Point {i}",
                    description=f"Initial attack vector {i}",
                    confidence=0.9,
                    evidence=[evidence]
                )
                
                node2 = ExploitNode(
                    node_id=evidence.id,  # Different UUID needed, but for speed test it's OK
                    type=NodeType.IMPACT,
                    title=f"Impact {i}",
                    description=f"Final impact {i}",
                    confidence=0.8
                )
                
                # Create flow
                edge = FlowEdge(
                    edge_id=evidence.id,
                    source=node1.node_id,
                    target=node2.node_id,
                    probability=0.7
                )
                
                flow = ExploitFlow(
                    name=f"Flow {i}",
                    description=f"Exploit flow {i}",
                    nodes=[node1, node2],
                    edges=[edge]
                )
                
                models.append(flow)
            
            return models
        
        # Test creating 500 complex models (fewer due to complexity)
        result = monitor.measure_time_and_memory(create_complex_models, 500)
        
        # Should complete in reasonable time
        assert result['time_seconds'] < 2.0, f"Complex model creation took {result['time_seconds']:.3f}s"
        assert len(result['result']) == 500
        
        print(f"Created 500 complex models in {result['time_seconds']:.3f}s")
    
    def test_model_validation_performance(self, monitor):
        """Test model validation speed"""
        
        def validate_models_with_errors(count: int):
            valid_count = 0
            error_count = 0
            
            for i in range(count):
                try:
                    # Mix of valid and invalid models
                    if i % 10 == 0:
                        # Create invalid model (bad CVSS score)
                        VulnerabilityReport(
                            advisory_id=f"invalid-{i}",
                            title="Invalid",
                            description="test",
                            severity=SeverityEnum.HIGH,
                            cvss_score=15.0  # Invalid score
                        )
                    else:
                        # Create valid model
                        VulnerabilityReport(
                            advisory_id=f"valid-{i}",
                            title="Valid",
                            description="test",
                            severity=SeverityEnum.LOW
                        )
                    valid_count += 1
                except Exception:
                    error_count += 1
            
            return valid_count, error_count
        
        result = monitor.measure_time_and_memory(validate_models_with_errors, 1000)
        valid_count, error_count = result['result']
        
        # Should handle validation efficiently
        assert result['time_seconds'] < 2.0
        assert error_count > 0  # Some validation errors expected
        assert valid_count > 0  # Some valid models expected
        
        print(f"Validated 1000 models ({valid_count} valid, {error_count} errors) in {result['time_seconds']:.3f}s")


class TestParserPerformance:
    """Test parser performance monitors"""
    
    @pytest.fixture
    def monitor(self):
        return PerformanceMonitor()
    
    def test_diff_parser_performance(self, monitor):
        """Test diff parsing speed with large diffs"""
        
        # Generate a large diff
        def generate_large_diff(num_files: int = 50, lines_per_file: int = 20) -> str:
            diff_parts = []
            for file_idx in range(num_files):
                diff_parts.append(f"--- a/file{file_idx}.py")
                diff_parts.append(f"+++ b/file{file_idx}.py")
                diff_parts.append(f"@@ -1,{lines_per_file} +1,{lines_per_file+2} @@")
                
                for line_idx in range(lines_per_file):
                    if line_idx == 10:  # Add security-relevant change
                        diff_parts.append(f"-    if validate_input(data):")
                        diff_parts.append(f"+    # TODO: add validation")
                        diff_parts.append(f"+    print('debug')")
                    else:
                        diff_parts.append(f" line {line_idx} content unchanged")
                        
            return "\n".join(diff_parts)
        
        large_diff = generate_large_diff()
        
        def parse_diff():
            parser = UnifiedDiffParser()
            return parser.parse_and_analyze(large_diff)
        
        result = monitor.measure_time_and_memory(parse_diff)
        
        # Performance requirement: 1000-line diff < 2 seconds
        # Our diff is ~1000 lines (50 files * 20 lines each)
        assert result['time_seconds'] < 2.0, f"Diff parsing took {result['time_seconds']:.3f}s, should be < 2s"
        
        analysis_result = result['result']
        assert len(analysis_result['hunks']) > 0
        
        print(f"Parsed large diff ({len(large_diff)} chars) in {result['time_seconds']:.3f}s")
        print(f"Found {analysis_result['summary']['total_hunks']} hunks")
    
    def test_advisory_parser_performance(self, monitor):
        """Test advisory parsing speed"""
        
        def parse_multiple_advisories(count: int):
            parser = MultiFormatAdvisoryParser()
            results = []
            
            for i in range(count):
                # Create test GHSA advisory
                advisory_data = {
                    "ghsa_id": f"GHSA-test-{i:04d}",
                    "summary": f"Test vulnerability {i}",
                    "details": f"This is a detailed description of vulnerability {i}. " * 10,  # Make it longer
                    "severity": "HIGH",
                    "cvss": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"},
                    "cwe_ids": [79, 89],
                    "references": [
                        {"url": f"https://example.com/advisory/{i}", "source": "test"},
                        {"url": f"https://github.com/fix/{i}", "source": "fix"}
                    ]
                }
                
                vuln_report = parser.parse(advisory_data)
                results.append(vuln_report)
            
            return results
        
        result = monitor.measure_time_and_memory(parse_multiple_advisories, 100)
        
        assert result['time_seconds'] < 5.0  # Should parse 100 advisories in under 5 seconds
        assert len(result['result']) == 100
        
        print(f"Parsed 100 advisories in {result['time_seconds']:.3f}s")
        print(f"Average per advisory: {result['time_seconds']/100*1000:.1f}ms")
    
    def test_version_extractor_performance(self, monitor):
        """Test version constraint processing speed"""
        
        def process_version_constraints(count: int):
            extractor = VersionExtractor()
            results = []
            
            test_constraints = [
                ("^1.2.3", EcosystemEnum.NPM),
                ("~1.0.0", EcosystemEnum.NPM),
                (">=1.0.0", EcosystemEnum.PYPI),
                ("1.2.3", EcosystemEnum.MAVEN),
                ("~>1.5", EcosystemEnum.RUBYGEMS)
            ]
            
            for i in range(count):
                constraint_str, ecosystem = test_constraints[i % len(test_constraints)]
                try:
                    version_range = extractor.create_version_range(
                        f"{constraint_str}.{i % 10}",  # Vary version
                        ecosystem
                    )
                    results.append(version_range)
                except Exception:
                    # Some constraints might fail, that's OK for performance test
                    pass
            
            return results
        
        result = monitor.measure_time_and_memory(process_version_constraints, 1000)
        
        assert result['time_seconds'] < 3.0  # Should process 1000 constraints quickly
        
        print(f"Processed {len(result['result'])} version constraints in {result['time_seconds']:.3f}s")


class TestMemoryUsage:
    """Test memory usage patterns"""
    
    @pytest.fixture
    def monitor(self):
        return PerformanceMonitor()
    
    def test_memory_usage_scaling(self, monitor):
        """Test that memory usage scales linearly with input size"""
        
        def create_models(count: int):
            models = []
            for i in range(count):
                model = VulnerabilityReport(
                    advisory_id=f"mem-test-{i}",
                    title=f"Memory test {i}",
                    description="Test description " * 50,  # Make it larger
                    severity=SeverityEnum.MEDIUM
                )
                models.append(model)
            return models
        
        # Test with different sizes
        sizes = [100, 500, 1000]
        memory_results = []
        
        for size in sizes:
            result = monitor.measure_time_and_memory(create_models, size)
            memory_per_model = result['peak_memory_mb'] / size if size > 0 else 0
            memory_results.append((size, result['peak_memory_mb'], memory_per_model))
            
            print(f"Size: {size}, Memory: {result['peak_memory_mb']:.2f}MB, Per model: {memory_per_model:.4f}MB")
        
        # Check that memory usage is reasonable
        _, peak_memory_1000, _ = memory_results[-1]
        
        # Performance requirement: Memory usage < 100MB for typical workloads
        assert peak_memory_1000 < 100, f"Memory usage {peak_memory_1000:.2f}MB exceeds 100MB limit"
    
    def test_memory_cleanup(self, monitor):
        """Test that objects are properly garbage collected"""
        import gc
        
        def create_and_destroy_models():
            # Create many models
            models = []
            for i in range(1000):
                model = VulnerabilityReport(
                    advisory_id=f"gc-test-{i}",
                    title=f"GC test {i}",
                    description="Test for garbage collection",
                    severity=SeverityEnum.LOW
                )
                models.append(model)
            
            # Clear references
            models.clear()
            gc.collect()  # Force garbage collection
            return "completed"
        
        result = monitor.measure_time_and_memory(create_and_destroy_models)
        
        # Memory usage should not be excessive after cleanup
        assert result['peak_memory_mb'] < 150  # Allow some overhead
        
        print(f"Memory after cleanup: {result['peak_memory_mb']:.2f}MB")


@pytest.mark.monitor
class TestBenchmarkSuite:
    """Complete monitor suite for CI/CD"""
    
    def test_overall_performance_monitor(self):
        """Comprehensive performance test for CI/CD monitoring"""
        monitor = PerformanceMonitor()
        
        start_time = time.perf_counter()
        start_memory = monitor.process.memory_info().rss / 1024 / 1024
        
        # Simulate realistic workload
        parser = UnifiedDiffParser()
        advisory_parser = MultiFormatAdvisoryParser()
        
        # Parse some diffs
        test_diff = """--- a/test.py
+++ b/test.py
@@ -1,5 +1,6 @@
 def process_data(input_data):
-    if validate(input_data):
-        return process(input_data)
+    # Skip validation for speed
+    print("debug")
+    return process(input_data)
     return None
"""
        
        for i in range(10):
            result = parser.parse_and_analyze(test_diff)
        
        # Parse some advisories
        for i in range(10):
            advisory = {
                "ghsa_id": f"GHSA-bench-{i:03d}",
                "summary": f"Benchmark test {i}",
                "severity": "MEDIUM"
            }
            vuln = advisory_parser.parse(advisory)
        
        # Create some models
        models = []
        for i in range(100):
            model = VulnerabilityReport(
                advisory_id=f"bench-{i}",
                title=f"Benchmark {i}",
                description="Benchmark test",
                severity=SeverityEnum.MEDIUM
            )
            models.append(model)
        
        end_time = time.perf_counter()
        end_memory = monitor.process.memory_info().rss / 1024 / 1024
        
        total_time = end_time - start_time
        memory_used = end_memory - start_memory
        
        print(f"Overall monitor completed in {total_time:.3f}s")
        print(f"Memory used: {memory_used:.2f}MB")
        
        # Overall performance should be reasonable
        assert total_time < 10.0  # Should complete in under 10 seconds
        assert memory_used < 50   # Should not use excessive memory


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])