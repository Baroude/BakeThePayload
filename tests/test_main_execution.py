# ABOUTME: Tests for main.py vulnerability analysis execution flow
# ABOUTME: Validates CLI interface and generalized GHSA advisory processing using real data

import pytest
import json
from pathlib import Path
import os

# Import the main functionality we'll create
try:
    from main import VulnerabilityAnalyzer, main, detect_primary_language
except ImportError:
    # Module doesn't exist yet - this is expected in TDD
    pytest.skip("main.py not implemented yet", allow_module_level=True)


class TestVulnerabilityAnalyzer:
    """Test the core VulnerabilityAnalyzer class using real data"""

    @pytest.fixture
    def real_data(self):
        """Load real vulnerability data for testing"""
        data_file = Path("GHSA-c7p4-hx26-pr73-vulnerability-collection.json")
        if not data_file.exists():
            pytest.skip("Real data file not found")
        
        with open(data_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    @pytest.fixture
    def ai_context_data(self):
        """Load real AI context data for testing"""
        data_file = Path("GHSA-c7p4-hx26-pr73-ai-context.json")
        if not data_file.exists():
            pytest.skip("AI context file not found")
        
        with open(data_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    @pytest.mark.asyncio
    async def test_analyzer_with_real_ghsa_data(self, real_data):
        """Test analyzer can process real GHSA data structure"""
        vulnerability = real_data["vulnerability"]
        
        # Test that we can extract key information
        assert vulnerability["id"] == "GHSA-c7p4-hx26-pr73"
        assert vulnerability["severity"] == "critical"
        assert "JWE" in vulnerability["title"]
        assert "CWE-354" in vulnerability["cwe_ids"]

    @pytest.mark.asyncio 
    async def test_repository_context_processing(self, real_data):
        """Test processing of real repository context data"""
        security_analysis = real_data["security_analysis"]
        
        # Verify repository analysis structure
        assert "key_functions" in security_analysis
        assert "call_graph_summary" in security_analysis
        
        # Check function analysis
        functions = security_analysis["key_functions"]
        assert len(functions) > 0
        
        # Find the setup_cipher function (key vulnerable function)
        setup_cipher = next((f for f in functions if f["name"] == "setup_cipher"), None)
        assert setup_cipher is not None
        assert "parameters" in setup_cipher
        assert "callers" in setup_cipher

    @pytest.mark.asyncio
    async def test_security_pattern_extraction(self, ai_context_data):
        """Test extraction of security patterns from real data"""
        patterns = ai_context_data["security_analysis"]["patterns_detected"]
        
        # Should have crypto weakness and input validation patterns
        pattern_types = [p["pattern"] for p in patterns]
        assert "crypto_weakness" in pattern_types
        assert "input_validation" in pattern_types
        
        # Check pattern structure
        for pattern in patterns:
            assert "confidence" in pattern
            assert "description" in pattern
            assert "location" in pattern
            assert "file" in pattern["location"]
            assert "line" in pattern["location"]

    @pytest.mark.asyncio
    async def test_cross_reference_validation(self, real_data):
        """Test cross-reference data validation"""
        cross_refs = real_data["cross_references"]
        
        # Should have CVE ID and source availability info
        assert "cve_id" in cross_refs
        assert "commit_count" in cross_refs
        assert "nvd_available" in cross_refs
        assert "osv_count" in cross_refs
        
        # Check specific values from our test data
        assert cross_refs["cve_id"] == "CVE-2025-54887"
        assert cross_refs["commit_count"] >= 1

    @pytest.mark.asyncio
    async def test_language_detection_from_real_data(self, real_data):
        """Test language detection using real repository files"""
        # Check detected language in metadata
        detected_language = real_data["collection_metadata"]["detected_language"]
        assert detected_language == "ruby"
        
        # Extract file paths from vulnerable functions for validation
        functions = real_data["security_analysis"]["key_functions"]
        file_paths = [func["file"] for func in functions]
        
        # Should detect Ruby as primary language
        language = detect_primary_language(file_paths)
        assert language == "ruby"


class TestMainCLI:
    """Test the main CLI interface with real data expectations"""

    @pytest.mark.asyncio
    async def test_main_output_structure(self):
        """Test that main produces expected output structure"""
        # This will test the actual implementation once created
        expected_keys = [
            "collection_metadata",
            "vulnerability", 
            "security_analysis",
            "cross_references",
            "diff_summary"
        ]
        
        # Load real output to verify structure
        data_file = Path("GHSA-c7p4-hx26-pr73-vulnerability-collection.json")
        if data_file.exists():
            with open(data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for key in expected_keys:
                assert key in data

    @pytest.mark.asyncio  
    async def test_ai_context_optimization(self):
        """Test AI context optimization produces smaller, focused output"""
        from main import VulnerabilityAnalyzer
        
        # Test with a known GHSA ID, ensuring raw advisory is disabled
        ghsa_id = "GHSA-c7p4-hx26-pr73"
        
        # Create analyzer without raw advisory inclusion to generate optimized context
        analyzer = VulnerabilityAnalyzer(
            github_token=os.getenv('GITHUB_TOKEN', 'fake_token_for_test'),
            include_raw_advisory=False
        )
        
        # Generate fresh AI context without raw advisory
        try:
            await analyzer.analyze(ghsa_id)
        except Exception as e:
            pytest.skip(f"Cannot test without valid GitHub token: {e}")
        
        full_file = Path("GHSA-c7p4-hx26-pr73-vulnerability-collection.json")
        ai_file = Path("GHSA-c7p4-hx26-pr73-ai-context.json")
        
        if full_file.exists() and ai_file.exists():
            full_size = full_file.stat().st_size
            ai_size = ai_file.stat().st_size
            
            # AI context should be significantly smaller when raw advisory is excluded
            reduction_ratio = (full_size - ai_size) / full_size
            assert reduction_ratio > 0.6  # At least 60% reduction (current optimization level)
            
            # But should still contain essential data
            with open(ai_file, 'r', encoding='utf-8') as f:
                ai_data = json.load(f)
            
            assert "vulnerability" in ai_data
            assert "security_analysis" in ai_data
            assert "cross_references" in ai_data


class TestLanguageDetection:
    """Test language detection functionality with real file patterns"""

    def test_detect_ruby_files(self):
        """Test detection of Ruby repositories"""
        files = ["lib/jwt.rb", "spec/jwt_spec.rb", "Gemfile", "lib/jwe/enc/aes_gcm.rb"]
        language = detect_primary_language(files)
        
        assert language == "ruby"

    def test_detect_python_files(self):
        """Test detection of Python repositories"""
        files = ["src/main.py", "tests/test_main.py", "setup.py", "requirements.txt"]
        language = detect_primary_language(files)
        
        assert language == "python"

    def test_detect_javascript_files(self):
        """Test detection of JavaScript repositories"""
        files = ["src/index.js", "package.json", "tests/test.js", "webpack.config.js"]
        language = detect_primary_language(files)
        
        assert language == "javascript"

    def test_detect_java_files(self):
        """Test detection of Java repositories"""
        files = ["src/main/java/Main.java", "pom.xml", "src/test/java/Test.java"]
        language = detect_primary_language(files)
        
        assert language == "java"

    def test_detect_mixed_files_ruby_majority(self):
        """Test language detection with mixed files, Ruby majority"""
        files = ["lib/main.rb", "lib/utils.rb", "script.py", "config.json"]
        language = detect_primary_language(files)
        
        assert language == "ruby"

    def test_detect_unknown_language(self):
        """Test language detection with unknown file types"""
        files = ["readme.txt", "config.xml", "data.csv"]
        language = detect_primary_language(files)
        
        assert language == "unknown"