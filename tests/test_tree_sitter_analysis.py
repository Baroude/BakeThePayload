# ABOUTME: Tests for Tree-sitter code analysis functionality
# ABOUTME: Validates context extraction, grammar management, and call graph generation

import os
import tempfile
from pathlib import Path

import pytest

from analysis.callgraph import CallGraph, CallGraphBuilder, CallGraphNode
from analysis.context import (
    CodeContext,
    CodeContextExtractor,
    FunctionContext,
    LanguageDetector,
    SupportedLanguage,
)
from analysis.grammar import (
    GrammarStatus,
    LanguageGrammarManager,
    detect_language_from_content,
)


class TestLanguageDetector:
    """Test language detection from file extensions"""

    def test_python_detection(self) -> None:
        assert LanguageDetector.detect_language("test.py") == SupportedLanguage.PYTHON
        assert (
            LanguageDetector.detect_language("/path/to/script.py")
            == SupportedLanguage.PYTHON
        )

    def test_javascript_detection(self) -> None:
        assert (
            LanguageDetector.detect_language("app.js") == SupportedLanguage.JAVASCRIPT
        )
        assert (
            LanguageDetector.detect_language("component.jsx")
            == SupportedLanguage.JAVASCRIPT
        )

    def test_typescript_detection(self) -> None:
        assert (
            LanguageDetector.detect_language("app.ts") == SupportedLanguage.TYPESCRIPT
        )
        assert (
            LanguageDetector.detect_language("component.tsx")
            == SupportedLanguage.TYPESCRIPT
        )

    def test_java_detection(self) -> None:
        assert LanguageDetector.detect_language("Main.java") == SupportedLanguage.JAVA

    def test_ruby_detection(self) -> None:
        assert LanguageDetector.detect_language("app.rb") == SupportedLanguage.RUBY

    def test_unsupported_extension(self) -> None:
        assert LanguageDetector.detect_language("file.txt") is None
        assert LanguageDetector.detect_language("README.md") is None


class TestLanguageGrammarManager:
    """Test Tree-sitter grammar management"""

    def test_grammar_initialization(self) -> None:
        manager = LanguageGrammarManager()
        status = manager.get_grammar_status()

        # Should have attempted to load all languages
        assert len(status) == len(SupportedLanguage)

        # High priority languages should be available
        available_langs = manager.get_available_languages()
        high_priority_missing = manager.get_missing_high_priority_languages()

        # At least Python should work
        assert SupportedLanguage.PYTHON in available_langs
        assert len(high_priority_missing) < len(manager.HIGH_PRIORITY_LANGUAGES)

    def test_parser_creation(self) -> None:
        manager = LanguageGrammarManager()

        # Test getting parser for Python
        parser = manager.get_parser(SupportedLanguage.PYTHON)
        assert parser is not None

        # Test unsupported language returns None
        if not manager.is_language_supported(SupportedLanguage.RUST):
            parser = manager.get_parser(SupportedLanguage.RUST)
            assert parser is None

    def test_grammar_validation(self) -> None:
        manager = LanguageGrammarManager()

        # Test validation with Python
        if manager.is_language_supported(SupportedLanguage.PYTHON):
            assert manager.validate_grammar(SupportedLanguage.PYTHON) is True

    def test_language_statistics(self) -> None:
        manager = LanguageGrammarManager()
        stats = manager.get_language_statistics()

        assert "total_languages" in stats
        assert "available" in stats
        assert "unavailable" in stats
        assert "error" in stats
        assert stats["total_languages"] == len(SupportedLanguage)
        assert (
            stats["available"] + stats["unavailable"] + stats["error"]
            == stats["total_languages"]
        )


class TestContentBasedDetection:
    """Test content-based language detection"""

    def test_python_content_detection(self) -> None:
        content = "#!/usr/bin/env python\nimport os\ndef main():\n    pass"
        lang = detect_language_from_content(content, "unknown")
        assert lang == SupportedLanguage.PYTHON

    def test_javascript_content_detection(self) -> None:
        content = "function test() {\n    console.log('hello');\n}"
        lang = detect_language_from_content(content, "unknown")
        assert lang == SupportedLanguage.JAVASCRIPT

    def test_java_content_detection(self) -> None:
        content = (
            "package com.example;\npublic class Test {\n    public void main() {}\n}"
        )
        lang = detect_language_from_content(content, "unknown")
        assert lang == SupportedLanguage.JAVA

    def test_ruby_content_detection(self) -> None:
        content = "def hello\n  puts 'world'\nend"
        lang = detect_language_from_content(content, "unknown")
        assert lang == SupportedLanguage.RUBY


class TestCodeContextExtractor:
    """Test code context extraction using Tree-sitter"""

    def test_python_function_extraction(self) -> None:
        extractor = CodeContextExtractor()

        python_code = """
def vulnerable_function(user_input):
    # This function has a vulnerability
    command = "ls " + user_input
    os.system(command)
    return "done"

def safe_function():
    return "safe"

def caller_function():
    result = vulnerable_function("test")
    return result
"""

        context = extractor.extract_context("test.py", python_code)

        # Should extract functions
        assert len(context.primary_functions) > 0
        assert context.file_language == SupportedLanguage.PYTHON
        assert context.confidence_score > 0.0

        # Find the vulnerable function
        vuln_func = None
        for func in context.primary_functions:
            if func.name == "vulnerable_function":
                vuln_func = func
                break

        assert vuln_func is not None
        assert vuln_func.parameters == ["user_input"]
        assert "os.system" in vuln_func.calls_made or "system" in vuln_func.calls_made

    def test_javascript_function_extraction(self) -> None:
        extractor = CodeContextExtractor()

        js_code = """
function vulnerableFunction(userInput) {
    // Vulnerable to injection
    const query = "SELECT * FROM users WHERE name = '" + userInput + "'";
    return database.query(query);
}

const safeFunction = () => {
    return "safe";
};

function callerFunction() {
    return vulnerableFunction("test");
}
"""

        context = extractor.extract_context("test.js", js_code)

        # Should extract functions
        assert len(context.primary_functions) > 0
        assert context.file_language == SupportedLanguage.JAVASCRIPT
        assert context.confidence_score > 0.0

    def test_target_line_filtering(self) -> None:
        extractor = CodeContextExtractor()

        python_code = """
def function_one():
    pass

def target_function():
    # This is the target
    return "target"

def function_three():
    pass
"""

        # Extract context targeting specific lines
        context = extractor.extract_context(
            "test.py", python_code, target_lines=[5, 6, 7]
        )

        # Should primarily find the target function
        target_found = any(
            func.name == "target_function" for func in context.primary_functions
        )
        assert target_found

    def test_unsupported_language(self) -> None:
        extractor = CodeContextExtractor()

        # Unknown file extension
        context = extractor.extract_context("test.unknown", "some code")

        # Should return empty context with 0 confidence
        assert len(context.primary_functions) == 0
        assert context.confidence_score == 0.0


class TestCallGraphBuilder:
    """Test call graph generation"""

    def test_simple_call_graph(self) -> None:
        builder = CallGraphBuilder()

        # Create temporary files for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # File 1: caller.py
            caller_path = os.path.join(temp_dir, "caller.py")
            with open(caller_path, "w") as f:
                f.write(
                    """
def main():
    result = helper_function("test")
    return result

def helper_function(arg):
    return process_data(arg)
"""
                )

            # File 2: processor.py
            processor_path = os.path.join(temp_dir, "processor.py")
            with open(processor_path, "w") as f:
                f.write(
                    """
def process_data(data):
    return data.upper()

def unused_function():
    pass
"""
                )

            # Build call graph
            graph = builder.build_call_graph([caller_path, processor_path])

            # Verify nodes were created
            assert len(graph.nodes) > 0
            assert len(graph.relationships) > 0
            assert graph.confidence_score > 0.0

            # Check for specific functions
            main_key = f"{caller_path}:main"
            helper_key = f"{caller_path}:helper_function"

            # Should have found main and helper functions
            node_keys = set(graph.nodes.keys())
            main_found = any("main" in key for key in node_keys)
            helper_found = any("helper_function" in key for key in node_keys)

            assert main_found
            assert helper_found

    def test_call_graph_relationships(self) -> None:
        builder = CallGraphBuilder()

        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = os.path.join(temp_dir, "test.py")
            with open(test_file, "w") as f:
                f.write(
                    """
def caller():
    callee()
    return "done"

def callee():
    return "result"
"""
                )

            graph = builder.build_call_graph([test_file])

            # Should have relationships
            assert len(graph.relationships) > 0

            # Find caller relationship
            caller_to_callee = None
            for rel in graph.relationships:
                if rel.caller_function == "caller" and rel.callee_function == "callee":
                    caller_to_callee = rel
                    break

            assert caller_to_callee is not None
            assert caller_to_callee.confidence > 0.0

    def test_empty_files(self) -> None:
        builder = CallGraphBuilder()

        # Test with empty file list
        graph = builder.build_call_graph([])
        assert len(graph.nodes) == 0
        assert len(graph.relationships) == 0
        assert graph.confidence_score == 0.0

    def test_nonexistent_files(self) -> None:
        builder = CallGraphBuilder()

        # Test with nonexistent files
        graph = builder.build_call_graph(["/nonexistent/file.py"])
        assert len(graph.nodes) == 0
        assert len(graph.relationships) == 0


class TestTreeSitterIntegration:
    """Integration tests for Tree-sitter analysis components"""

    def test_end_to_end_analysis(self) -> None:
        """Test complete analysis pipeline"""
        extractor = CodeContextExtractor()
        builder = CallGraphBuilder()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a realistic Python file
            test_file = os.path.join(temp_dir, "vulnerable.py")
            with open(test_file, "w") as f:
                f.write(
                    """
import os
import subprocess

def authenticate_user(username, password):
    # Vulnerable SQL injection
    query = f"SELECT * FROM users WHERE name='{username}' AND pass='{password}'"
    return database.execute(query)

def execute_command(user_input):
    # Vulnerable command injection
    command = "ping " + user_input
    return subprocess.call(command, shell=True)

def main():
    user = authenticate_user(request.form['user'], request.form['pass'])
    if user:
        result = execute_command(request.form['cmd'])
        return result
    return "unauthorized"
"""
                )

            # Test context extraction
            with open(test_file, "r") as f:
                content = f.read()

            context = extractor.extract_context(test_file, content)

            # Verify extraction
            assert context.file_language == SupportedLanguage.PYTHON
            assert len(context.primary_functions) >= 3
            assert context.confidence_score > 0.5

            # Test call graph building
            graph = builder.build_call_graph([test_file])
            assert len(graph.nodes) >= 3
            assert len(graph.relationships) > 0
            assert graph.confidence_score > 0.0

            # Verify we can find the main function
            main_functions = [
                func for func in context.primary_functions if func.name == "main"
            ]
            assert len(main_functions) == 1

            main_func = main_functions[0]
            assert "authenticate_user" in main_func.calls_made
            assert "execute_command" in main_func.calls_made

    def test_performance_requirements(self) -> None:
        """Test that analysis meets performance requirements"""
        import time

        extractor = CodeContextExtractor()

        # Large-ish Python code sample
        large_code = """
import os
""" + "\n".join(
            [
                f"""
def function_{i}():
    return function_{i+1}() if {i} < 50 else "end"
"""
                for i in range(100)
            ]
        )

        start_time = time.time()
        context = extractor.extract_context("large.py", large_code)
        extraction_time = time.time() - start_time

        # Should complete within 5 seconds per spec
        assert extraction_time < 5.0
        assert len(context.primary_functions) > 0
        assert context.confidence_score > 0.0


@pytest.mark.integration
class TestTreeSitterRealWorld:
    """Integration tests with real vulnerability patterns"""

    def test_ruby_jwe_vulnerability_pattern(self) -> None:
        """Test analysis of Ruby JWE vulnerability pattern"""
        from analysis.grammar import LanguageGrammarManager

        manager = LanguageGrammarManager()

        # Skip test if Ruby grammar not available
        if not manager.is_language_supported(SupportedLanguage.RUBY):
            pytest.skip("Ruby grammar not available")

        extractor = CodeContextExtractor()

        # Sample Ruby code with vulnerability pattern
        ruby_code = """
module JWE
  class Cipher
    def decrypt(encrypted_data, key)
      # Vulnerable: No validation of encrypted_data structure
      header = JSON.parse(encrypted_data.split('.')[0])

      # Direct usage without validation
      if header['alg'] == 'dir'
        return decrypt_direct(encrypted_data, key)
      else
        return decrypt_normal(encrypted_data, key)
      end
    end

    private

    def decrypt_direct(data, key)
      # Vulnerable implementation
      payload = data.split('.')[1]
      Base64.decode64(payload)
    end
  end
end
"""

        context = extractor.extract_context("cipher.rb", ruby_code)

        # Should successfully parse Ruby
        assert context.file_language == SupportedLanguage.RUBY
        assert len(context.primary_functions) > 0
        assert context.confidence_score > 0.5

        # Should find the vulnerable decrypt method
        decrypt_found = any(
            func.name == "decrypt" for func in context.primary_functions
        )
        assert decrypt_found


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
