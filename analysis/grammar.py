# ABOUTME: Language grammar management for Tree-sitter parsers
# ABOUTME: Handles grammar loading, validation, and fallback for supported languages

from typing import Dict, List, Optional, Set
from enum import Enum
import tree_sitter as ts
from pathlib import Path

from analysis.context import SupportedLanguage

# Import individual language grammars
try:
    import tree_sitter_python
except ImportError:
    tree_sitter_python = None

try:
    import tree_sitter_javascript
except ImportError:
    tree_sitter_javascript = None

try:
    import tree_sitter_java
except ImportError:
    tree_sitter_java = None

try:
    import tree_sitter_ruby
except ImportError:
    tree_sitter_ruby = None


class GrammarStatus(Enum):
    """Status of grammar availability"""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class LanguageGrammarManager:
    """
    Manages Tree-sitter language grammars with dynamic loading and validation.
    Bundles common language grammars and installs additional as needed.
    """
    
    # High priority languages that should always be available
    HIGH_PRIORITY_LANGUAGES = {
        SupportedLanguage.PYTHON,
        SupportedLanguage.JAVASCRIPT,
        SupportedLanguage.JAVA,
        SupportedLanguage.RUBY
    }
    
    def __init__(self):
        self._grammar_status: Dict[SupportedLanguage, GrammarStatus] = {}
        self._parsers: Dict[SupportedLanguage, ts.Parser] = {}
        self._initialize_grammars()
    
    def _initialize_grammars(self) -> None:
        """Initialize and validate all supported language grammars"""
        for language in SupportedLanguage:
            try:
                self._load_grammar(language)
                self._grammar_status[language] = GrammarStatus.AVAILABLE
            except Exception as e:
                print(f"Warning: Failed to load grammar for {language.value}: {e}")
                self._grammar_status[language] = GrammarStatus.ERROR
    
    def _load_grammar(self, language: SupportedLanguage) -> None:
        """Load Tree-sitter grammar for a language"""
        # Map languages to their grammar modules
        language_modules = {
            SupportedLanguage.PYTHON: tree_sitter_python,
            SupportedLanguage.JAVASCRIPT: tree_sitter_javascript,
            SupportedLanguage.JAVA: tree_sitter_java,
            SupportedLanguage.RUBY: tree_sitter_ruby,
        }
        
        grammar_module = language_modules.get(language)
        if not grammar_module:
            raise ValueError(f"No grammar module available for language: {language}")
        
        try:
            # Get the language from the grammar module
            ts_language_capsule = grammar_module.language()
            ts_language = ts.Language(ts_language_capsule)
            
            # Create a test parser to verify functionality
            parser = ts.Parser()
            parser.language = ts_language
            
            # Store the parser for reuse
            self._parsers[language] = parser
            
        except Exception as e:
            raise RuntimeError(f"Failed to load {language.value} grammar: {e}")
    
    def is_language_supported(self, language: SupportedLanguage) -> bool:
        """Check if a language grammar is available and working"""
        return self._grammar_status.get(language) == GrammarStatus.AVAILABLE
    
    def get_parser(self, language: SupportedLanguage) -> Optional[ts.Parser]:
        """Get Tree-sitter parser for a language"""
        if not self.is_language_supported(language):
            return None
        
        return self._parsers.get(language)
    
    def get_available_languages(self) -> List[SupportedLanguage]:
        """Get list of languages with working grammars"""
        return [
            lang for lang, status in self._grammar_status.items()
            if status == GrammarStatus.AVAILABLE
        ]
    
    def get_grammar_status(self) -> Dict[SupportedLanguage, GrammarStatus]:
        """Get status of all language grammars"""
        return self._grammar_status.copy()
    
    def validate_grammar(self, language: SupportedLanguage) -> bool:
        """Validate that a grammar works with sample code"""
        parser = self.get_parser(language)
        if not parser:
            return False
        
        # Simple test code for each language
        test_code = {
            SupportedLanguage.PYTHON: "def test(): pass",
            SupportedLanguage.JAVASCRIPT: "function test() { }",
            SupportedLanguage.TYPESCRIPT: "function test(): void { }",
            SupportedLanguage.JAVA: "public class Test { public void test() { } }",
            SupportedLanguage.RUBY: "def test; end",
            SupportedLanguage.GO: "func test() { }",
            SupportedLanguage.C: "void test() { }",
            SupportedLanguage.CPP: "void test() { }",
            SupportedLanguage.RUST: "fn test() { }",
            SupportedLanguage.PHP: "<?php function test() { } ?>",
        }
        
        sample = test_code.get(language, "")
        if not sample:
            return False
        
        try:
            tree = parser.parse(sample.encode('utf-8'))
            return tree.root_node.has_error is False
        except Exception:
            return False
    
    def get_missing_high_priority_languages(self) -> List[SupportedLanguage]:
        """Get high priority languages that failed to load"""
        missing = []
        for lang in self.HIGH_PRIORITY_LANGUAGES:
            if not self.is_language_supported(lang):
                missing.append(lang)
        return missing
    
    def get_language_statistics(self) -> Dict[str, int]:
        """Get statistics about grammar availability"""
        stats = {
            'total_languages': len(SupportedLanguage),
            'available': 0,
            'unavailable': 0,
            'error': 0
        }
        
        for status in self._grammar_status.values():
            if status == GrammarStatus.AVAILABLE:
                stats['available'] += 1
            elif status == GrammarStatus.UNAVAILABLE:
                stats['unavailable'] += 1
            elif status == GrammarStatus.ERROR:
                stats['error'] += 1
        
        return stats


def detect_language_from_content(content: str, file_path: str) -> Optional[SupportedLanguage]:
    """
    Enhanced language detection using both file extension and content analysis
    """
    # First try file extension
    from analysis.context import LanguageDetector
    lang = LanguageDetector.detect_language(file_path)
    if lang:
        return lang
    
    # Fallback: content-based detection
    content_lower = content.lower().strip()
    
    # Check for language-specific patterns
    if content_lower.startswith('#!/usr/bin/env python') or 'import ' in content_lower:
        return SupportedLanguage.PYTHON
    elif content_lower.startswith('#!/usr/bin/env node') or 'function ' in content_lower:
        return SupportedLanguage.JAVASCRIPT
    elif 'public class ' in content_lower or 'package ' in content_lower:
        return SupportedLanguage.JAVA
    elif content_lower.startswith('#!/usr/bin/env ruby') or 'def ' in content_lower and 'end' in content_lower:
        return SupportedLanguage.RUBY
    elif 'func ' in content_lower and 'package ' in content_lower:
        return SupportedLanguage.GO
    elif '#include <' in content_lower:
        return SupportedLanguage.C
    elif 'fn ' in content_lower and 'use ' in content_lower:
        return SupportedLanguage.RUST
    elif content_lower.startswith('<?php'):
        return SupportedLanguage.PHP
    
    return None