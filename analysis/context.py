# ABOUTME: Tree-sitter based code context extraction with hybrid AI selection approach
# ABOUTME: Provides function/context extraction with static queries and AI-determined depth

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import tree_sitter as ts

from models.vulnerability import VulnerabilityReport

# Import individual language grammars
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


class SupportedLanguage(Enum):
    """Supported programming languages for Tree-sitter analysis"""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    RUBY = "ruby"
    GO = "go"
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    PHP = "php"


@dataclass
class QueryResult:
    """Result from a Tree-sitter query execution"""

    node_type: str
    name: str
    start_byte: int
    end_byte: int
    start_point: Tuple[int, int]  # (row, column)
    end_point: Tuple[int, int]
    text: str
    captures: Dict[str, str]  # Named captures from the query


@dataclass
class FunctionContext:
    """Extracted context for a function or method"""

    name: str
    start_line: int
    end_line: int
    full_text: str
    parameters: List[str]
    return_type: Optional[str]
    calls_made: List[str]
    variables_used: List[str]
    file_path: str


@dataclass
class CodeContext:
    """Complete code context for vulnerability analysis"""

    primary_functions: List[FunctionContext]
    related_functions: List[FunctionContext]
    class_definitions: List[QueryResult]
    import_statements: List[QueryResult]
    file_language: SupportedLanguage
    extraction_depth: int
    confidence_score: float


class LanguageDetector:
    """Detects programming language from file extensions"""

    EXTENSION_MAP = {
        ".py": SupportedLanguage.PYTHON,
        ".js": SupportedLanguage.JAVASCRIPT,
        ".ts": SupportedLanguage.TYPESCRIPT,
        ".jsx": SupportedLanguage.JAVASCRIPT,
        ".tsx": SupportedLanguage.TYPESCRIPT,
        ".java": SupportedLanguage.JAVA,
        ".rb": SupportedLanguage.RUBY,
        ".go": SupportedLanguage.GO,
        ".c": SupportedLanguage.C,
        ".cpp": SupportedLanguage.CPP,
        ".cc": SupportedLanguage.CPP,
        ".cxx": SupportedLanguage.CPP,
        ".rs": SupportedLanguage.RUST,
        ".php": SupportedLanguage.PHP,
    }

    @classmethod
    def detect_language(cls, file_path: str) -> Optional[SupportedLanguage]:
        """Detect language from file extension"""
        path = Path(file_path)
        return cls.EXTENSION_MAP.get(path.suffix.lower())


class StaticQueryManager:
    """Manages static Tree-sitter queries for different languages"""

    def __init__(self) -> None:
        self._query_cache: Dict[str, ts.Query] = {}
        self._parsers: Dict[SupportedLanguage, ts.Parser] = {}

    def _get_parser(self, language: SupportedLanguage) -> ts.Parser:
        """Get or create parser for language"""
        if language not in self._parsers:
            parser = ts.Parser()

            # Map languages to their grammar modules
            language_modules = {
                SupportedLanguage.PYTHON: tree_sitter_python,
                SupportedLanguage.JAVASCRIPT: tree_sitter_javascript,
                SupportedLanguage.JAVA: tree_sitter_java,
                SupportedLanguage.RUBY: tree_sitter_ruby,
            }

            grammar_module = language_modules.get(language)
            if not grammar_module:
                raise ValueError(
                    f"No grammar module available for language: {language}"
                )

            try:
                ts_language_capsule = grammar_module.language()
                ts_language = ts.Language(ts_language_capsule)
                parser.language = ts_language
                self._parsers[language] = parser
            except Exception as e:
                raise ValueError(f"Failed to initialize parser for {language}: {e}")

        return self._parsers[language]

    def _get_query_patterns(self, language: SupportedLanguage) -> Dict[str, str]:
        """Get static query patterns for a language"""
        if language == SupportedLanguage.PYTHON:
            from .queries.python import (
                ALL_CALLS,
                ASSIGNMENTS,
                CLASS_DEFINITIONS,
                FUNCTION_DEFINITIONS,
                IMPORT_STATEMENTS,
                METHOD_DEFINITIONS,
            )

            return {
                "functions": FUNCTION_DEFINITIONS,
                "methods": METHOD_DEFINITIONS,
                "calls": ALL_CALLS,
                "classes": CLASS_DEFINITIONS,
                "assignments": ASSIGNMENTS,
                "imports": IMPORT_STATEMENTS,
            }
        elif language == SupportedLanguage.JAVASCRIPT:
            from .queries.javascript import (
                ALL_CALLS,
                ALL_FUNCTIONS,
                CLASS_DECLARATIONS,
                IMPORT_STATEMENTS,
                VARIABLE_DECLARATIONS,
            )

            return {
                "functions": ALL_FUNCTIONS,
                "calls": ALL_CALLS,
                "classes": CLASS_DECLARATIONS,
                "variables": VARIABLE_DECLARATIONS,
                "imports": IMPORT_STATEMENTS,
            }
        elif language == SupportedLanguage.JAVA:
            from .queries.java import (
                ALL_METHODS,
                ALL_TYPES,
                FIELD_DECLARATIONS,
                IMPORT_DECLARATIONS,
                METHOD_INVOCATIONS,
            )

            return {
                "methods": ALL_METHODS,
                "calls": METHOD_INVOCATIONS,
                "types": ALL_TYPES,
                "fields": FIELD_DECLARATIONS,
                "imports": IMPORT_DECLARATIONS,
            }
        elif language == SupportedLanguage.RUBY:
            from .queries.ruby import (
                ALL_ASSIGNMENTS,
                ALL_CALLS,
                ALL_DEFINITIONS,
                REQUIRE_STATEMENTS,
            )

            return {
                "definitions": ALL_DEFINITIONS,
                "calls": ALL_CALLS,
                "assignments": ALL_ASSIGNMENTS,
                "requires": REQUIRE_STATEMENTS,
            }
        else:
            return {}

    def execute_query(
        self, language: SupportedLanguage, content: str, query_type: str
    ) -> List[QueryResult]:
        """Execute a static query on code content"""
        try:
            parser = self._get_parser(language)
            patterns = self._get_query_patterns(language)

            if query_type not in patterns:
                return []

            # Parse the code
            tree = parser.parse(content.encode("utf-8"))

            # Create and execute query
            query_key = f"{language.value}_{query_type}"
            if query_key not in self._query_cache:
                # Get language from parser
                parser = self._get_parser(language)
                ts_language = parser.language
                query = ts.Query(ts_language, patterns[query_type])
                self._query_cache[query_key] = query
            else:
                query = self._query_cache[query_key]

            # Execute query and collect results
            cursor = ts.QueryCursor(query)
            matches = cursor.matches(tree.root_node)
            results = []

            for pattern_index, captures_dict in matches:
                # Group all captures from this match together
                all_captures = {}
                main_node = None

                for capture_name, nodes in captures_dict.items():
                    for node in nodes:
                        node_text = getattr(node, "text", b"")
                        text = (
                            node_text.decode("utf-8")
                            if hasattr(node_text, "decode")
                            else str(node_text)
                        )
                        all_captures[capture_name] = text

                        # Use the largest node as the main node (usually the definition)
                        current_size = node.end_byte - node.start_byte
                        if main_node is not None:
                            main_size = (  # type: ignore[unreachable]
                                main_node.end_byte - main_node.start_byte
                            )
                        else:
                            main_size = -1
                        if current_size > main_size:
                            main_node = node

                if main_node:
                    # Create a single result with all captures from this match
                    main_node_text = getattr(main_node, "text", b"")
                    main_text = (
                        main_node_text.decode("utf-8")
                        if hasattr(main_node_text, "decode")
                        else str(main_node_text)
                    )

                    result = QueryResult(
                        node_type=main_node.type,
                        name=f"{query_type}.definition",  # Use query type as name
                        start_byte=main_node.start_byte,
                        end_byte=main_node.end_byte,
                        start_point=(
                            main_node.start_point[0],
                            main_node.start_point[1],
                        ),
                        end_point=(main_node.end_point[0], main_node.end_point[1]),
                        text=main_text,
                        captures=all_captures,
                    )
                    results.append(result)

            return results

        except Exception as e:
            # Log error but don't crash the analysis
            print(f"Query execution failed for {language} {query_type}: {e}")
            return []


class CodeContextExtractor:
    """
    Hybrid static query + AI selection approach for code context extraction.
    Uses Tree-sitter static queries with AI-determined relevance and depth.
    """

    def __init__(self) -> None:
        self.query_manager = StaticQueryManager()
        self.language_detector = LanguageDetector()

    def extract_context(
        self,
        file_path: str,
        content: str,
        target_lines: Optional[List[int]] = None,
        vulnerability_type: Optional[str] = None,
    ) -> CodeContext:
        """
        Extract code context using hybrid approach:
        1. Detect language
        2. Run static queries
        3. AI processes results to determine optimal extraction depth
        """
        # Detect language
        language = self.language_detector.detect_language(file_path)
        if not language:
            return self._create_empty_context(file_path)

        # Execute static queries
        query_results = self._execute_all_queries(language, content)

        # Extract function contexts
        primary_functions = self._extract_primary_functions(
            query_results, content, target_lines
        )

        # For now, use simple heuristics for related functions
        # In Phase 3, AI will determine optimal extraction depth
        related_functions = self._extract_related_functions(
            query_results, content, primary_functions
        )

        # Extract other relevant structures
        class_definitions = query_results.get("classes", []) + query_results.get(
            "types", []
        )
        import_statements = query_results.get("imports", []) + query_results.get(
            "requires", []
        )

        # Calculate confidence score based on extraction success
        confidence = self._calculate_confidence(primary_functions, query_results)

        return CodeContext(
            primary_functions=primary_functions,
            related_functions=related_functions,
            class_definitions=class_definitions,
            import_statements=import_statements,
            file_language=language,
            extraction_depth=1,  # Simple depth for now
            confidence_score=confidence,
        )

    def _execute_all_queries(
        self, language: SupportedLanguage, content: str
    ) -> Dict[str, List[QueryResult]]:
        """Execute all available static queries for a language"""
        patterns = self.query_manager._get_query_patterns(language)
        results = {}

        for query_type in patterns.keys():
            results[query_type] = self.query_manager.execute_query(
                language, content, query_type
            )

        return results

    def _extract_primary_functions(
        self,
        query_results: Dict[str, List[QueryResult]],
        content: str,
        target_lines: Optional[List[int]],
    ) -> List[FunctionContext]:
        """Extract primary functions relevant to the vulnerability"""
        functions = []
        seen_functions = set()  # Track to avoid duplicates

        # Get function/method definitions
        function_results = (
            query_results.get("functions", [])
            + query_results.get("methods", [])
            + query_results.get("definitions", [])
        )

        for result in function_results:
            if result.name.endswith(".definition"):
                # Extract function details
                func_context = self._create_function_context(
                    result, content, query_results
                )

                # Create unique key to avoid duplicates
                func_key = f"{func_context.name}:{func_context.start_line}:{func_context.end_line}"
                if func_key in seen_functions:
                    continue
                seen_functions.add(func_key)

                # If target lines specified, filter by relevance
                if target_lines:
                    start_line = result.start_point[0] + 1
                    end_line = result.end_point[0] + 1

                    # Check if function overlaps with target lines
                    if any(start_line <= line <= end_line for line in target_lines):
                        functions.append(func_context)
                else:
                    functions.append(func_context)

        return functions

    def _extract_related_functions(
        self,
        query_results: Dict[str, List[QueryResult]],
        content: str,
        primary_functions: List[FunctionContext],
    ) -> List[FunctionContext]:
        """Extract functions related to primary functions via calls"""
        related = []
        primary_names = {func.name for func in primary_functions}

        # Find call relationships
        call_results = query_results.get("calls", [])
        called_names = set()

        for call in call_results:
            if hasattr(call, "captures") and "call.name" in call.captures:
                called_names.add(call.captures["call.name"])

        # Extract functions that are called but not in primary set
        function_results = (
            query_results.get("functions", [])
            + query_results.get("methods", [])
            + query_results.get("definitions", [])
        )

        for result in function_results:
            if result.name.endswith(".definition"):
                func_name = self._extract_function_name(result)
                if func_name in called_names and func_name not in primary_names:
                    func_context = self._create_function_context(
                        result, content, query_results
                    )
                    related.append(func_context)

        return related

    def _create_function_context(
        self,
        result: QueryResult,
        content: str,
        query_results: Dict[str, List[QueryResult]],
    ) -> FunctionContext:
        """Create FunctionContext from QueryResult"""
        func_name = self._extract_function_name(result)

        # Extract parameters from the combined captures
        parameters = self._extract_parameters(result)

        # Find calls within this function
        calls_made = self._find_calls_in_range(
            query_results.get("calls", []), result.start_byte, result.end_byte
        )

        # Find variables used
        variables_used = self._find_variables_in_range(
            query_results.get("assignments", []) + query_results.get("variables", []),
            result.start_byte,
            result.end_byte,
        )

        return FunctionContext(
            name=func_name,
            start_line=result.start_point[0] + 1,
            end_line=result.end_point[0] + 1,
            full_text=result.text,
            parameters=parameters,
            return_type=None,  # Could be extracted from query captures
            calls_made=calls_made,
            variables_used=variables_used,
            file_path="",  # Will be set by caller
        )

    def _extract_function_name(self, result: QueryResult) -> str:
        """Extract function name from query result"""
        # Try different capture patterns
        for key in ["function.name", "method.name", "method.name"]:
            if key in result.captures:
                return result.captures[key]

        # Fallback: parse from text
        lines = result.text.split("\n")
        if lines:
            first_line = lines[0].strip()
            if first_line.startswith("def "):
                # Python function
                parts = first_line.split("(")
                if len(parts) > 0:
                    return parts[0].replace("def ", "").strip()
            elif first_line.startswith("function "):
                # JavaScript function
                parts = first_line.split("(")
                if len(parts) > 0:
                    return parts[0].replace("function ", "").strip()

        return "unknown_function"

    def _extract_parameters(self, result: QueryResult) -> List[str]:
        """Extract parameter names from function definition"""
        params = []

        # Look for parameter captures - check common parameter capture names
        param_keys = ["function.params", "method.params", "params"]

        for key in param_keys:
            if key in result.captures:
                value = result.captures[key]
                # Split on common parameter separators
                param_text = value.strip("()")
                if param_text and param_text != "self":  # Skip empty and 'self'
                    param_names = []
                    for param in param_text.split(","):
                        param = param.strip()
                        if param and param != "self":
                            # Handle type hints and default values
                            if ":" in param:
                                param = param.split(":")[0].strip()
                            if "=" in param:
                                param = param.split("=")[0].strip()
                            param_names.append(param)
                    params.extend(param_names)
                break  # Use first matching parameter capture

        return params

    def _find_calls_in_range(
        self, call_results: List[QueryResult], start_byte: int, end_byte: int
    ) -> List[str]:
        """Find function calls within a byte range"""
        calls = []

        for call in call_results:
            if start_byte <= call.start_byte <= end_byte:
                # Extract call name - handle both simple and attribute calls
                if "call.name" in call.captures:
                    # Simple function call
                    call_name = call.captures["call.name"]
                    calls.append(call_name)
                elif "call.method" in call.captures:
                    # Attribute call like os.system
                    method_name = call.captures["call.method"]
                    if "call.object" in call.captures:
                        obj_name = call.captures["call.object"]
                        calls.append(f"{obj_name}.{method_name}")
                    else:
                        calls.append(method_name)

        return calls

    def _find_variables_in_range(
        self, var_results: List[QueryResult], start_byte: int, end_byte: int
    ) -> List[str]:
        """Find variable usage within a byte range"""
        variables = set()

        for var in var_results:
            if start_byte <= var.start_byte <= end_byte:
                # Extract variable name
                var_name = (
                    var.captures.get("assignment.target", "")
                    or var.captures.get("variable.name", "")
                    or var.captures.get("variable.usage", "")
                )
                if var_name:
                    variables.add(var_name)

        return list(variables)

    def _calculate_confidence(
        self,
        primary_functions: List[FunctionContext],
        query_results: Dict[str, List[QueryResult]],
    ) -> float:
        """Calculate confidence score for context extraction"""
        base_score = 0.5

        # Boost for successful function extraction
        if primary_functions:
            base_score += 0.3

        # Boost for successful query execution
        successful_queries = sum(1 for results in query_results.values() if results)
        total_queries = len(query_results)
        if total_queries > 0:
            query_success_rate = successful_queries / total_queries
            base_score += 0.2 * query_success_rate

        return min(base_score, 1.0)

    def _create_empty_context(self, file_path: str) -> CodeContext:
        """Create empty context for unsupported files"""
        return CodeContext(
            primary_functions=[],
            related_functions=[],
            class_definitions=[],
            import_statements=[],
            file_language=SupportedLanguage.PYTHON,  # Default
            extraction_depth=0,
            confidence_score=0.0,
        )

    def extract_function_by_name(
        self, file_path: str, content: str, function_name: str
    ) -> Optional[FunctionContext]:
        """Extract specific function context by name"""
        language = self.language_detector.detect_language(file_path)
        if not language:
            return None

        query_results = self._execute_all_queries(language, content)

        # Find function with matching name
        function_results = (
            query_results.get("functions", [])
            + query_results.get("methods", [])
            + query_results.get("definitions", [])
        )

        for result in function_results:
            if result.name.endswith(".definition"):
                extracted_name = self._extract_function_name(result)
                if extracted_name == function_name:
                    func_context = self._create_function_context(
                        result, content, query_results
                    )
                    func_context.file_path = file_path
                    return func_context

        return None

    def get_supported_languages(self) -> List[SupportedLanguage]:
        """Get list of supported languages"""
        return list(SupportedLanguage)
