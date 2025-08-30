# Missing Tests — Analysis Module

This document enumerates concrete, GitHub‑issue–ready tasks to improve test coverage for the `analysis` package. Each item includes scope, rationale, and acceptance criteria. Create separate issues per item.

## [analysis/context.py] Extend LanguageDetector extension coverage
- Summary: Add tests for all extensions in `EXTENSION_MAP` not currently covered.
- Rationale: Ensure file extension detection remains accurate across supported languages.
- References: `analysis/context.py: LanguageDetector.EXTENSION_MAP`, `analysis/context.py: LanguageDetector.detect_language`
- Acceptance Criteria:
  - Add tests asserting correct detection for: `.go`, `.c`, `.cpp` (and `.cc`/`.cxx`), `.rs`, `.php`.
  - Add a negative test asserting unknown extensions (e.g., `.txt`, `.md`) return `None`.
  - Tests live under `tests/` and run with `pytest -q` without network.
- Suggested Test Names:
  - `test_go_detection`, `test_c_cpp_detection`, `test_rust_php_detection`, `test_unsupported_extension`

## [analysis/grammar.py] Content-based detection for more languages + negatives
- Summary: Add tests for `detect_language_from_content` covering TypeScript, Go, C, Rust, PHP, and ambiguous/negative inputs.
- Rationale: Current tests only cover Python/JS/Java/Ruby; expand to all heuristics implemented.
- References: `analysis/grammar.py: detect_language_from_content`
- Acceptance Criteria:
  - Given representative snippets, detection returns: TypeScript, Go, C, Rust, PHP respectively.
  - Ambiguous or non-code content returns `None`.
  - Does not depend on installed grammars.
- Suggested Test Names:
  - `test_typescript_go_c_rust_php_content_detection`, `test_content_detection_negative_cases`

## [analysis/grammar.py] Validate grammars for all available languages
- Summary: Iterate available grammars and assert `validate_grammar(lang)` is True where supported.
- Rationale: Avoid regressions in parser initialization across installed grammars.
- References: `analysis/grammar.py: LanguageGrammarManager.validate_grammar`, `get_available_languages`
- Acceptance Criteria:
  - For each `lang` in `LanguageGrammarManager().get_available_languages()`, `validate_grammar(lang)` returns True.
  - Test skips cleanly if no languages are available (edge CI env).
- Suggested Test Name:
  - `test_validate_all_available_grammars`

## [analysis/grammar.py] High-priority grammar availability contracts
- Summary: Verify `get_missing_high_priority_languages()` only reports languages not available, and never includes those marked available.
- Rationale: Ensure status tracking is internally consistent.
- References: `analysis/grammar.py: LanguageGrammarManager.HIGH_PRIORITY_LANGUAGES`, `get_missing_high_priority_languages`, `get_available_languages`
- Acceptance Criteria:
  - Returned set is a subset of `HIGH_PRIORITY_LANGUAGES`.
  - Intersection with `get_available_languages()` is empty.
- Suggested Test Name:
  - `test_missing_high_priority_languages_consistency`

## [analysis/context.py] StaticQueryManager.execute_query correctness — Python
- Summary: Unit-test query results and captures for Python patterns.
- Rationale: End-to-end tests exist, but unit-level assertions on `QueryResult.captures` ensure query stability.
- References: `analysis/context.py: StaticQueryManager.execute_query`, `analysis/queries/python.py`
- Acceptance Criteria:
  - On a sample with function, attribute call (`os.system`), assignment, and imports:
    - `query_type="functions"` yields results with `captures` including `function.name` and `function.params`.
    - `query_type="calls"` yields results with `call.name` or (`call.object` + `call.method`).
    - `query_type="assignments"` yields results with `assignment.target`.
    - `query_type="imports"` yields results with `import.module`.
- Suggested Test Name:
  - `test_execute_query_python_captures`

## [analysis/context.py] StaticQueryManager.execute_query correctness — JavaScript
- Summary: Validate captures for JS functions, method calls, variables, and imports.
- Rationale: Symmetry with Python; catches query drift.
- References: `analysis/queries/javascript.py`
- Acceptance Criteria:
  - Skip if JS grammar not available (`LanguageGrammarManager().is_language_supported(JAVASCRIPT) == False`).
  - Asserts captures for: `ALL_FUNCTIONS`, `ALL_CALLS`, `VARIABLE_DECLARATIONS`, `IMPORT_STATEMENTS`.
- Suggested Test Name:
  - `test_execute_query_javascript_captures`

## [analysis/context.py] StaticQueryManager.execute_query correctness — Java
- Summary: Validate Java method/constructor detection and invocation captures.
- Rationale: Ensure Java queries compile and return expected captures when grammars are present.
- References: `analysis/queries/java.py`
- Acceptance Criteria:
  - Skip if Java grammar not available.
  - Asserts captures for `ALL_METHODS`, `METHOD_INVOCATIONS`, `ALL_TYPES`, `FIELD_DECLARATIONS`, `IMPORT_DECLARATIONS` as applicable to the sample.
- Suggested Test Name:
  - `test_execute_query_java_captures`

## [analysis/context.py] StaticQueryManager.execute_query correctness — Ruby
- Summary: Validate Ruby definitions, calls, assignments, and require statements.
- Rationale: Strengthen coverage of Ruby path used in integration.
- References: `analysis/queries/ruby.py`
- Acceptance Criteria:
  - Skip if Ruby grammar not available.
  - Asserts captures exist for `ALL_DEFINITIONS`, `ALL_CALLS`, `ALL_ASSIGNMENTS`, `REQUIRE_STATEMENTS`.
- Suggested Test Name:
  - `test_execute_query_ruby_captures`

## [analysis/context.py] StaticQueryManager edge cases — unknown query types and unsupported language
- Summary: Ensure unknown `query_type` and languages without patterns return empty lists.
- Rationale: Guard against exceptions and define clear contract.
- References: `analysis/context.py: StaticQueryManager._get_query_patterns`, `execute_query`
- Acceptance Criteria:
  - `execute_query(lang, code, "nonexistent_query")` returns `[]`.
  - For `SupportedLanguage.TYPESCRIPT` (no patterns defined), all `query_type` return `[]`.
- Suggested Test Name:
  - `test_execute_query_edge_cases`

## [analysis/context.py] Parameter extraction ignores self/defaults/type hints
- Summary: Verify `_extract_parameters` behavior via `CodeContextExtractor` on class methods.
- Rationale: Prevent regressions in argument parsing which feeds vulnerability analysis.
- References: `analysis/context.py: CodeContextExtractor._extract_parameters`
- Acceptance Criteria:
  - For `def m(self, a: int, b=1): ...` parameters resolve to `["a", "b"]`.
  - No `self` in results; type hints/defaults stripped.
- Suggested Test Name:
  - `test_parameter_extraction_python_method`

## [analysis/context.py] Variable usage extraction inside functions
- Summary: Verify variables collected from assignments/decls within byte range.
- Rationale: Ensures `variables_used` is populated correctly for contextual scoring.
- References: `analysis/context.py: CodeContextExtractor._find_variables_in_range`
- Acceptance Criteria:
  - Given a function body with assignments to `x` and `y`, `variables_used` contains `{"x","y"}` (order not important).
- Suggested Test Name:
  - `test_variable_usage_extraction`

## [analysis/context.py] Related function extraction via call relationships
- Summary: Ensure related functions are discovered when focusing on specific lines.
- Rationale: Validates the heuristic used before AI‑guided depth selection.
- References: `analysis/context.py: CodeContextExtractor._extract_related_functions`
- Acceptance Criteria:
  - With code where `caller()` calls `helper()`, and `target_lines` restrict extraction to `caller()`, `related_functions` includes `helper()`.
- Suggested Test Name:
  - `test_related_function_extraction_with_target_lines`

## [analysis/context.py] extract_function_by_name API behavior
- Summary: Assert correct return for present and missing functions across languages.
- Rationale: Public API utility; currently untested directly.
- References: `analysis/context.py: CodeContextExtractor.extract_function_by_name`
- Acceptance Criteria:
  - For Python sample, returns a `FunctionContext` for existing name; returns `None` for unknown name.
  - Repeat for JavaScript if grammar is available (skip otherwise).
- Suggested Test Name:
  - `test_extract_function_by_name`

## [analysis/context.py] get_supported_languages returns full enum
- Summary: Sanity test to ensure stable API contract.
- Rationale: Guards accidental filtering or ordering changes.
- References: `analysis/context.py: CodeContextExtractor.get_supported_languages`
- Acceptance Criteria:
  - `set(extractor.get_supported_languages()) == set(SupportedLanguage)`.
- Suggested Test Name:
  - `test_get_supported_languages_completeness`

## [analysis/callgraph.py] Callers and callees utilities
- Summary: Test `get_function_callers` and `get_function_callees` on a simple graph.
- Rationale: Helpers used by higher‑level features lack direct tests.
- References: `analysis/callgraph.py: CallGraphBuilder.get_function_callers`, `get_function_callees`
- Acceptance Criteria:
  - Given a file where `a()` calls `b()`, `get_function_callers(graph, 'b', file)` returns node for `a`, and `get_function_callees(graph, 'a', file)` returns node for `b`.
- Suggested Test Name:
  - `test_callers_and_callees_helpers`

## [analysis/callgraph.py] Call path search respects max_depth
- Summary: Verify `find_call_paths` depth constraint and discovered paths.
- Rationale: Prevent unbounded traversal and ensure utility correctness.
- References: `analysis/callgraph.py: CallGraphBuilder.find_call_paths`
- Acceptance Criteria:
  - For chain `a -> b -> c -> d`, with `max_depth=2`, paths from `a` to `d` are empty; with `max_depth>=3`, at least one path is returned and ends with `d`.
- Suggested Test Name:
  - `test_find_call_paths_depth`

## [analysis/callgraph.py] Graph statistics correctness
- Summary: Validate counts and resolution rate reported by `get_graph_statistics`.
- Rationale: Stats are user‑facing signals of analysis quality.
- References: `analysis/callgraph.py: CallGraphBuilder.get_graph_statistics`
- Acceptance Criteria:
  - For a small known sample, stats dict contains keys: `total_functions`, `total_relationships`, `internal_calls`, `external_calls`, `resolution_rate`, `max_outbound_calls`, `max_inbound_calls`, `confidence_score`.
  - Derived values match the constructed graph (tolerate float rounding for rates).
- Suggested Test Name:
  - `test_get_graph_statistics_values`

## [analysis/callgraph.py] Robustness to invalid source code
- Summary: Ensure builder handles syntactically invalid files without exceptions.
- Rationale: Real repos may include partial/invalid code during development.
- References: `analysis/callgraph.py: CallGraphBuilder._extract_all_functions`
- Acceptance Criteria:
  - Given a file with invalid Python syntax, `build_call_graph([path])` completes; `graph.nodes` and `graph.relationships` are empty or minimal, and no exceptions are thrown.
- Suggested Test Name:
  - `test_call_graph_handles_invalid_code_gracefully`

---

Notes
- Where language grammars may not be installed (Java, Ruby, etc.), use guards like:
  - `manager = LanguageGrammarManager();
    if not manager.is_language_supported(SupportedLanguage.RUBY): pytest.skip("Ruby grammar not available")`
- Prefer small inline code samples and temporary files (via `tmp_path` or `tempfile.TemporaryDirectory`) to keep tests fast and hermetic.
- Reuse existing `tests/test_tree_sitter_analysis.py` classes or create new focused test modules (e.g., `tests/test_analysis_queries.py`, `tests/test_callgraph_helpers.py`) for clarity.
