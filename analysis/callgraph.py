# ABOUTME: Simplified call graph generation using Tree-sitter queries
# ABOUTME: Builds lightweight caller/callee relationships to depth 3 for vulnerability analysis

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from analysis.context import CodeContextExtractor, FunctionContext, SupportedLanguage
from analysis.grammar import LanguageGrammarManager, detect_language_from_content


@dataclass
class CallRelationship:
    """Represents a function call relationship"""

    caller_function: str
    caller_file: str
    callee_function: str
    callee_file: Optional[str]  # None if external/unknown
    call_line: int
    confidence: float


@dataclass
class CallGraphNode:
    """Node in the call graph representing a function"""

    function_name: str
    file_path: str
    start_line: int
    end_line: int
    calls_out: Set[str]  # Functions this function calls
    called_by: Set[str]  # Functions that call this function


@dataclass
class CallGraph:
    """Complete call graph for a repository or file set"""

    nodes: Dict[str, CallGraphNode]  # Key: "file:function"
    relationships: List[CallRelationship]
    depth: int
    confidence_score: float


class CallGraphBuilder:
    """
    Builds lightweight call graphs using Tree-sitter without heavy semantic analysis.
    Focuses on modified functions and their immediate call relationships.
    """

    def __init__(self) -> None:
        self.context_extractor = CodeContextExtractor()
        self.grammar_manager = LanguageGrammarManager()

    def build_call_graph(
        self,
        file_paths: List[str],
        target_functions: Optional[List[str]] = None,
        max_depth: int = 3,
    ) -> CallGraph:
        """
        Build call graph for specified files focusing on target functions.

        Args:
            file_paths: List of file paths to analyze
            target_functions: Function names to focus analysis on
            max_depth: Maximum call depth to traverse

        Returns:
            CallGraph with nodes and relationships
        """
        nodes = {}
        relationships = []
        processed_files: Set[str] = set()

        # Extract function contexts from all files
        function_contexts = self._extract_all_functions(file_paths)

        # Build nodes from function contexts
        for file_path, functions in function_contexts.items():
            for func in functions:
                node_key = f"{file_path}:{func.name}"

                node = CallGraphNode(
                    function_name=func.name,
                    file_path=file_path,
                    start_line=func.start_line,
                    end_line=func.end_line,
                    calls_out=set(func.calls_made),
                    called_by=set(),
                )
                nodes[node_key] = node

        # Build call relationships
        for file_path, functions in function_contexts.items():
            for func in functions:
                caller_key = f"{file_path}:{func.name}"

                # For each call this function makes
                for callee_name in func.calls_made:
                    # Try to find the callee in our analyzed functions
                    callee_file = self._find_function_file(
                        callee_name, function_contexts
                    )

                    relationship = CallRelationship(
                        caller_function=func.name,
                        caller_file=file_path,
                        callee_function=callee_name,
                        callee_file=callee_file,
                        call_line=func.start_line,  # Approximation
                        confidence=0.8 if callee_file else 0.3,
                    )
                    relationships.append(relationship)

                    # Update called_by relationships
                    if callee_file:
                        callee_key = f"{callee_file}:{callee_name}"
                        if callee_key in nodes:
                            nodes[callee_key].called_by.add(caller_key)

        # Calculate overall confidence
        confidence = self._calculate_graph_confidence(nodes, relationships)

        return CallGraph(
            nodes=nodes,
            relationships=relationships,
            depth=max_depth,
            confidence_score=confidence,
        )

    def _extract_all_functions(
        self, file_paths: List[str]
    ) -> Dict[str, List[FunctionContext]]:
        """Extract function contexts from all specified files"""
        function_contexts = {}

        for file_path in file_paths:
            try:
                if not os.path.exists(file_path):
                    continue

                # Read file content
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Extract context
                context = self.context_extractor.extract_context(file_path, content)

                # Combine primary and related functions
                all_functions = context.primary_functions + context.related_functions

                # Update file path in contexts
                for func in all_functions:
                    func.file_path = file_path

                function_contexts[file_path] = all_functions

            except Exception as e:
                print(f"Warning: Failed to extract functions from {file_path}: {e}")
                function_contexts[file_path] = []

        return function_contexts

    def _find_function_file(
        self, function_name: str, function_contexts: Dict[str, List[FunctionContext]]
    ) -> Optional[str]:
        """Find which file contains a function with the given name"""
        for file_path, functions in function_contexts.items():
            for func in functions:
                if func.name == function_name:
                    return file_path
        return None

    def _calculate_graph_confidence(
        self, nodes: Dict[str, CallGraphNode], relationships: List[CallRelationship]
    ) -> float:
        """Calculate confidence score for the call graph"""
        if not nodes:
            return 0.0

        # Base confidence from successful function extraction
        base_confidence = 0.6

        # Boost for resolved relationships
        total_calls = len(relationships)
        if total_calls > 0:
            resolved_calls = sum(
                1 for rel in relationships if rel.callee_file is not None
            )
            resolution_rate = resolved_calls / total_calls
            base_confidence += 0.3 * resolution_rate

        # Boost for high-confidence relationships
        if total_calls > 0:
            high_confidence_calls = sum(
                1 for rel in relationships if rel.confidence > 0.7
            )
            confidence_rate = high_confidence_calls / total_calls
            base_confidence += 0.1 * confidence_rate

        return min(base_confidence, 1.0)

    def get_function_callers(
        self, graph: CallGraph, function_name: str, file_path: str
    ) -> List[CallGraphNode]:
        """Get all functions that call the specified function"""
        target_key = f"{file_path}:{function_name}"
        target_node = graph.nodes.get(target_key)

        if not target_node:
            return []

        callers = []
        for caller_key in target_node.called_by:
            if caller_key in graph.nodes:
                callers.append(graph.nodes[caller_key])

        return callers

    def get_function_callees(
        self, graph: CallGraph, function_name: str, file_path: str
    ) -> List[CallGraphNode]:
        """Get all functions called by the specified function"""
        target_key = f"{file_path}:{function_name}"
        target_node = graph.nodes.get(target_key)

        if not target_node:
            return []

        callees = []
        for callee_name in target_node.calls_out:
            # Find the callee node
            for node_key, node in graph.nodes.items():
                if node.function_name == callee_name:
                    callees.append(node)
                    break

        return callees

    def find_call_paths(
        self,
        graph: CallGraph,
        start_function: str,
        start_file: str,
        target_function: str,
        max_depth: int = 3,
    ) -> List[List[str]]:
        """
        Find call paths from start function to target function.
        Returns list of paths, where each path is a list of function keys.
        """
        start_key = f"{start_file}:{start_function}"
        if start_key not in graph.nodes:
            return []

        paths = []
        visited = set()

        def dfs_path_search(
            current_key: str, target: str, path: List[str], depth: int
        ) -> None:
            if depth > max_depth:
                return

            if current_key in visited:
                return

            visited.add(current_key)
            path.append(current_key)

            current_node = graph.nodes.get(current_key)
            if not current_node:
                path.pop()
                visited.remove(current_key)
                return

            # Check if we found the target
            if current_node.function_name == target:
                paths.append(path.copy())
                path.pop()
                visited.remove(current_key)
                return

            # Explore callees
            for callee_name in current_node.calls_out:
                for node_key, node in graph.nodes.items():
                    if node.function_name == callee_name:
                        dfs_path_search(node_key, target, path, depth + 1)
                        break

            path.pop()
            visited.remove(current_key)

        dfs_path_search(start_key, target_function, [], 0)
        return paths

    def get_graph_statistics(self, graph: CallGraph) -> Dict[str, Any]:
        """Get statistics about the call graph"""
        total_nodes = len(graph.nodes)
        total_relationships = len(graph.relationships)

        # Count internal vs external calls
        internal_calls = sum(
            1 for rel in graph.relationships if rel.callee_file is not None
        )
        external_calls = total_relationships - internal_calls

        # Find nodes with most connections
        max_calls_out = max(
            (len(node.calls_out) for node in graph.nodes.values()), default=0
        )
        max_called_by = max(
            (len(node.called_by) for node in graph.nodes.values()), default=0
        )

        return {
            "total_functions": total_nodes,
            "total_relationships": total_relationships,
            "internal_calls": internal_calls,
            "external_calls": external_calls,
            "resolution_rate": internal_calls / total_relationships
            if total_relationships > 0
            else 0,
            "max_outbound_calls": max_calls_out,
            "max_inbound_calls": max_called_by,
            "confidence_score": graph.confidence_score,
        }
