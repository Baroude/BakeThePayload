import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field


class ChangeType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class SecurityPatternType(str, Enum):
    AUTH_BYPASS = "auth_bypass"
    INPUT_VALIDATION = "input_validation"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    DESERIALIZATION = "deserialization"
    BUFFER_OVERFLOW = "buffer_overflow"
    CRYPTO_WEAKNESS = "crypto_weakness"
    TOCTOU = "toctou"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_DISCLOSURE = "information_disclosure"


@dataclass
class SecurityPattern:
    pattern_type: SecurityPatternType
    regex: str
    description: str
    confidence: float
    context_required: bool = False


class DiffHunk(BaseModel):
    file_path: str = Field(..., description="Path to the file being modified")
    old_start: int = Field(..., description="Starting line number in old file")
    old_count: int = Field(..., description="Number of lines in old file")
    new_start: int = Field(..., description="Starting line number in new file")
    new_count: int = Field(..., description="Number of lines in new file")
    context_lines: List[str] = Field(
        default_factory=list, description="Unchanged context lines"
    )
    removed_lines: List[Tuple[int, str]] = Field(
        default_factory=list, description="Removed lines with line numbers"
    )
    added_lines: List[Tuple[int, str]] = Field(
        default_factory=list, description="Added lines with line numbers"
    )
    function_context: Optional[str] = Field(
        default=None, description="Function or method context"
    )


class SecurityMatch(BaseModel):
    pattern_type: SecurityPatternType
    line_number: int
    line_content: str
    confidence: float
    description: str
    file_path: str
    context: Optional[str] = Field(default=None)


class UnifiedDiffParser:
    """
    Parser for unified diff format that extracts security-relevant changes
    """

    def __init__(self) -> None:
        self.security_patterns = self._initialize_security_patterns()

    def _initialize_security_patterns(self) -> List[SecurityPattern]:
        """Initialize comprehensive multi-language security pattern library"""
        return [
            # === AUTHENTICATION & AUTHORIZATION PATTERNS ===
            # Authentication bypass patterns
            SecurityPattern(
                SecurityPatternType.AUTH_BYPASS,
                r"(-\s*)(if|return|throw).*auth|login|authenticate|verify",
                "Removed authentication check",
                0.8,
                context_required=True,
            ),
            SecurityPattern(
                SecurityPatternType.AUTH_BYPASS,
                r"(-\s*).*\.hasPermission|\.checkAuth|\.requireAuth",
                "Removed authorization check",
                0.9,
            ),
            SecurityPattern(
                SecurityPatternType.AUTH_BYPASS,
                r"(-\s*).*(assert|require|check).*(auth|permission|role)",
                "Removed authorization assertion",
                0.8,
            ),
            
            # === INPUT VALIDATION PATTERNS ===
            # Generic validation patterns
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(-\s*)(validate|sanitize|escape|clean).*\(",
                "Removed input validation",
                0.7,
            ),
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(-\s*).*instanceof.*check",
                "Removed type validation",
                0.6,
            ),
            # Character/Unicode validation patterns (JavaScript, Python, Java)
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(\+\s*).*(charCode|codePoint|ord).*>\s*\d+",
                "Added character code validation",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(-\s*).*(charCode|codePoint|ord).*>\s*\d+",
                "Removed character code validation",
                0.9,
            ),
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(\+\s*).*if.*\.length\s*[><=]",
                "Added length validation",
                0.7,
            ),
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(-\s*).*if.*\.length\s*[><=]",
                "Removed length validation",
                0.8,
            ),
            # Type checking patterns
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(\+\s*).*(isinstance|typeof|Type\.|is_a\?)",
                "Added type checking",
                0.6,
            ),
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(-\s*).*(isinstance|typeof|Type\.|is_a\?)",
                "Removed type checking",
                0.7,
            ),
            
            # === SQL INJECTION PATTERNS ===
            SecurityPattern(
                SecurityPatternType.SQL_INJECTION,
                r'(\+\s*).*\+.*["\'].*SELECT|INSERT|UPDATE|DELETE',
                "Added string concatenation in SQL",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.SQL_INJECTION,
                r"(-\s*).*prepare|bind|escape.*sql",
                "Removed SQL parameterization",
                0.9,
            ),
            SecurityPattern(
                SecurityPatternType.SQL_INJECTION,
                r"(\+\s*).*(query|execute).*\+.*user|input",
                "Added unsafe SQL construction",
                0.7,
            ),
            
            # === XSS PATTERNS ===
            SecurityPattern(
                SecurityPatternType.XSS,
                r"(-\s*).*escape|sanitize.*html",
                "Removed HTML escaping",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.XSS,
                r"(\+\s*).*innerHTML|outerHTML.*\+",
                "Added direct HTML injection",
                0.7,
            ),
            SecurityPattern(
                SecurityPatternType.XSS,
                r"(-\s*).*(encode|escape).*(html|xml|url)",
                "Removed encoding/escaping",
                0.8,
            ),
            
            # === DESERIALIZATION PATTERNS ===
            SecurityPattern(
                SecurityPatternType.DESERIALIZATION,
                r"(-\s*).*whitelist|allowlist.*deserial",
                "Removed deserialization whitelist",
                0.9,
            ),
            SecurityPattern(
                SecurityPatternType.DESERIALIZATION,
                r"(\+\s*).*pickle\.loads|json\.loads.*user",
                "Added unsafe deserialization",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.DESERIALIZATION,
                r"(\+\s*).*(eval|exec|Function).*\(",
                "Added code execution",
                0.9,
            ),
            
            # === BUFFER OVERFLOW PATTERNS ===
            SecurityPattern(
                SecurityPatternType.BUFFER_OVERFLOW,
                r"(-\s*).*bounds.*check|length.*check",
                "Removed bounds checking",
                0.7,
            ),
            SecurityPattern(
                SecurityPatternType.BUFFER_OVERFLOW,
                r"(\+\s*).*strcpy|strcat|sprintf",
                "Added unsafe string function",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.BUFFER_OVERFLOW,
                r"(-\s*).*(malloc|alloc).*size.*check",
                "Removed allocation size validation",
                0.8,
            ),
            
            # === CRYPTOGRAPHIC WEAKNESS PATTERNS ===
            SecurityPattern(
                SecurityPatternType.CRYPTO_WEAKNESS,
                r"(-\s*).*AES|RSA.*[0-9]{3,4}",
                "Weakened cryptographic strength",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.CRYPTO_WEAKNESS,
                r"(\+\s*).*MD5|SHA1(?!.*SHA256)",
                "Added weak hash function",
                0.9,
            ),
            SecurityPattern(
                SecurityPatternType.CRYPTO_WEAKNESS,
                r"(-\s*).*(verify|check).*(signature|hash|tag)",
                "Removed cryptographic verification",
                0.9,
            ),
            SecurityPattern(
                SecurityPatternType.CRYPTO_WEAKNESS,
                r"(\+\s*).*(verify|check).*(signature|hash|tag)",
                "Added cryptographic verification",
                0.8,
            ),
            
            # === TOCTOU PATTERNS ===
            SecurityPattern(
                SecurityPatternType.TOCTOU,
                r"(-\s*).*lock|mutex|atomic",
                "Removed concurrency protection",
                0.6,
                context_required=True,
            ),
            SecurityPattern(
                SecurityPatternType.TOCTOU,
                r"(\+\s*).*(synchronized|lock|mutex)",
                "Added concurrency protection",
                0.6,
            ),
            
            # === PRIVILEGE ESCALATION PATTERNS ===
            SecurityPattern(
                SecurityPatternType.PRIVILEGE_ESCALATION,
                r"(-\s*).*admin|root.*check",
                "Removed privilege check",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.PRIVILEGE_ESCALATION,
                r"(\+\s*).*setuid|seteuid|sudo",
                "Added privilege elevation",
                0.7,
            ),
            SecurityPattern(
                SecurityPatternType.PRIVILEGE_ESCALATION,
                r"(-\s*).*(isAdmin|hasRole|checkPermission)",
                "Removed permission check",
                0.8,
            ),
            
            # === INFORMATION DISCLOSURE PATTERNS ===
            SecurityPattern(
                SecurityPatternType.INFORMATION_DISCLOSURE,
                r"(\+\s*).*print|log|console.*password|secret|key",
                "Added sensitive information logging",
                0.9,
            ),
            SecurityPattern(
                SecurityPatternType.INFORMATION_DISCLOSURE,
                r"(-\s*).*redact|mask|hide.*sensitive",
                "Removed sensitive data protection",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.INFORMATION_DISCLOSURE,
                r"(\+\s*).*(error|exception).*stack.*trace",
                "Added verbose error information",
                0.6,
            ),
            
            # === MULTI-LANGUAGE ERROR HANDLING PATTERNS ===
            # JavaScript/TypeScript error handling
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(\+\s*).*throw\s+new\s+(Error|TypeError).*invalid|invalid.*char",
                "Added input validation error",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(-\s*).*throw\s+new\s+(Error|TypeError).*invalid|invalid.*char",
                "Removed input validation error",
                0.9,
            ),
            # Python error handling
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(\+\s*).*raise\s+(ValueError|TypeError).*invalid",
                "Added input validation error",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(-\s*).*raise\s+(ValueError|TypeError).*invalid",
                "Removed input validation error",
                0.9,
            ),
            # Java error handling
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(\+\s*).*throw\s+new\s+(IllegalArgument|Invalid).*Exception",
                "Added input validation error",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(-\s*).*throw\s+new\s+(IllegalArgument|Invalid).*Exception",
                "Removed input validation error",
                0.9,
            ),
            # Ruby error handling (existing patterns)
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(\+\s*).*raise.*unless.*size|length|valid",
                "Added validation check",
                0.8,
            ),
            SecurityPattern(
                SecurityPatternType.CRYPTO_WEAKNESS,
                r"(\+\s*).*raise.*unless.*tag\.(bytesize|length)",
                "Added authentication tag validation",
                0.9,
            ),
            SecurityPattern(
                SecurityPatternType.AUTH_BYPASS,
                r"(\+\s*).*raise.*unless.*(auth|valid|check)",
                "Added security check",
                0.7,
            ),
            
            # === LANGUAGE-SPECIFIC VULNERABILITY PATTERNS ===
            # JavaScript Unicode/Character validation (specific patterns)
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(\+\s*).*charCodeAt.*>\s*\d+",
                "Added character code validation",
                0.9,
            ),
            SecurityPattern(
                SecurityPatternType.INPUT_VALIDATION,
                r"(-\s*).*charCodeAt.*>\s*\d+",
                "Removed character code validation",
                0.9,
            ),
        ]

    def parse(self, diff_content: str) -> List[DiffHunk]:
        """Parse unified diff content into structured hunks"""
        hunks = []
        lines = diff_content.split("\n")
        i = 0

        current_file = None

        while i < len(lines):
            line = lines[i]

            # Parse git diff headers (extract file from git diff line if no --- +++ headers)
            if line.startswith("diff --git "):
                match = re.match(r"diff --git a/(.*) b/(.*)", line)
                if match:
                    current_file = match.group(2)  # Use the 'b/' version (after change)
                i += 1
                continue

            # Parse file headers
            if line.startswith("--- "):
                old_file = self._extract_filename(line)
                i += 1
                continue
            elif line.startswith("+++ "):
                new_file = self._extract_filename(line)
                current_file = new_file
                i += 1
                continue

            # Parse hunk headers
            if line.startswith("@@"):
                hunk_info = self._parse_hunk_header(line)
                if hunk_info and current_file:
                    hunk, lines_consumed = self._parse_hunk_content(
                        lines[i + 1 :], current_file, hunk_info
                    )
                    hunks.append(hunk)
                    i += lines_consumed + 1
                else:
                    i += 1
            else:
                i += 1

        return hunks

    def _extract_filename(self, line: str) -> str:
        """Extract filename from diff header line"""
        # Handle various diff formats
        if line.startswith("--- a/") or line.startswith("+++ b/"):
            return line[6:].split("\t")[0]
        elif line.startswith("--- ") or line.startswith("+++ "):
            filename = line[4:].split("\t")[0]
            if filename.startswith("a/") or filename.startswith("b/"):
                return filename[2:]
            return filename
        return line

    def _parse_hunk_header(
        self, line: str
    ) -> Optional[Tuple[int, int, int, int, Optional[str]]]:
        """Parse hunk header like @@ -10,7 +10,6 @@ function_context"""
        match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$", line)
        if match:
            old_start = int(match.group(1))
            old_count = int(match.group(2)) if match.group(2) else 1
            new_start = int(match.group(3))
            new_count = int(match.group(4)) if match.group(4) else 1
            context = match.group(5).strip() if match.group(5) else None
            return (old_start, old_count, new_start, new_count, context)
        return None

    def _parse_hunk_content(
        self,
        lines: List[str],
        file_path: str,
        hunk_info: Tuple[int, int, int, int, Optional[str]],
    ) -> Tuple[DiffHunk, int]:
        """Parse the content of a diff hunk"""
        old_start, old_count, new_start, new_count, context = hunk_info

        hunk = DiffHunk(
            file_path=file_path,
            old_start=old_start,
            old_count=old_count,
            new_start=new_start,
            new_count=new_count,
            function_context=context,
        )

        old_line_num = old_start
        new_line_num = new_start
        lines_consumed = 0

        for line in lines:
            if line.startswith("@@"):
                break
            elif line.startswith("---") or line.startswith("+++"):
                break
            elif line.startswith(" "):
                # Context line
                hunk.context_lines.append(line[1:])
                old_line_num += 1
                new_line_num += 1
            elif line.startswith("-"):
                # Removed line
                hunk.removed_lines.append((old_line_num, line[1:]))
                old_line_num += 1
            elif line.startswith("+"):
                # Added line
                hunk.added_lines.append((new_line_num, line[1:]))
                new_line_num += 1
            elif line.startswith("\\"):
                # "No newline at end of file" - ignore
                pass
            else:
                break

            lines_consumed += 1

        return hunk, lines_consumed

    def detect_security_patterns(self, hunks: List[DiffHunk]) -> List[SecurityMatch]:
        """Detect security-relevant patterns in diff hunks"""
        matches = []

        for hunk in hunks:
            # Check removed lines for security concerns
            for line_num, content in hunk.removed_lines:
                for pattern in self.security_patterns:
                    if pattern.regex.startswith("(-\\s*)"):
                        match = re.search(pattern.regex, f"- {content}")
                        if match:
                            context = (
                                self._build_context(hunk, line_num)
                                if pattern.context_required
                                else None
                            )
                            matches.append(
                                SecurityMatch(
                                    pattern_type=pattern.pattern_type,
                                    line_number=line_num,
                                    line_content=content,
                                    confidence=pattern.confidence,
                                    description=pattern.description,
                                    file_path=hunk.file_path,
                                    context=context,
                                )
                            )

            # Check added lines for security concerns
            for line_num, content in hunk.added_lines:
                for pattern in self.security_patterns:
                    if pattern.regex.startswith("(\\+\\s*)"):
                        match = re.search(pattern.regex, f"+ {content}")
                        if match:
                            context = (
                                self._build_context(hunk, line_num)
                                if pattern.context_required
                                else None
                            )
                            matches.append(
                                SecurityMatch(
                                    pattern_type=pattern.pattern_type,
                                    line_number=line_num,
                                    line_content=content,
                                    confidence=pattern.confidence,
                                    description=pattern.description,
                                    file_path=hunk.file_path,
                                    context=context,
                                )
                            )

        return matches

    def _build_context(self, hunk: DiffHunk, target_line: int) -> str:
        """Build context around a target line for better pattern matching"""
        context_lines = []

        # Add function context if available
        if hunk.function_context:
            context_lines.append(f"Function: {hunk.function_context}")

        # Add surrounding context lines
        context_lines.extend(hunk.context_lines[-3:])  # Last 3 context lines

        return "\n".join(context_lines)

    def parse_and_analyze(
        self, diff_content: str
    ) -> Dict[str, Union[List[DiffHunk], List[SecurityMatch], Dict[str, int]]]:
        """Parse diff and detect security patterns in one operation"""
        hunks = self.parse(diff_content)
        security_matches = self.detect_security_patterns(hunks)

        return {
            "hunks": hunks,
            "security_matches": security_matches,
            "summary": {
                "total_hunks": len(hunks),
                "files_modified": len(set(hunk.file_path for hunk in hunks)),
                "security_issues_found": len(security_matches),
                "high_confidence_issues": len(
                    [m for m in security_matches if m.confidence >= 0.8]
                ),
            },
        }
