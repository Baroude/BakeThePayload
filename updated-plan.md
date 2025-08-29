# Vulnerability Analysis & Exploit Generation Agent System
## Architecture & Implementation Plan (Updated)

## 1. Architecture Overview
```ascii
┌─────────────────────────────────────────────────────────────────────────────┐
│                           INPUT LAYER                                        │
├─────────────────┬──────────────────┬────────────────────────────────────────┤
│  GitHub APIs    │  Advisory DBs    │        File System                     │
│  - Commits      │  - GHSA          │        - Local patches                │
│  - Releases     │  - NVD           │        - Cached data                  │
│  - Diffs        │  - OSV           │        - Previous analyses            │
│  - **Repos**    │                  │                                        │
└────────┬────────┴────────┬─────────┴────────┬───────────────────────────────┘
         │                 │                  │
         ▼                 ▼                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      NORMALIZATION LAYER (Collector Agent)                   │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐   │
│ │ Diff Parser  │ │Advisory Parse│ │Version Extract│ │**Repo Manager**  │   │
│ │(unified fmt) │ │(JSON→Pydantic│ │ (semver)     │ │- Sparse checkout │   │
│ └──────────────┘ └──────────────┘ └──────────────┘ │- File extraction │   │
│                                                      │- Cleanup policy  │   │
│                                                      └──────────────────┘   │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TYPED SECURITY MODEL (Pydantic)                      │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ Core Models:                                                        │    │
│  │ • VulnerabilityReport(id, severity, description, references...)     │    │
│  │ • AffectedArtifact(name, versions, file_paths...)                   │    │
│  │ • **CodeContext(full_function_body, call_sites, data_flows)**      │    │
│  │ • ExploitFlow(nodes: List[ExploitNode], edges: List[FlowEdge])      │    │
│  │ • Impact(confidentiality, integrity, availability, scope)           │    │
│  │ • Trace(advisory_id, commit_hash, file_path, line_spans)            │    │
│  │ • RiskAssessment(cvss_score, confidence, factors, reasoning)        │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 **ANALYSIS ENGINE (Analyst Agent) - UPDATED**                │
│ ┌───────────────────────────────────────────────────────────────────────┐ │
│ │ **Code Analysis Toolkit:**      │ **Outputs:**                        │ │
│ │ • Tree-sitter Parser (Primary)  │ • Full function extraction          │ │
│ │   - AST generation               │ • Call graph generation             │ │
│ │   - Symbol resolution            │ • Data-flow paths                   │ │
│ │   - Query-based extraction      │ • Usage context                     │ │
│ │ • CodeQL (Optional/Heavy)       │ • Vulnerability patterns            │ │
│ │   - Semantic analysis            │ • Confidence scoring                │ │
│ │   - Taint tracking               │                                     │ │
│ └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      VALIDATION LAYER (Reviewer Agent)                       │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ • Schema validation        • Contradiction detection                  │  │
│  │ • Reference integrity      • Severity consistency check               │  │
│  │ • Evidence verification    • Gap analysis & flagging                  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    **GENERATION LAYER (UPDATED)**                            │
├──────────────────────────────┬───────────────────────────────────────────────┤
│     Developer1 Agent         │       **Developer2 Agent + Tester Loop**      │
│  (Vulnerable App Generator)  │         (Iterative Exploit Generator)         │
│  • Framework selection        │  ┌─────────────────────────────────┐         │
│  • Vulnerable code synthesis  │  │ 1. Initial exploit generation  │         │
│  • Environment setup          │  │ 2. Automated testing           │         │
│  • Containerization           │  │ 3. Error analysis              │◄────┐    │
│                              │  │ 4. Refinement/retry            │     │    │
│                              │  │ 5. Human feedback (optional)   │     │    │
│                              │  └─────────────────────────────────┘     │    │
│                              │           │                              │    │
│                              │           ▼                              │    │
│                              │  ┌─────────────────────────────────┐     │    │
│                              │  │   Exploit Tester Component      │     │    │
│                              │  │   • Execute against vuln app    │     │    │
│                              │  │   • Capture success/failure     │─────┘    │
│                              │  │   • Extract error messages      │          │
│                              │  │   • Verify exploitation impact   │          │
│                              │  └─────────────────────────────────┘          │
└──────────────────────────────┴───────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OUTPUT ARTIFACTS                                   │
│  • Vulnerable application (containerized)                                    │
│  • Working exploit script with documentation                                 │
│  • Test harness & validation suite                                          │
│  • Security report with confidence metrics                                   │
│  • Iteration logs and refinement history                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```
## 2. Updated Data Flow Architecture

```ascii
[Input Sources] → [Cache Check] → [Parse & Normalize] → [Clone Repo (Sparse)] →
                       ↓                                      ↓
                  [Cache Store]                    [Extract Context Files]
                       ↑                                      ↓
[Typed Models] ← [Transform] ← [Validate] ← [Tree-sitter Analysis]
       ↓
[Analysis Pipeline] → [Function Extraction] → [Call Graph] → [Risk Score]
       ↓                                                         ↓
[Review & Validate] ← [Contradiction Check] ← [Evidence Verification]
       ↓
[Generation Split] → [Vuln App Branch] → [Container Build] → [Deploy]
       ↓                     ↓
[Exploit Branch] → [Initial Generation] → [Test Loop] → [Refinement] → [Success]
                            ↑                                 │
                            └─────────[Failure Analysis]◄────┘
```

## 3. Code Analysis Strategy (Tree-sitter + Optional CodeQL)

### 3.1 Tree-sitter as Primary Tool
**Advantages:**
- Supports 40+ languages out of the box
- Lightweight - no database build required
- Fast parsing (milliseconds for most files)
- Query language for pattern matching
- Direct AST access for context extraction

**Implementation approach:**
The CodeContextExtractor will use Tree-sitter to parse source files and extract vulnerable function bodies, identify call sites, and gather modification context. The system will:
1. Parse files using language-specific Tree-sitter grammars
2. Query for function definitions using Tree-sitter's query language
3. Extract full function bodies from the AST
4. Locate all call sites to vulnerable functions
5. Capture surrounding context (10 lines around modifications)
6. Return structured data including function bodies, call locations, and data flow hints

### 3.2 Simplified Call Graph Generation
**Approach:** Use Tree-sitter queries combined with symbol resolution to build lightweight call graphs without requiring full semantic analysis.

The CallGraphBuilder will:
- Find direct callers through pattern matching with Tree-sitter
- Extract called functions by parsing function bodies
- Implement limited depth traversal (max depth 3) to avoid explosion
- Return structured call graph data including callers, callees, traversal depth, and truncation status

### 3.3 CodeQL as Optional Enhancement
**When to use CodeQL:**
- Complex taint analysis needed
- Security-critical applications
- When Tree-sitter analysis has low confidence
- Specific language with excellent CodeQL support (Java, C++, JavaScript)

**Lightweight CodeQL usage strategy:**
The OptionalCodeQLAnalyzer will selectively apply CodeQL only when necessary, based on vulnerability type, language support, and confidence scores. It will:
- Determine when CodeQL analysis adds value (e.g., SQL injection, taint flow, XSS vulnerabilities)
- Run targeted pre-built queries rather than full database scans
- Leverage existing CodeQL packs when available
- Cache results aggressively to minimize performance impact

### 3.4 Repository Management Strategy

**Sparse Checkout & Cleanup:**
The RepositoryManager implements minimal disk footprint management through:
- Sparse checkout initialization for selective file retrieval
- Shallow clone with limited commit history
- Checkout of only affected files and their dependencies
- Temporary directory usage with automatic cleanup
- Extract-and-dispose pattern where repositories are cloned, analyzed, and immediately removed
- No long-term storage of cloned repositories

## 4. Iterative POC Development System

### 4.1 Exploit Development Loop Architecture

The IterativeExploitDeveloper manages the iterative refinement process for exploit generation with the following characteristics:

**Core Loop Components:**
- Maximum of 5 iterations (configurable)
- Cost budget of $10 per vulnerability
- Token budget of 50,000 tokens
- Optional human feedback integration

**Iteration Process:**
1. **Initial Generation**: Create first exploit attempt based on vulnerability analysis
2. **Automated Testing**: Execute exploit against vulnerable application in sandbox
3. **Success Evaluation**: Check if exploitation criteria are met
4. **Failure Analysis**: If unsuccessful, analyze errors and output
5. **Refinement Strategy**: Apply targeted improvements based on failure type
6. **Human Feedback** (Optional): Request guidance every 2 iterations
7. **Resource Check**: Verify cost/token/time limits before continuing

**Exit Conditions:**
- Successful exploitation achieved
- Maximum iterations reached
- Resource limits exceeded (cost, tokens, or time)
- Human intervention requests stop
- Consistent failure pattern detected

### 4.2 Exploit Testing Component

The ExploitTester provides automated testing with sandboxed execution:

**Testing Infrastructure:**
- Docker-based isolation for safe execution
- 30-second timeout per test attempt
- Comprehensive output capture (stdout, stderr, network traffic)
- Impact verification based on vulnerability type

**Success Criteria by Vulnerability Type:**
- **RCE**: Command execution verified through output or side effects
- **SQL Injection**: Data extraction or database modification confirmed
- **XSS**: Script execution detected in rendered output
- **File Disclosure**: Sensitive file contents retrieved
- **Auth Bypass**: Unauthorized access to protected resources achieved
- **Privilege Escalation**: Higher privilege operations successful

**Test Result Data:**
- Exploitation success status
- Captured output and errors
- Impact type and evidence
- Performance metrics
- Failure points for refinement

### 4.3 Refinement Strategies

The ExploitRefiner implements targeted improvement strategies based on failure analysis:

**Failure Categories and Strategies:**
- **Syntax Errors**: Fix code syntax and formatting issues
- **Connection Failures**: Adjust network parameters, endpoints, protocols
- **Payload Blocked**: Implement filter evasion techniques
- **Partial Success**: Enhance impact and complete exploitation chain
- **Timing Issues**: Adjust delays, synchronization, race conditions
- **Encoding Errors**: Fix character encoding and data format issues
- **Authentication Required**: Add credential handling or bypass techniques
- **Generic Failures**: Apply broad refinement heuristics

**Refinement Approach:**
- Analyze specific error messages and failure points
- Apply targeted fixes rather than complete regeneration
- Preserve working components from previous attempts
- Incrementally improve exploit reliability
- Track what has been tried to avoid repetition

### 4.4 Human-in-the-Loop Integration

The HumanFeedbackInterface enables optional expert guidance:

**Feedback Request Context:**
- Current exploit code and approach
- Error summary and failure analysis
- Iteration count and resource usage
- Success metrics and partial achievements

**Human Actions Available:**
1. Continue automated refinement
2. Provide hints or guidance
3. Modify exploitation approach
4. Stop iterations
5. Escalate for manual review

**Integration Points:**
- Triggered every 2 iterations or on repeated failures
- Present clear summary of attempts and failures
- Accept structured guidance or code modifications
- Incorporate feedback into next iteration
- Log human interventions for analysis

## 5. AI Integration Strategy

### Core Principle: Hybrid Data Approach
The system uses a **hybrid approach** combining structured data for consistency with raw data for exploit context:

**For All AI Tasks:**
- **Primary**: Structured Pydantic models (validated, consistent, cacheable)
- **Essential**: Raw diff content + extracted function context from Tree-sitter
- **Fallback**: Raw advisory JSON (when parsing loses critical context)

### AI Context by Task Type

| Task Type | Structured Data | Raw Diff | Function Context | Raw Advisory | Token Est. | Model Size |
|-----------|----------------|----------|------------------|--------------|------------|------------|
| Classification | ✅ Required | ❌ Optional | ❌ Optional | ❌ Rare | <1K | Small |
| Vulnerability Analysis | ✅ Required | ✅ Required | ✅ Required | ⚠️ If confidence <0.7 | 3-5K | Medium |
| Exploit Flow Generation | ✅ Required | ✅ Required | ✅ Required | ⚠️ If needed | 5-7K | Medium |
| Code Generation | ✅ Required | ✅ Required | ✅ Required | ⚠️ If needed | 6-10K | Large |
| Exploit Development | ✅ Required | ✅ Required | ✅ Required | ✅ Often needed | 8-12K | Large |
| Exploit Refinement | ✅ Error logs | ✅ Previous attempt | ✅ Target context | ❌ Rarely | 4-6K | Medium |

### Context Optimization Rules
1. **Always provide structured data** for validation and consistency
2. **Always include raw diff** for exploit-related tasks
3. **Always include Tree-sitter extracted function context** for code understanding
4. **Include raw advisory** when confidence scores are low (<0.7)
5. **For refinement iterations**, focus on error analysis and specific failure points
6. **Cache intelligently** based on structured data fingerprints

### OpenRouter Model Selection by Agent

#### Collector Agent AI Models
| Task | Model | Context Size | Cost/1M Tokens | Rationale |
|------|-------|-------------|----------------|-----------|
| Format Detection | DeepSeek R1 0528 | <2K tokens | FREE | Cost-effective reasoning |
| Source Classification | DeepSeek v3.1 | <3K tokens | $0.20/$0.80 | Ultra-cheap classification |
| Data Validation | Gemini 2.0 Flash Exp | <2K tokens | FREE | Backup free option |

#### Analyst Agent AI Models
| Task | Model | Context Size | Cost/1M Tokens | Rationale |
|------|-------|-------------|----------------|-----------|
| Pattern Recognition | DeepSeek R1 0528 | 4-6K tokens | FREE | Strong reasoning with function context |
| Exploit Flow Analysis | DeepSeek R1 0528 | 6-10K tokens | FREE | Complex reasoning with call graphs |
| Risk Assessment | Claude 4 Sonnet | 4-8K tokens | Premium | High-quality severity evaluation |
| Code Context Analysis | DeepSeek v3.1 | 3-5K tokens | $0.20/$0.80 | Cost-effective Tree-sitter output processing |

#### Developer2 Agent AI Models (Iterative POC)
| Task | Model | Context Size | Cost/1M Tokens | Rationale |
|------|-------|-------------|----------------|-----------|
| Initial Exploit Generation | Claude 4 Sonnet | 8-12K tokens | Premium | High-quality first attempt |
| Error Analysis | DeepSeek R1 0528 | 3-5K tokens | FREE | Good reasoning for failures |
| Refinement Generation | DeepSeek v3.1 | 4-6K tokens | $0.20/$0.80 | Cost-effective iterations |
| Final Polish | Claude 4 Sonnet | 6-8K tokens | Premium | Quality final version |

### Iteration Loop Cost Management
- **First attempt**: Premium model (Claude 4 Sonnet) for best initial quality
- **Iterations 2-3**: Mid-tier models (DeepSeek v3.1) for refinements
- **Iterations 4-5**: FREE models unless critical issues
- **Human feedback**: Triggers premium model for next iteration

## 6. Detailed Implementation Timeline

### Phase 1: Foundation (Week 1-2) ✅ COMPLETED
- ✅ Day 1: Development environment setup (UV, project init, dependencies)
- ✅ Days 1-3: Core Pydantic models (12 models with full validation)
- ✅ Days 4-5: Input parsers (diff, advisory, version extractors)
- ✅ Week 2, Days 1-3: Model validation tests (33 comprehensive tests)
- ✅ Week 2, Days 4-5: Parser integration tests and performance benchmarks
- ✅ Infrastructure: README, pyproject.toml, pre-commit hooks, Makefile

### Phase 2: Agent Implementation (Week 3-5)

#### Week 3: Collector Agent & Repository Management
- Days 1-2: AsyncHTTPClient with retry logic and rate limiting
- Day 3: Multi-source data collection (GitHub, GHSA, OSV, NVD)
- Day 4: Repository manager with sparse checkout implementation
- Day 5: AI response caching system (memory + disk layers)

#### Week 4: Enhanced Analyst Agent with Tree-sitter
- Day 1: Tree-sitter integration for 10+ languages
- Day 2: Function extraction and context building
- Day 3: Simplified call graph generation
- Day 4: Optional CodeQL integration points
- Day 5: Confidence scoring system with Tree-sitter context

#### Week 5: Reviewer Agent & Iterative Developer
- Days 1-2: Reviewer agent validation framework
- Day 3: Exploit generation loop implementation
- Day 4: Sandboxed testing environment (Docker)
- Day 5: Failure analysis and refinement strategies

### Phase 3: Integration & Testing (Week 6-7)

#### Week 6: Full Pipeline Integration
- Days 1-2: Agent orchestration and handoffs
- Day 3: End-to-end testing with real vulnerabilities
- Day 4: Performance optimization and caching
- Day 5: Human feedback interface implementation

#### Week 7: Production Hardening
- Days 1-2: Error handling and recovery mechanisms
- Day 3: Monitoring and metrics implementation
- Day 4: Documentation and deployment guides
- Day 5: Security audit and penetration testing

### Phase 4: Deployment & Operations (Week 8)
- Day 1: Production environment setup
- Day 2: CI/CD pipeline configuration
- Day 3: Monitoring dashboards and alerts
- Day 4: Initial production deployment
- Day 5: Post-deployment validation and tuning

## 7. Key Constraints & Considerations

### 7.1 Technical Constraints

**Input Quality Issues:**
- **Ambiguous Advisories**: Many advisories lack technical detail
  - *Mitigation*: Use Tree-sitter to extract actual code context, cross-reference sources
- **Incomplete Patches**: Some fixes span multiple commits
  - *Mitigation*: Track related commits, use call graph to find dependencies
- **Version Inconsistencies**: Different versioning schemes across ecosystems
  - *Mitigation*: Maintain version parser per ecosystem, fallback heuristics

**Scale Limitations:**
- **Large Repositories**: Some repos are massive (GB+)
  - *Mitigation*: Sparse checkout, extract only needed files, immediate cleanup
- **Complex Call Graphs**: Enterprise codebases have deep call chains
  - *Mitigation*: Limit depth to 3, focus on direct relationships
- **API Rate Limits**: GitHub/NVD have strict limits
  - *Mitigation*: Aggressive caching, request batching, multiple API keys
- **LLM Context Windows**: Complex vulnerabilities may exceed limits
  - *Mitigation*: Smart context selection, prioritize Tree-sitter extracted functions

### 7.2 Security Constraints

**Exploit Safety:**
- Never generate destructive payloads
- Include kill switches in all exploits
- Sandbox all execution environments
- Log all generated artifacts for audit
- Limit network access in test environments

**Data Privacy:**
- Hash sensitive information
- Implement data retention policies (24hr for repos)
- Secure API key management (HashiCorp Vault)
- Encrypt cached data at rest
- No persistent storage of proprietary code

### 7.3 Operational Constraints

**Repository Management:**
- Max 10GB total repository cache
- Auto-cleanup after 1 hour
- Sparse checkout by default
- Extract-and-dispose pattern

**Iteration Loop Controls:**
- Hard stop at 5 iterations
- Cost limit at $10 per vulnerability
- Token budget of 50,000
- Timeout of 10 minutes total
- Human review option every 2 iterations

**Monitoring & Observability:**
```yaml
Metrics to Track:
  - Tree-sitter parse success rate
  - Context extraction completeness
  - Iteration convergence rate
  - Exploitation success by iteration
  - Repository cache hit ratio
  - API quota usage
  - Model costs per iteration
  - Human intervention frequency

Alerting Thresholds:
  - Parse success < 90%
  - Exploitation success < 60% after 3 iterations
  - Repository cache > 8GB
  - Cost per vuln > $7
  - Processing time > 5min
```

## 8. Key Implementation Considerations

### 6.1 Language Support Matrix

| Language | Tree-sitter | CodeQL | Priority |
|----------|------------|--------|----------|
| Python | ✅ Excellent | ✅ Good | High |
| JavaScript | ✅ Excellent | ✅ Excellent | High |
| Java | ✅ Good | ✅ Excellent | High |
| C/C++ | ✅ Good | ✅ Excellent | Medium |
| Go | ✅ Good | ✅ Good | Medium |
| Ruby | ✅ Good | ⚠️ Limited | Medium |
| PHP | ✅ Good | ⚠️ Limited | Low |
| Rust | ✅ Good | ⚠️ Beta | Low |

### 6.2 Storage & Performance Targets

**Disk Usage:**
- Repository cache: Max 10GB with LRU eviction
- Extracted contexts: Max 1GB cached
- Temporary files: Auto-cleanup after 1 hour

**Processing Times:**
- Tree-sitter parsing: <100ms per file
- Context extraction: <5s per vulnerability
- Call graph generation: <10s (depth 3)
- Full analysis: <30s without CodeQL, <2min with CodeQL

### 6.3 Iteration Loop Limits

**Resource Limits:**
- Max iterations: 5 (configurable)
- Max time per iteration: 2 minutes
- Max total time: 10 minutes
- Token budget: 50,000 tokens
- Cost budget: $10 per vulnerability

**Exit Conditions:**
- Successful exploitation achieved
- Resource limits exceeded
- Human intervention requested stop
- Consistent failure pattern detected (3x same error)

## 8. Key Implementation Considerations

### 8.1 Language Support Matrix

| Language | Tree-sitter | CodeQL | Priority |
|----------|------------|--------|----------|
| Python | ✅ Excellent | ✅ Good | High |
| JavaScript | ✅ Excellent | ✅ Excellent | High |
| Java | ✅ Good | ✅ Excellent | High |
| C/C++ | ✅ Good | ✅ Excellent | Medium |
| Go | ✅ Good | ✅ Good | Medium |
| Ruby | ✅ Good | ⚠️ Limited | Medium |
| PHP | ✅ Good | ⚠️ Limited | Low |
| Rust | ✅ Good | ⚠️ Beta | Low |

### 8.2 Storage & Performance Targets

**Disk Usage:**
- Repository cache: Max 10GB with LRU eviction
- Extracted contexts: Max 1GB cached
- Temporary files: Auto-cleanup after 1 hour

**Processing Times:**
- Tree-sitter parsing: <100ms per file
- Context extraction: <5s per vulnerability
- Call graph generation: <10s (depth 3)
- Full analysis: <30s without CodeQL, <2min with CodeQL

### 8.3 Iteration Loop Limits

**Resource Limits:**
- Max iterations: 5 (configurable)
- Max time per iteration: 2 minutes
- Max total time: 10 minutes
- Token budget: 50,000 tokens
- Cost budget: $10 per vulnerability

**Exit Conditions:**
- Successful exploitation achieved
- Resource limits exceeded
- Human intervention requested stop
- Consistent failure pattern detected (3x same error)

## 9. Success Metrics

### Core Pipeline Metrics
- **Accuracy**: 85%+ correct vulnerability identification
- **Completeness**: 90%+ of advisories processable
- **Context Quality**: 90%+ of modified functions fully extracted
- **Language Coverage**: Support for 8+ major languages
- **Performance**: <2min average processing time (excluding iterations)
- **Efficiency**: <$0.10 per analysis (pre-exploitation)
- **Reliability**: 99.5% uptime for core pipeline

### Tree-sitter/CodeQL Metrics
- **Parse Success Rate**: 95%+ for supported languages
- **Function Extraction**: 100% for identified vulnerable functions
- **Call Graph Completeness**: 80%+ of direct callers/callees found
- **Context Extraction Speed**: <5s for average-sized files
- **CodeQL Usage**: <10% of analyses require CodeQL

### Exploitation Success Metrics
- **Initial Success Rate**: 40%+ on first attempt
- **Convergence Rate**: 70%+ succeed within 3 iterations
- **Final Success Rate**: 85%+ within 5 iterations
- **Refinement Effectiveness**: Each iteration improves success by 20%+
- **Human Intervention**: <20% require human feedback
- **Cost Efficiency**: Average <$5 per successful exploit

### Resource Efficiency Metrics
- **Repository Cache Hit**: 60%+ for common repos
- **Storage Footprint**: <100MB per analyzed vulnerability
- **Cleanup Effectiveness**: 100% temp files removed within 1hr
- **API Rate Limit**: Stay under 80% of quotas
- **Token Usage**: Average <30K tokens per full analysis

This updated architecture leverages Tree-sitter for lightweight, broad language support while maintaining CodeQL as an optional enhancement for complex cases. The iterative POC development system ensures higher success rates through systematic refinement, automated testing, and optional human guidance. The focus on minimal resource usage and smart context extraction makes the system both efficient and scalable.
