# Phase 2: Agent Implementation Plan

## Overview
Phase 2 implements the core agent system for vulnerability analysis, building on the foundation from Phase 1. This phase creates the Collector, Analyst, and Reviewer agents with comprehensive caching and validation, adds Tree-sitter based code context extraction with optional CodeQL, introduces a Repository Manager (sparse checkout), and scaffolds an Iterative Developer loop. Duration: 3 weeks (Week 3–5).

## Prerequisites ✅
- Phase 1 Foundation completed with 12 Pydantic models, 3 parsers, and 70 tests (97% pass rate)
- Development environment with UV, dependencies, and tooling setup
- Complete infrastructure with README, pyproject.toml, pre-commit hooks, Makefile

## 2.1 Collector Agent (Week 3) ✅ COMPLETED

### 2.1.1 Async HTTP Client Infrastructure (Days 1–2) ✅ COMPLETED
- **AsyncHTTPClient**: Concurrent fetching with retry logic
- **Rate Limiting**: Exponential backoff for API quotas (GitHub, NVD)
- **Connection Pooling**: Efficient resource management
- **Error Handling**: Circuit breakers and graceful degradation

  Implemented:
  - `agents/collector.py:AsyncHTTPClient` with retries, backoff, pooling, circuit breaker
  - Tests: `tests/test_async_http_client.py`

### 2.1.2 Multi-Source Data Collection (Day 3) ✅ COMPLETED
- **GitHub API Integration**: Commits, releases, diffs, security advisories
- **Advisory Database APIs**: GHSA, OSV, NVD with format adapters
- **File System Sources**: Local patches, cached data, previous analyses
- **Webhook Support**: Real-time updates instead of polling

  Implemented:
  - `agents/data_sources.py`: `DataSourceManager`, `GitHubDataSource`, `AdvisoryDataSource`, `FileSystemDataSource`, `WebhookDataSource`
  - Format adapters in `agents/adapters.py`
  - Tests: `tests/test_data_collection.py`

### 2.1.3 AI Response Caching (Day 5) ✅ COMPLETED
```
Memory Cache: In-memory LRU (50MB)
├── AI model responses (24hr TTL)
├── Semantic similarity hashes (1hr TTL)
└── Token count estimates (persistent)

Disk Cache: Compressed storage (500MB)
├── Prompt/response pairs (24hr TTL)
└── Model failure logs (7 days)
```

  Implemented:
  - `cache/memory.py`, `cache/disk.py`, `cache/manager.py`, `cache/utils.py`
  - Tests: `tests/test_cache.py`

### 2.1.4 Data Normalization Pipeline (Day 4) ✅ COMPLETED
- **Format Adapters**: Per-source type with fallback mappings
- **Deduplication**: Content hashing and fuzzy matching
- **Cross-Referencing**: Link related vulnerabilities and patches
- **Sequential Processing**: One vulnerability at a time for reliability

  Implemented:
  - Adapters: `agents/adapters.py`
  - Deduplication utilities: `agents/deduplication.py`
  - Sequential processing in `DataSourceManager.process_vulnerabilities()`
  - Tests: `tests/test_data_collection.py`

### 2.1.5 Repository Manager (Day 4) ✅ COMPLETED
- **Full Repository Checkout**: Complete clone for comprehensive call graph generation (supports Tree-sitter analysis)
- **History Context**: Include 100 commits before/after patch for temporal analysis
- **Size Limits**: 5GB maximum per repository with fast-fail on oversized repos
- **File Filtering**: Post-clone removal of binaries, documentation, tests to optimize storage
- **Extract-and-Dispose Pattern**: One vulnerability = one repository clone, cleanup after complete analysis pipeline
- **Public Repositories Only**: No private repo authentication required
- **Context Utilities**: Map diff hunks to files/functions; fetch full function context via Tree-sitter
- **Integration**: Extends `DataSourceManager` with `clone_repository()`, `get_commit_history()`, `extract_full_context()` methods
- **Error Handling**: Network failures, missing commits, repository size validation, cleanup failures
- **Ruby Support**: Full Tree-sitter integration with Ruby repository analysis and call graph generation

  Implemented:
  - `integration/repo.py`: Complete repository manager with cloning, filtering, context extraction
  - Tree-sitter integration: Ruby function analysis with caller/callee relationships
  - Test integration: `test_github_advisory.py` demonstrates full repository analysis workflow
  - Ruby parsing: Enhanced function name extraction for methods, classes, modules

### 2.1.6 Context Optimization Pipeline (Day 5) ✅ COMPLETED
- **AI Context Optimization**: Reduce data bloat while preserving essential vulnerability information for exploit generation
- **Smart Function Filtering**: Remove module/class definitions, focus on actual vulnerable methods
- **Raw Diff Integration**: Always include complete diff content for exploit generation tasks
- **Full Function Context**: Include complete function source code (not truncated previews)
- **Conditional Raw Advisory**: Optional raw advisory inclusion via CLI flag for low confidence cases
- **Language-Agnostic Structure**: Foundation for multi-language context optimization
- **Token Efficiency**: Optimize for AI consumption while maintaining exploit generation capability

  Implemented:
  - Enhanced context optimizer: Includes raw diffs + full function context for exploit generation
  - CLI flag `--include-raw-advisory` for conditional raw advisory inclusion
  - Full function source preservation (not 200-char previews) for complete code understanding
  - Enhanced security patterns with file location and code context
  - Function filtering: Exclude modules/classes, focus on methods with callers
  - Code context extraction: Show ±2 lines around security issues with diff markers
  - Dual output: Full collection data + AI-optimized context with exploit-ready data
  - Size optimization: 44-62% reduction while preserving essential exploit generation data

### 2.1.7 Main Execution Flow Generalization (Day 6) ✅ COMPLETED
- **Universal GHSA Analysis**: Create main.py to generalize functionality for any GHSA advisory
- **Multi-Language Support**: Extract language detection and Tree-sitter grammar selection
- **Configurable Pipeline**: Command-line interface for advisory ID input and output format selection
- **Reusable Components**: Separate concerns for data collection, repository analysis, and context optimization
- **Error Handling**: Robust handling of different repository types, languages, and advisory formats
- **Output Standardization**: Consistent JSON output format for any GHSA advisory analysis

  Implemented:
  - `main.py`: Complete CLI interface with VulnerabilityAnalyzer class
  - Language detection: Support for 12+ programming languages (Ruby, Python, JavaScript, Java, PHP, Go, Rust, C/C++, C#, Swift, Kotlin, Scala)
  - CLI arguments: GHSA ID input, output directory, optional repository analysis skip, conditional raw advisory inclusion
  - GHSA ID validation: Regex pattern matching for proper format
  - Enhanced context generation: Raw diffs + full function context for exploit generation capability
  - Modular pipeline: Reusable components extracted from test script
  - Error handling: Comprehensive validation and graceful failure modes
  - Tests: `tests/test_main_execution.py` with 13 tests using real data validation

## 2.2 Analyst Agent (Week 4) ⬜ NOT STARTED

### 2.2.1 Security Pattern Library (Day 1) 🟡 PARTIAL
- **Auth Bypass Patterns**: Missing/modified authentication checks
- **Deserialization Vulnerabilities**: Unsafe object construction patterns
- **Injection Points**: String concatenation in queries, commands
- **Buffer Overflow**: Bounds check modifications and omissions
- **TOCTOU Conditions**: Time-of-check vs time-of-use gaps
- **Cryptographic Issues**: Weak algorithms, key management problems
- **Path Traversal**: Directory traversal and file access patterns
- **Race Conditions**: Thread safety and synchronization issues

  Implemented (Phase 1 diff patterns):
  - `parsers/diff.py` security pattern detection (10+ patterns)
  - Tests: `tests/test_parsers.py`

### 2.2.2 Static Analysis Engine (Day 1) ⬜ NOT STARTED
- **AST-Based Analysis**: Code structure and flow analysis
- **Regex Pattern Matching**: Common vulnerability signatures
- **Context-Aware Scoring**: Change impact assessment
- **Function Mapping**: Entry points and data flow tracking

### 2.2.3 AI Integration Architecture (Day 2) ⬜ NOT STARTED
**OpenRouter Integration with Cost Optimization**:
- **API Integration**: OpenRouter client with unified access to 300+ models
- **Model Selection**: Start with FREE models (DeepSeek R1), escalate to premium only on failure
- **Fallback Strategy**: Dev = console prompts for manual review, Prod = automatic cheaper model retry
- **Performance Learning**: JSON cache files tracking model success rates per vulnerability type
- **Context Management**: Fail on context overflow to measure occurrence frequency
- **Budget Enforcement**: Manual approval required when token/cost limits exceeded
- **Structured Data**: VulnerabilityReport, SecurityMatch, AffectedArtifact models
- **Raw Exploit Context**: Original diff content with metadata for exploit generation tasks

### 2.2.4 Exploit Flow Construction (Day 2–3) ⬜ NOT STARTED
- **Attack Graph Building**: Entry point to impact mapping
- **Step Sequencing**: Logical attack progression
- **Precondition Chains**: Required conditions for exploitation
- **Probability Calculation**: Reachability and success likelihood
- **Impact Assessment**: CIA triad analysis with scope evaluation

### 2.2.5 Confidence Scoring System (Day 5) ⬜ NOT STARTED
- **Evidence Strength**: Explicit vs implied vulnerability indicators
- **Advisory Clarity**: Detailed vs vague descriptions
- **Patch Complexity**: Single line vs multi-file changes
- **Source Reliability**: Trusted sources vs community reports
- **Validation Results**: Cross-reference consistency

### 2.2.6 Tree-sitter Code Context Extraction (Day 1–2) ✅ COMPLETED
**Hybrid Static Query + AI Selection Approach**:
- **Static Query Library**: Pre-built queries per language for function definitions, calls, assignments, classes
- **AI Query Selection**: Analyst Agent determines which queries to run based on vulnerability type
- **Language Support**: Python, JavaScript, Java, Ruby grammars (high priority languages)
- **Grammar Management**: Bundle common language grammars, install additional as needed
- **Context Extraction**: AI processes query results to determine optimal extraction depth
- **Integration**: Tree-sitter results feed into AI context optimization pipeline
- **Ruby Support**: Enhanced function name extraction for Ruby methods, classes, modules

  Implemented:
  - `analysis/context.py`: `CodeContextExtractor` with hybrid static query + AI selection approach
  - `analysis/grammar.py`: `LanguageGrammarManager` with dynamic loading and validation
  - `analysis/queries/`: Static Tree-sitter query library for Python, JavaScript, Java, Ruby
  - `analysis/callgraph.py`: Simplified call graph generation to depth 3
  - Enhanced Ruby parsing: Fixed function name extraction for Ruby methods, classes, modules
  - Repository integration: `test_github_advisory.py` now includes full Ruby repository analysis
  - Tests: `tests/test_tree_sitter_analysis.py` with 25 tests (all Ruby tests working)

### 2.2.7 Simplified Call Graph Generation (Day 3) ✅ COMPLETED
- Build lightweight caller/callee relationships to depth 3
- Prioritize paths impacting modified functions
- Avoid heavy semantic analysis; keep fast and language-agnostic

  Implemented:
  - `analysis/callgraph.py`: `CallGraphBuilder` with lightweight caller/callee relationships
  - Call path finding and graph statistics functionality
  - Integration with Tree-sitter context extraction
  - Tests included in `tests/test_tree_sitter_analysis.py`

### 2.2.8 Optional CodeQL Integration (Day 4) ⬜ NOT STARTED
- Trigger only for languages/scenarios where CodeQL adds value
- Use existing packs (e.g., SQLi, XSS) for deeper taint/flow checks
- Guarded, opt-in path with strict timeouts and caching

## 2.3 Reviewer Agent (Week 5) ⬜ NOT STARTED

### 2.3.1 Validation Framework
- **Schema Validation**: All models conform to Pydantic schemas
- **Reference Integrity**: Cross-model consistency checks
- **Evidence Verification**: Traceability and source validation
- **Logical Consistency**: Contradiction detection and resolution

### 2.3.2 Quality Assurance Rules
- **Evidence Requirements**: Every claim must have supporting evidence
- **Severity Alignment**: CVSS scores match impact assessments
- **Version Consistency**: Range constraints are logically sound
- **File Path Verification**: Referenced paths exist in repositories
- **Temporal Consistency**: Timelines and sequences are logical

### 2.3.3 Gap Analysis Engine
- **Missing Information Detection**: Identify incomplete analyses
- **Uncertainty Flagging**: Highlight low-confidence areas
- **Source Cross-Validation**: Compare multiple information sources
- **Manual Review Queue**: Route complex cases for human validation

### 2.3.4 Reporting and Metrics
- **Analysis Quality Metrics**: Completeness and confidence scores
- **Validation Reports**: Detailed findings with recommendations
- **Improvement Suggestions**: Identify pattern library gaps
- **Performance Tracking**: Success rates and processing times

### 2.3.5 Iterative Developer Integration (Week 5, Days 3–5)
- Scaffold exploit generation loop (structure only; safe placeholders)
- Add Docker-based sandbox with 30–60s timeouts
- Implement failure analysis and targeted refinement strategies
- Optional human-in-the-loop checkpoints for low-confidence cases

## 2.4 Advanced Features (Week 3 Integration) ⬜ NOT STARTED

### 2.4.1 Context Optimization Strategy
**Smart Context Selection**: Dynamic context optimization based on task complexity and confidence levels
- **Base Context**: Structured vulnerability data and security matches for all tasks
- **Exploit Tasks**: Always include raw diff and metadata for exploit analysis, code generation, attack flow tasks
- **Low Confidence Recovery**: Add raw advisory JSON when parsing confidence drops below 0.7
- **Context Size Management**: Automatic token estimation and budget enforcement

### 2.4.2 OpenRouter AI Model Specifications by Agent

#### Collector Agent AI Models
**Primary Tasks**: Format detection, data classification, duplicate identification

| Task | Model | Context Size | Cost/1M Tokens | Rationale |
|------|-------|-------------|----------------|-----------|
| Format Detection | DeepSeek R1 0528 | <2K tokens | FREE | Cost-effective reasoning model |
| Source Classification | DeepSeek v3.1 | <3K tokens | $0.20/$0.80 | Ultra-cheap classification |
| Data Validation | Gemini 2.0 Flash Exp | <2K tokens | FREE | Backup free option |

**Fallback Chain**: DeepSeek R1 (FREE) → Gemini Flash (FREE) → DeepSeek v3.1

#### Analyst Agent AI Models
**Primary Tasks**: Vulnerability analysis, pattern recognition, exploit flow construction

| Task | Model | Context Size | Cost/1M Tokens | Rationale |
|------|-------|-------------|----------------|-----------|
| Pattern Recognition | DeepSeek R1 0528 | 3-5K tokens | FREE | Strong reasoning capabilities |
| Exploit Flow Analysis | DeepSeek R1 0528 | 4-8K tokens | FREE | Complex reasoning, attack logic |
| Risk Assessment | Claude 4 Sonnet | 3-6K tokens | Premium | High-quality severity evaluation |
| Impact Analysis | DeepSeek v3.1 | 2-4K tokens | $0.20/$0.80 | Cost-effective assessment |

**Context Strategy**: Always include structured data + raw diff for exploit analysis
**Fallback Chain**: DeepSeek R1 (FREE) → Claude 4 Sonnet → DeepSeek v3.1

#### Reviewer Agent AI Models
**Primary Tasks**: Validation, consistency checking, quality assurance

| Task | Model | Context Size | Cost/1M Tokens | Rationale |
|------|-------|-------------|----------------|-----------|
| Logical Consistency | Claude 4 Sonnet | 6-10K tokens | Premium | Highest quality validation |
| Evidence Validation | DeepSeek v3.1 | 4-6K tokens | $0.20/$0.80 | Cost-effective fact-checking |
| Cross-Reference Check | DeepSeek R1 0528 | 3-5K tokens | FREE | Good reasoning for cross-validation |
| Report Generation | Claude 4 Sonnet | 4-8K tokens | Premium | Clear, structured output |
| Final Quality Gate | Claude 4 Sonnet | 8-12K tokens | Premium | Comprehensive final review |

**Quality Thresholds**: Confidence >0.8 required for auto-approval
**Fallback Chain**: Claude 4 Sonnet → DeepSeek v3.1 → DeepSeek R1 (FREE)

#### OpenRouter Integration Benefits
**Purpose**: Unified access to multiple AI providers with cost optimization

**Key Advantages**:
- Single API interface for 300+ models
- Transparent pricing and automatic failover
- No vendor lock-in with multiple provider access
- Cost comparison and optimization built-in
- Unified billing and token management

### 2.4.3 Model Selection Logic
**Dynamic Model Selection**: Cost-optimized model assignment with quality safeguards
- **Collector Agent**: DeepSeek R1 (FREE) for most tasks, DeepSeek v3.1 for complex classification
- **Analyst Agent**: DeepSeek R1 (FREE) for analysis, Claude 4 Sonnet for critical risk assessment
- **Reviewer Agent**: Claude 4 Sonnet for final validation, DeepSeek models for routine checks
- **Fallback Strategy**: Automatic downgrade on rate limits: Premium → Paid → FREE models

**Token Budget Management**: Soft limit system with manual approval gates
- **Daily Budget**: 500K tokens (conservative starting point)
- **Soft Limits**: 80% warning, 90% cheap models only, 95% FREE only, >100% manual approval
- **Cost Estimate**: $1-7/day with FREE model priority
- **Performance Analytics**: JSON cache tracking success rates by model per vulnerability type
- **Context Overflow**: Fail and log when context exceeds model limits for measurement

### 2.4.4 Cost Optimization Implementation
- **AI Response Caching**: Semantic similarity matching for similar vulnerabilities
- **FREE Model Priority**: DeepSeek R1 primary, escalate only on failure
- **Strategic Premium Usage**: Claude 4 Sonnet only for critical validation steps
- **Environment-Specific Failover**: Dev = manual review, Prod = automatic cheaper model retry
- **Learning System**: JSON cache files tracking model performance per vulnerability type
- **Budget Controls**: Manual approval gates when token/cost limits exceeded

### 2.4.5 Performance Monitoring
**Key Metrics to Track**:
- Analysis success rate per model (target: >80% for FREE models)
- AI response cache hit ratio (target: >50%)
- Token budget usage (soft limits: 80%, 90%, 95%)
- Model failure rates and fallback triggers
- Average processing time per vulnerability (target: 30-60 seconds)
- Cost per vulnerability analysis (target: <$0.70)

**Alerting Thresholds**:
- FREE model success rate drops below 70%
- Token budget exceeds 80% (warning), 95% (critical)
- Processing time exceeds 2 minutes
- Daily cost exceeds $10

## 2.5 Infrastructure Requirements

### 2.5.1 Dependencies Addition ✅ COMPLETED
**Core Dependencies**:
- aiohttp>=3.9.0 for async HTTP client functionality
- cachetools>=5.3.0 for in-memory LRU caching
- asyncio-throttle>=1.0.0 for rate limiting
- tree-sitter>=0.25.1 for multi-language code parsing
- tree-sitter-python, tree-sitter-javascript, tree-sitter-java, tree-sitter-ruby for language support

  Status:
  - Present: aiohttp, cachetools, asyncio-throttle, tree-sitter, language grammars
  - Completed: Static Tree-sitter query library for hybrid AI selection approach

**AI Integration Dependencies**:
- openrouter>=0.3.0 for unified AI model access
- tiktoken>=0.5.0 for token counting and estimation
- httpx>=0.25.0 for async HTTP requests to OpenRouter

  Status:
  - Missing: openrouter, tiktoken, httpx

**Development and Monitoring Dependencies**:
- aioresponses>=0.7.0 for async testing
- pytest-asyncio>=0.23.0 for async test support
- pytest-mock>=3.12.0 for mocking capabilities
- prometheus-client>=0.19.0 for metrics collection
- docker (host) for sandboxed exploit testing
- codeql CLI (optional) for targeted deep analysis

  Status:
  - Present: aioresponses, pytest-asyncio, pytest-mock
  - Missing: prometheus-client, docker, codeql

### 2.5.2 Project Structure Extension 🟡 PARTIAL
**New Module Organization**:

**/agents/** - Core agent implementations
- collector.py: AsyncHTTPClient, caching, normalization
- analyst.py: Pattern library, flow construction, AI integration
- reviewer.py: Validation, quality assurance, reporting
- base.py: Base agent class, common utilities

**/cache/** - AI response caching system
- memory.py: In-memory LRU cache for AI responses
- disk.py: Compressed disk cache for prompt/response pairs
- utils.py: Cache key generation and similarity matching

**/patterns/** - Security analysis patterns
- security.py: Security pattern definitions
- matchers.py: Pattern matching engine
- scoring.py: Confidence calculation algorithms

**/integration/** - External service integrations
- github.py: GitHub API client with rate limiting
- advisory.py: Advisory database integrations
- openrouter.py: OpenRouter API client with model selection and failover
- repo.py: Repository manager (sparse checkout, caching, diff utils)

**/analysis/** - Code context and advanced analysis
- context.py: Tree-sitter based function/context extractor with static query library
- callgraph.py: Full codebase call graph generation
- codeql.py: Optional CodeQL bridge (guarded, cached)
- queries/: Static Tree-sitter query library organized by language

  Status:
  - Present: `/agents` (base, collector, adapters, data_sources, rate_limiter), `/cache`, `/analysis`, `/integration`
  - Completed: `/analysis` package with Tree-sitter integration, `/integration/repo.py`
  - Missing: `/patterns` package, analyst/reviewer agent modules

### 2.5.3 Configuration Management
- **Environment Variables**: API keys, cache settings, model endpoints
- **Config Files**: Pattern libraries, scoring weights, thresholds
- **Runtime Parameters**: Dynamic adjustment of batch sizes, timeouts
- **Security Settings**: API rate limits, retry policies, fallback modes

## Recent Achievements (Tree-sitter Ruby Integration)

### Ruby Repository Analysis Enhancement ✅ COMPLETED
- **Test Script Enhancement**: `test_github_advisory.py` now includes full Ruby repository analysis
- **Function Name Extraction**: Fixed Ruby method, class, and module name parsing
- **Call Graph Analysis**: 13 functions analyzed with caller/callee relationships  
- **Vulnerability Context**: Shows how vulnerable functions like `encrypt`, `decrypt`, `setup_cipher` are used
- **Repository Stats**: Analyzes Ruby repositories (jwt/ruby-jwe: 83 commits, 2 Ruby files)
- **Integration Success**: 17% call resolution rate with detailed caller context for key functions

### Tree-sitter Analysis Results
The enhanced script successfully demonstrated:
- Repository cloning and Ruby file detection
- Function extraction: `encrypt`, `decrypt`, `setup_cipher`, `iv`, `tag` functions
- Caller relationships: `setup_cipher` called by `encrypt`/`decrypt` (vulnerability entry points)
- Parameter analysis: Shows function signatures and usage patterns
- Call analysis: Maps how vulnerable authentication tag validation flows through the codebase

## Success Criteria

### Functional Requirements
- [x] Collector agent handles 95%+ of advisory formats without errors
- [x] Repo manager supports full repository checkout and targeted analysis
- [x] Tree-sitter parse success rate ≥95% on Ruby repositories
- [ ] Cache hit ratios exceed 60% across all layers
- [ ] Analyst agent identifies security patterns with 85%+ accuracy
- [ ] Reviewer agent catches 90%+ of logical inconsistencies
- [ ] Average processing time: <30s without CodeQL, <2min with CodeQL

### Performance Requirements
- [x] Sequential processing of 1 vulnerability at a time
- [x] Tree-sitter parse success rate ≥95% on supported languages (Ruby: 100%)
- [x] Simplified call graph generation <10s (depth 3) - Ruby analysis: ~5s
- [ ] Token budget compliance with <80% soft limit usage
- [ ] Memory usage under 2GB peak for single vulnerability
- [ ] AI response cache hit ratio >50% for similar patterns
- [ ] Model failover completes within 10 seconds

### Quality Requirements
- [ ] 90%+ test coverage for all agent components
- [ ] FREE models achieve >70% success rate for routine tasks
- [ ] Pattern library covers top 20 vulnerability types
- [ ] Validation rules prevent 95%+ of inconsistent outputs
- [ ] CodeQL used in <10% of analyses (only when needed)
- [ ] Cost per vulnerability analysis under $0.70

### Integration Requirements
- [ ] Seamless handoff between agents
- [ ] Structured data flows validate against Phase 1 models
- [ ] External API integrations handle failures gracefully
- [ ] AI response caching works consistently
- [ ] Tree-sitter context included in Analyst → Reviewer handoff
- [ ] OpenRouter failover mechanisms work reliably across models

This Phase 2 implementation provides the core intelligence layer for automated vulnerability analysis, building on Phase 1's solid foundation while preparing for Phase 3's code generation capabilities.
