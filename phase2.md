# Phase 2: Agent Implementation Plan

## Overview
Phase 2 implements the core agent system for vulnerability analysis, building on the foundation from Phase 1. This phase creates the Collector, Analyst, and Reviewer agents with comprehensive caching and validation. Duration: 3 weeks.

## Prerequisites ✅
- Phase 1 Foundation completed with 12 Pydantic models, 3 parsers, and 70 tests (97% pass rate)
- Development environment with UV, dependencies, and tooling setup
- Complete infrastructure with README, pyproject.toml, pre-commit hooks, Makefile

## 2.1 Collector Agent (Week 2, Days 1-3)

### 2.1.1 Async HTTP Client Infrastructure
- **AsyncHTTPClient**: Concurrent fetching with retry logic
- **Rate Limiting**: Exponential backoff for API quotas (GitHub, NVD)
- **Connection Pooling**: Efficient resource management
- **Error Handling**: Circuit breakers and graceful degradation

### 2.1.2 Multi-Source Data Collection
- **GitHub API Integration**: Commits, releases, diffs, security advisories
- **Advisory Database APIs**: GHSA, OSV, NVD with format adapters
- **File System Sources**: Local patches, cached data, previous analyses
- **Webhook Support**: Real-time updates instead of polling

### 2.1.3 AI Response Caching
```
Memory Cache: In-memory LRU (50MB)
├── AI model responses (24hr TTL)
├── Semantic similarity hashes (1hr TTL)
└── Token count estimates (persistent)

Disk Cache: Compressed storage (500MB)
├── Prompt/response pairs (24hr TTL)
└── Model failure logs (7 days)
```

### 2.1.4 Data Normalization Pipeline
- **Format Adapters**: Per-source type with fallback mappings
- **Deduplication**: Content hashing and fuzzy matching
- **Cross-Referencing**: Link related vulnerabilities and patches
- **Sequential Processing**: One vulnerability at a time for reliability

## 2.2 Analyst Agent (Week 2, Days 4-5, Week 3, Days 1-2)

### 2.2.1 Security Pattern Library
- **Auth Bypass Patterns**: Missing/modified authentication checks
- **Deserialization Vulnerabilities**: Unsafe object construction patterns
- **Injection Points**: String concatenation in queries, commands
- **Buffer Overflow**: Bounds check modifications and omissions
- **TOCTOU Conditions**: Time-of-check vs time-of-use gaps
- **Cryptographic Issues**: Weak algorithms, key management problems
- **Path Traversal**: Directory traversal and file access patterns
- **Race Conditions**: Thread safety and synchronization issues

### 2.2.2 Static Analysis Engine
- **AST-Based Analysis**: Code structure and flow analysis
- **Regex Pattern Matching**: Common vulnerability signatures
- **Context-Aware Scoring**: Change impact assessment
- **Function Mapping**: Entry points and data flow tracking

### 2.2.3 AI Integration Architecture
**Hybrid Data Approach**: Combines structured metadata with raw content for comprehensive analysis
- **Structured Data**: VulnerabilityReport, SecurityMatch, AffectedArtifact models
- **Raw Exploit Context**: Original diff content with metadata (files changed, functions modified, line counts)
- **Context Recovery**: Raw advisory JSON when parsed data loses critical information
- **Optimization Flags**: Confidence thresholds and context inclusion rules

### 2.2.4 Exploit Flow Construction
- **Attack Graph Building**: Entry point to impact mapping
- **Step Sequencing**: Logical attack progression
- **Precondition Chains**: Required conditions for exploitation
- **Probability Calculation**: Reachability and success likelihood
- **Impact Assessment**: CIA triad analysis with scope evaluation

### 2.2.5 Confidence Scoring System
- **Evidence Strength**: Explicit vs implied vulnerability indicators
- **Advisory Clarity**: Detailed vs vague descriptions
- **Patch Complexity**: Single line vs multi-file changes
- **Source Reliability**: Trusted sources vs community reports
- **Validation Results**: Cross-reference consistency

## 2.3 Reviewer Agent (Week 3, Days 3-5)

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

## 2.4 Advanced Features (Week 3 Integration)

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

**Token Budget Management**: Soft limit system with usage monitoring
- **Daily Budget**: 500K tokens (conservative starting point)
- **Soft Limits**: 80% warning, 90% cheap models only, 95% FREE only
- **Cost Estimate**: $1-7/day with mixed model usage
- **Monitoring**: Track success rates by model to optimize selection

### 2.4.4 Cost Optimization Implementation
- **AI Response Caching**: Semantic similarity matching for similar vulnerabilities
- **FREE Model Priority**: Use DeepSeek R1 and Gemini Flash as primary options
- **Strategic Premium Usage**: Claude 4 Sonnet only for critical validation steps
- **Automatic Failover**: Downgrade to cheaper models on rate limits or errors
- **Usage Analytics**: Track model performance to optimize cost/quality balance

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

### 2.5.1 Dependencies Addition
**Core Dependencies**:
- aiohttp>=3.9.0 for async HTTP client functionality
- cachetools>=5.3.0 for in-memory LRU caching
- asyncio-throttle>=1.0.0 for rate limiting

**AI Integration Dependencies**:
- openrouter>=0.3.0 for unified AI model access
- tiktoken>=0.5.0 for token counting and estimation
- httpx>=0.25.0 for async HTTP requests to OpenRouter

**Development and Monitoring Dependencies**:
- aioresponses>=0.7.0 for async testing
- pytest-asyncio>=0.23.0 for async test support
- pytest-mock>=3.12.0 for mocking capabilities
- prometheus-client>=0.19.0 for metrics collection

### 2.5.2 Project Structure Extension
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

### 2.5.3 Configuration Management
- **Environment Variables**: API keys, cache settings, model endpoints
- **Config Files**: Pattern libraries, scoring weights, thresholds
- **Runtime Parameters**: Dynamic adjustment of batch sizes, timeouts
- **Security Settings**: API rate limits, retry policies, fallback modes

## Success Criteria

### Functional Requirements
- [ ] Collector agent handles 95%+ of advisory formats without errors
- [ ] Cache hit ratios exceed 60% across all layers
- [ ] Analyst agent identifies security patterns with 85%+ accuracy
- [ ] Reviewer agent catches 90%+ of logical inconsistencies
- [ ] Average processing time under 2 minutes per vulnerability

### Performance Requirements
- [ ] Sequential processing of 1 vulnerability at a time
- [ ] Token budget compliance with <80% soft limit usage
- [ ] Memory usage under 2GB peak for single vulnerability
- [ ] AI response cache hit ratio >50% for similar patterns
- [ ] Model failover completes within 10 seconds

### Quality Requirements
- [ ] 90%+ test coverage for all agent components
- [ ] FREE models achieve >70% success rate for routine tasks
- [ ] Pattern library covers top 20 vulnerability types
- [ ] Validation rules prevent 95%+ of inconsistent outputs
- [ ] Cost per vulnerability analysis under $0.70

### Integration Requirements
- [ ] Seamless handoff between agents
- [ ] Structured data flows validate against Phase 1 models
- [ ] External API integrations handle failures gracefully
- [ ] AI response caching works consistently
- [ ] OpenRouter failover mechanisms work reliably across models

This Phase 2 implementation provides the core intelligence layer for automated vulnerability analysis, building on Phase 1's solid foundation while preparing for Phase 3's code generation capabilities.
