# Circle-IR Architecture & Design Decisions

This document outlines the key architectural decisions that make Circle-IR a high-performance, adaptive SAST tool.

## Table of Contents

1. [System Overview](#system-overview)
2. [Core Design Principles](#core-design-principles)
3. [Key Architectural Decisions](#key-architectural-decisions)
   - [ADR-001: Constant Propagation Engine](#adr-001-constant-propagation-engine)
   - [ADR-002: Dynamic Pattern Discovery](#adr-002-dynamic-pattern-discovery)
   - [ADR-003: LLM-Augmented Analysis](#adr-003-llm-augmented-analysis)
   - [ADR-004: Configuration-Driven Taint Patterns](#adr-004-configuration-driven-taint-patterns)
   - [ADR-005: Multi-Target Build System](#adr-005-multi-target-build-system)
4. [Analysis Pipeline](#analysis-pipeline)
5. [Benchmark Performance](#benchmark-performance)

---

## System Overview

Circle-IR is a static application security testing (SAST) tool that performs taint analysis to detect data flow vulnerabilities. It tracks data from user-controlled sources (HTTP inputs, environment variables, etc.) to dangerous sinks (SQL queries, command execution, etc.).

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Circle-IR Pipeline                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Source Code                                                             │
│       │                                                                  │
│       ▼                                                                  │
│  ┌─────────────┐    ┌──────────────────┐    ┌─────────────────────┐     │
│  │  Tree-sitter │───▶│  AST Extraction  │───▶│  IR Generation      │     │
│  │  Parser      │    │  (Types, Calls)  │    │  (CFG, DFG, Meta)   │     │
│  └─────────────┘    └──────────────────┘    └─────────────────────┘     │
│                                                        │                 │
│                                                        ▼                 │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    Analysis Engine                               │    │
│  │  ┌───────────────┐  ┌──────────────┐  ┌─────────────────────┐   │    │
│  │  │   Constant    │  │   Pattern    │  │   Taint Analysis    │   │    │
│  │  │  Propagation  │─▶│  Discovery   │─▶│   & Propagation     │   │    │
│  │  └───────────────┘  └──────────────┘  └─────────────────────┘   │    │
│  │         │                  │                     │               │    │
│  │         ▼                  ▼                     ▼               │    │
│  │  ┌───────────────┐  ┌──────────────┐  ┌─────────────────────┐   │    │
│  │  │  Dead Code    │  │     LLM      │  │  False Positive     │   │    │
│  │  │  Elimination  │  │ Verification │  │    Filtering        │   │    │
│  │  └───────────────┘  └──────────────┘  └─────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│                           ┌───────────────┐                              │
│                           │   Findings    │                              │
│                           │  (SARIF/JSON) │                              │
│                           └───────────────┘                              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Core Design Principles

### 1. Zero False Positives Over Maximum Coverage
We prioritize **precision over recall**. A finding that is reported should be a real vulnerability. This is achieved through:
- Constant propagation to eliminate safe assignments
- Dead code detection to skip unreachable sinks
- Sanitizer recognition to identify security controls

### 2. Adaptive Pattern Discovery
Rather than relying solely on hardcoded patterns, the system **learns and discovers** new vulnerability patterns during analysis using:
- Heuristic-based detection from method signatures
- LLM verification for confidence boosting
- Cross-file pattern accumulation

### 3. Configuration-Driven Extensibility
All taint sources, sinks, and sanitizers are defined in configuration, allowing:
- Easy addition of new vulnerability patterns
- Framework-specific customization
- Organization-specific rules

### 4. Environment Agnostic Core
The core analysis library works in any JavaScript environment:
- Node.js for CLI usage
- Browser for web-based analysis
- Cloudflare Workers for serverless deployment

---

## Key Architectural Decisions

### ADR-001: Constant Propagation Engine

**Status:** Implemented
**Impact:** +50% TPR improvement on OWASP Benchmark

#### Context
Many SAST tools produce false positives because they don't track whether a variable has been assigned a safe constant value before reaching a sink.

#### Decision
Implement a sophisticated constant propagation engine that:
1. Tracks variable values through assignments
2. Evaluates conditional expressions to detect dead code
3. Maintains per-key taint tracking for collections (maps, lists)
4. Performs inter-procedural analysis for method return values

#### Implementation

```typescript
// src/analysis/constant-propagation.ts

interface ConstantPropagatorResult {
  symbols: Map<string, ConstantValue>;      // Variable → constant value
  tainted: Set<string>;                      // Tainted variable names
  unreachableLines: Set<number>;             // Dead code lines
  sanitizedVars: Set<string>;                // Variables that were sanitized
  taintedArrayElements: Map<string, Set<number>>; // Array index tracking
}
```

#### Key Features

**Dead Code Detection:**
```java
// Before: FP - both branches flagged
if (false) {
    stmt.execute(userInput);  // Unreachable - not flagged
}

// Constant condition evaluation
String mode = "safe";
if (mode.equals("unsafe")) {
    stmt.execute(userInput);  // Unreachable - not flagged
}
```

**Strong Updates:**
```java
String query = request.getParameter("q");  // Tainted
query = "SELECT * FROM users";              // Constant - overwrites taint
stmt.execute(query);                        // Safe - not flagged
```

**Collection Tracking:**
```java
Map<String, String> params = new HashMap<>();
params.put("safe", "constant");
params.put("unsafe", request.getParameter("x"));

stmt.execute(params.get("safe"));    // Safe - not flagged
stmt.execute(params.get("unsafe"));  // Dangerous - flagged
```

#### Consequences
- OWASP Benchmark improved from ~50% to 100%
- Eliminated ~50% of false positives
- Added ~800 lines of analysis code

---

### ADR-002: Dynamic Pattern Discovery

**Status:** Implemented
**Impact:** Adaptive detection of unknown vulnerability patterns

#### Context
Hardcoded patterns cannot cover all possible vulnerability scenarios. New frameworks, custom code, and evolving attack vectors require constant pattern updates.

#### Decision
Implement a heuristic-based pattern discovery system that:
1. Analyzes method signatures to identify potential sources/sinks
2. Uses confidence scoring for discovered patterns
3. Optionally verifies with LLM for higher confidence
4. Caches patterns for cross-file accumulation

#### Implementation

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Heuristic     │────▶│  LLM Verify     │────▶│  Pattern Cache  │
│   Discovery     │     │  (optional)     │     │  (runtime)      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        └───────────────────────┴───────────────────────┘
                                │
                        ┌───────▼───────┐
                        │   Analyzer    │
                        │  (uses all)   │
                        └───────────────┘
```

#### Heuristic Rules

**Source Detection:**
| Pattern | Type | Confidence |
|---------|------|------------|
| `get(Parameter\|Header\|Cookie)*` | http_param | 0.9 |
| `read(Line\|String\|Object)*` | io_input | 0.8 |
| `parse\|decode\|deserialize*` | io_input | 0.7 |
| Parameter type: `HttpServletRequest` | http_param | 0.8 |
| Annotation: `@RequestParam` | http_param | 0.95 |

**Sink Detection:**
| Pattern | Type | CWE | Confidence |
|---------|------|-----|------------|
| `execute(Query\|Update\|Sql)*` | sql_injection | CWE-89 | 0.9 |
| `exec\|run\|spawn\|system*` | command_injection | CWE-78 | 0.9 |
| `read\|write\|open*File` | path_traversal | CWE-22 | 0.8 |
| `eval\|compile*Expression` | code_injection | CWE-94 | 0.9 |

**Class Context Boosting:**
```typescript
// Class name patterns boost confidence
*Controller  → source: +0.2, sink: +0.1
*Handler     → source: +0.1, sink: +0.15
*Processor   → source: +0.1, sink: +0.2
*File/*Path  → sink (path_traversal): +0.25
*Sql/*Jdbc   → sink (sql_injection): +0.3
```

#### Usage

```typescript
const result = await analyze(code, filePath, 'java', {
  enablePatternDiscovery: true,
  patternConfidenceThreshold: 0.6,  // Use patterns with ≥60% confidence
});
```

#### Consequences
- Adapts to new codebases automatically
- Reduces manual pattern maintenance
- Cross-file pattern accumulation improves accuracy over time

---

### ADR-003: LLM-Augmented Analysis

**Status:** Implemented
**Impact:** Higher confidence verification, reduced false positives

#### Context
Heuristic-based detection can produce false positives. Human-level reasoning can distinguish true vulnerabilities from false positives.

#### Decision
Integrate LLM capabilities for:
1. **Enrichment:** Discover additional sources/sinks from code context
2. **Verification:** Confirm taint paths are exploitable
3. **Pattern Validation:** Verify heuristically-discovered patterns

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LLM Integration                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Enrichment  │  │ Verification │  │ Pattern Verify   │   │
│  │    Agent     │  │    Agent     │  │     Agent        │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│         │                │                   │               │
│         └────────────────┼───────────────────┘               │
│                          ▼                                   │
│                 ┌────────────────┐                           │
│                 │   LLM Client   │                           │
│                 │  (OpenAI API)  │                           │
│                 └────────────────┘                           │
│                          │                                   │
│                          ▼                                   │
│                 ┌────────────────┐                           │
│                 │  LLM Proxy     │                           │
│                 │ (configurable) │                           │
│                 └────────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

#### Configuration

```bash
# Environment variables
LLM_BASE_URL=http://localhost:4000/v1
LLM_API_KEY=your-api-key
LLM_ENRICHMENT_MODEL=gpt-4
LLM_VERIFICATION_MODEL=gpt-4
```

#### Graceful Degradation
When LLM is unavailable:
- Falls back to heuristic confidence
- Reduces pattern confidence by 20%
- Continues analysis without blocking

---

### ADR-004: Configuration-Driven Taint Patterns

**Status:** Implemented
**Impact:** Extensibility, framework-specific support

#### Context
Different frameworks and organizations have different vulnerability patterns. Hardcoding all patterns is unmaintainable.

#### Decision
Define all taint patterns in configuration:

```typescript
// Source pattern
{
  method: 'getParameter',
  class: 'HttpServletRequest',
  type: 'http_param',
  severity: 'high',
  return_tainted: true
}

// Sink pattern
{
  method: 'executeQuery',
  class: 'Statement',
  type: 'sql_injection',
  cwe: 'CWE-89',
  severity: 'critical',
  arg_positions: [0]
}

// Sanitizer pattern
{
  method: 'setString',
  class: 'PreparedStatement',
  removes: ['sql_injection']
}
```

#### Pattern Categories

**Sources (400+ patterns):**
- HTTP: parameters, headers, cookies, body, path
- I/O: file input, environment, command line
- Database: query results
- Deserialization: XML, JSON, object streams

**Sinks (300+ patterns):**
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- XSS (CWE-79)
- Code Injection (CWE-94)
- LDAP Injection (CWE-90)
- XPath Injection (CWE-643)
- SSRF (CWE-918)
- Deserialization (CWE-502)

**Sanitizers (100+ patterns):**
- PreparedStatement (SQL)
- ESAPI encoding (XSS)
- Path normalization (Path Traversal)
- Input validation

---

### ADR-005: Multi-Target Build System

**Status:** Implemented
**Impact:** Universal deployment

#### Context
The tool needs to run in multiple environments: CLI, browser, serverless.

#### Decision
Use a multi-target build system:

```
src/
├── core/           # Environment-agnostic (no Node.js APIs)
├── analysis/       # Pure analysis logic
├── types/          # TypeScript definitions
├── browser.ts      # Browser entry point
├── worker.ts       # Cloudflare Worker entry point
└── cli/            # Node.js CLI
```

#### Build Targets

| Target | Format | Use Case |
|--------|--------|----------|
| Node.js | ES2022 | CLI, scripts |
| Browser | ESM bundle | Web UI |
| Worker | ESM bundle | Serverless API |

```bash
npm run build           # Node.js
npm run build:browser   # Browser bundle
npm run build:worker    # Cloudflare Worker
npm run build:all       # All targets
```

---

## Analysis Pipeline

### Phase 1: Parsing & Extraction
```
Source Code → Tree-sitter → AST → Types, Calls, Imports
```

### Phase 2: IR Generation
```
AST → CFG (Control Flow Graph)
    → DFG (Data Flow Graph)
    → Meta (File metadata)
```

### Phase 3: Constant Propagation
```
AST + DFG → Variable tracking
          → Dead code detection
          → Collection taint tracking
```

### Phase 4: Pattern Discovery (Optional)
```
Types + Calls → Heuristic detection
             → LLM verification
             → Pattern cache
```

### Phase 5: Taint Analysis
```
Sources + Sinks + Config → Path enumeration
                        → Sanitizer checking
                        → Confidence scoring
```

### Phase 6: Filtering
```
Taint flows → Constant propagation filter
           → Dead code filter
           → Sanitizer filter
           → Verified findings
```

---

## Benchmark Performance

### Summary
| Benchmark | TPR | FPR | Score |
|-----------|-----|-----|-------|
| **OWASP Benchmark** | 100% | 0% | **+100%** |
| **Juliet Test Suite** | 100% | 0% | **+100%** |
| **SecuriBench Micro** | 97.2% | 53.3% | +43.9% |
| **CWE-Bench-Java** | 81.7% (with LLM) | - | **+81.7%** |

### OWASP Benchmark v1.2 (Perfect Score)
- **2740 test cases, 0 false negatives, 0 false positives**
- Perfect on all 11 categories: sqli, cmdi, xss, pathtraver, ldapi, xpathi, trustbound, hash, crypto, weakrand, securecookie

### Juliet Test Suite (Perfect Score)
- **156 test cases across 9 CWEs**
- Perfect on: CWE-23, CWE-36, CWE-78, CWE-79/80/81/83, CWE-89, CWE-90, CWE-643

### SecuriBench Micro
| Category | TPR | FPR |
|----------|-----|-----|
| basic | 100% | N/A |
| arrays | 100% | 0% |
| inter | 100% | N/A |
| datastructures | 100% | N/A |
| collections | 84.6% | 100% |
| aliasing | 83.3% | N/A |
| pred | 100% | 40% |
| sanitizers | 100% | 66.7% |

FPs primarily from: correlated predicates, custom sanitizers, strong updates.

### CWE-Bench-Java (120 Projects with LLM Discovery)
| CWE | TPR | Count |
|-----|-----|-------|
| CWE-022 (Path Traversal) | 85.5% | 47/55 |
| CWE-078 (Command Injection) | 76.9% | 10/13 |
| CWE-079 (XSS) | 87.1% | 27/31 |
| CWE-094 (Code Injection) | 66.7% | 14/21 |
| **Overall (Claude Opus Discovery)** | **81.7%** | **98/120** |

**Comparison:**
- Circle-IR + Claude Opus: 81.7% (98/120)
- IRIS + GPT-4: 45.8% (55/120)
- CodeQL: 22.5% (27/120)

---

## Future Directions

1. **Inter-file Analysis:** Track taint across module boundaries
2. **Type Inference:** Better receiver type resolution
3. **Framework-Specific Plugins:** Spring, Struts, etc.
4. **IDE Integration:** VS Code, IntelliJ extensions
5. **CI/CD Integration:** GitHub Actions, GitLab CI

---

## References

- [Circle-IR Specification](./SPEC.md)
- [LLM Configuration](./LLM-CONFIG.md)
- [OWASP Benchmark](https://owasp.org/www-project-benchmark/)
- [CWE Database](https://cwe.mitre.org/)
