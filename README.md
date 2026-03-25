# circle-ir

A high-performance Static Application Security Testing (SAST) library for detecting security vulnerabilities through taint analysis, and code quality findings through an extensible analysis-pass pipeline. Works in Node.js and browsers.

## Features

- **Taint Analysis**: Track data flow from sources (user input) to sinks (dangerous operations)
- **Multi-language Support**: Java, JavaScript/TypeScript, Python, Rust, Bash/Shell
- **High Accuracy**: 100% on OWASP Benchmark, 100% on Juliet Test Suite, 97.7% TPR on SecuriBench Micro
- **11-Pass Pipeline**: Security taint passes + quality passes (dead code, missing await, N+1, doc coverage, TODO markers)
- **Cross-File Analysis**: `analyzeProject()` surfaces taint flows that span multiple files
- **Universal**: Works in Node.js and browsers with environment-agnostic core
- **Zero External Dependencies**: Core analysis runs without network calls or external services
- **Browser Compatible**: Tree-sitter WASM for universal parsing
- **Configuration-Driven**: YAML/JSON patterns for sources, sinks, and sanitizers

## Installation

```bash
npm install circle-ir
```

## Quick Start

### Node.js

```typescript
import { initAnalyzer, analyze } from 'circle-ir';

// Initialize the analyzer
await initAnalyzer();

// Analyze Java code
const result = await analyze(code, 'MyClass.java', 'java');

// Security taint flows
for (const flow of result.taint.flows || []) {
  console.log(`Found ${flow.sink_type} vulnerability`);
  console.log(`  Source: line ${flow.source_line}`);
  console.log(`  Sink: line ${flow.sink_line}`);
}

// Quality findings from analysis passes (dead-code, missing-await, n-plus-one, etc.)
for (const finding of result.findings || []) {
  console.log(`[${finding.severity}] ${finding.rule_id} at line ${finding.line}`);
  console.log(`  ${finding.message}`);
  if (finding.fix) console.log(`  Fix: ${finding.fix}`);
}
```

### Browser

```html
<script type="module">
import { initAnalyzer, analyze } from './dist/browser/circle-ir.js';

await initAnalyzer({
  wasmPath: './wasm/web-tree-sitter.wasm',
  languagePaths: {
    java: './wasm/tree-sitter-java.wasm'
  }
});

const result = await analyze(code, 'Test.java', 'java');
console.log(result);
</script>
```

## API Reference

### `initAnalyzer(options?)`

Initialize the analyzer. Must be called before `analyze()`.

```typescript
interface AnalyzerOptions {
  wasmPath?: string;           // Path to web-tree-sitter.wasm
  languagePaths?: {            // Paths to language WASM files
    java?: string;
    javascript?: string;
    python?: string;
    rust?: string;
  };
  taintConfig?: TaintConfig;   // Custom taint configuration
}
```

### `analyze(code, filePath, language, options?)`

Analyze a single file and return Circle-IR output.

```typescript
const result = await analyze(code, 'File.java', 'java');

// Result contains:
result.meta       // File metadata
result.types      // Classes, methods, fields
result.calls      // Method invocations
result.cfg        // Control flow graph
result.dfg        // Data flow graph
result.taint      // Taint sources, sinks, flows
result.imports    // Import statements
result.exports    // Exported symbols
result.findings   // SastFinding[] from all 11 analysis passes
```

### `analyzeProject(files, options?)`

Analyze multiple files together to detect cross-file taint flows.

```typescript
import { analyzeProject } from 'circle-ir';

const result = await analyzeProject([
  { code: controllerCode, filePath: 'UserController.java', language: 'java' },
  { code: serviceCode,    filePath: 'UserService.java',    language: 'java' },
  { code: daoCode,        filePath: 'UserDao.java',        language: 'java' },
]);

// Per-file analysis (same as analyze() per file)
for (const { file, analysis } of result.files) {
  console.log(`${file}: ${analysis.taint.flows?.length ?? 0} intra-file flows`);
}

// Cross-file taint paths (the key deliverable)
for (const path of result.taint_paths) {
  console.log(`Cross-file ${path.sink.type}: ${path.source.file} → ${path.sink.file}`);
  console.log(`  Confidence: ${path.confidence.toFixed(2)}, CWE: ${path.sink.cwe}`);
}

// Resolved inter-file method calls
console.log(`${result.cross_file_calls.length} cross-file calls resolved`);

// Project metadata
console.log(`${result.meta.total_files} files, ${result.meta.total_loc} LOC`);
```

### `analyzeForAPI(code, filePath, language, options?)`

Simplified API response format suitable for REST APIs.

```typescript
const response = await analyzeForAPI(code, 'File.java', 'java');

// Response format:
{
  success: true,
  analysis: {
    sources: [...],
    sinks: [...],
    vulnerabilities: [...]
  },
  meta: {
    parseTimeMs: 15,
    analysisTimeMs: 42,
    totalTimeMs: 57
  }
}
```

## Supported Languages

| Language | Parser | Frameworks |
|----------|--------|------------|
| **Java** | tree-sitter-java | Spring, JAX-RS, Servlet API |
| **JavaScript/TypeScript** | tree-sitter-javascript | Express, Fastify, Koa, Node.js |
| **Python** | tree-sitter-python | Flask, Django, FastAPI |
| **Rust** | tree-sitter-rust | Actix-web, Rocket, Axum |
| **Bash/Shell** | tree-sitter-bash | Shell scripts (.sh, .bash, .zsh, .ksh) |

### Multi-Language Examples

```typescript
// Analyze JavaScript
const jsResult = await analyze(jsCode, 'server.js', 'javascript');

// Analyze Python
const pyResult = await analyze(pyCode, 'app.py', 'python');

// Analyze Rust
const rsResult = await analyze(rsCode, 'main.rs', 'rust');
```

## Detected Vulnerabilities

| Type | CWE | Description |
|------|-----|-------------|
| SQL Injection | CWE-89 | User input in SQL queries |
| Command Injection | CWE-78 | User input in system commands |
| XSS | CWE-79 | User input in HTML output |
| Path Traversal | CWE-22 | User input in file paths |
| LDAP Injection | CWE-90 | User input in LDAP queries |
| XPath Injection | CWE-643 | User input in XPath queries |
| Deserialization | CWE-502 | Untrusted deserialization |
| SSRF | CWE-918 | Server-side request forgery |
| Code Injection | CWE-94 | Dynamic code execution |
| XXE | CWE-611 | XML external entity injection |

## Configuration

Custom taint sources, sinks, and sanitizers can be configured via YAML:

```yaml
# configs/sources/custom.yaml
sources:
  - method: getUserInput
    class: CustomInputHandler
    type: http_param
    severity: high
    tainted_args: [return]
```

## SAST Findings & Quality Passes

The 11-pass pipeline emits `SastFinding[]` via `result.findings`. Each finding is SARIF 2.1.0-aligned:

```typescript
interface SastFinding {
  id: string;           // e.g. "dead-code-42"
  rule_id: string;      // e.g. "dead-code"
  category: PassCategory; // 'security' | 'reliability' | 'performance' | 'maintainability' | 'architecture'
  severity: string;     // 'critical' | 'high' | 'medium' | 'low'
  level: SarifLevel;    // 'error' | 'warning' | 'note' | 'none'
  message: string;
  file: string;
  line: number;
  cwe?: string;         // e.g. "CWE-561"
  fix?: string;         // Instance-specific remediation hint
  evidence?: Record<string, unknown>;
}
```

**Current passes** (see [docs/PASSES.md](docs/PASSES.md) for the full registry):

| Pass | rule_id | Category | CWE | Level |
|------|---------|----------|-----|-------|
| TaintMatcherPass | _(produces flows)_ | security | — | error |
| ConstantPropagationPass | _(reduces FP)_ | security | — | — |
| LanguageSourcesPass | _(enriches sources)_ | security | — | — |
| SinkFilterPass | _(filters sinks)_ | security | — | — |
| TaintPropagationPass | _(propagates taint)_ | security | — | error |
| InterproceduralPass | _(cross-method)_ | security | — | error |
| DeadCodePass | `dead-code` | reliability | CWE-561 | warning |
| MissingAwaitPass | `missing-await` | reliability | CWE-252 | warning |
| NPlusOnePass | `n-plus-one` | performance | CWE-1049 | warning |
| MissingPublicDocPass | `missing-public-doc` | maintainability | — | note |
| TodoInProdPass | `todo-in-prod` | maintainability | — | note |

## Key Analysis Features

- **Constant Propagation**: Eliminates false positives by tracking variable values and detecting dead code
- **DFG-Based Verification**: Uses data flow graphs to verify end-to-end taint flows
- **Inter-Procedural Analysis**: Tracks taint across method boundaries
- **Sanitizer Recognition**: Detects PreparedStatement, ESAPI, escapeHtml, and other sanitizers
- **Collection Tracking**: Precise taint tracking through List/Map operations with index shifting

## Benchmark Results

All scores below are for **circle-ir static analysis only** (no LLM).

| Benchmark | Score | Details |
|-----------|-------|---------|
| **OWASP Benchmark** | +100% | TPR 100%, FPR 0% (1415 test cases) |
| **Juliet Test Suite** | +100% | 156/156 test cases, 9 CWEs |
| **SecuriBench Micro** | 97.7% TPR | 105/108 vulns detected, 6.7% FPR |
| **CWE-Bench-Java** | 42.5% | 51/120 real-world CVEs (vs CodeQL 22.5%, IRIS+GPT-4 45.8%) |
| **Bash Synthetic** | 68.2% TPR | 15 TP, 9 TN, 0 FP on 31 synthetic test cases |

## Documentation

- [Pass & Metric Registry](docs/PASSES.md) - Canonical list of every pass and metric with rule_id, CWE, and status
- [Circle-IR Specification](docs/SPEC.md) - IR format specification
- [Architecture Guide](docs/ARCHITECTURE.md) - Detailed system architecture
- [Changelog](CHANGELOG.md) - Version history
- [TODO](TODO.md) - Phase-based roadmap

## License

MIT
