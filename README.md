# circle-ir

A high-performance Static Application Security Testing (SAST) library for detecting security vulnerabilities through taint analysis. Works in Node.js, browsers, and Cloudflare Workers.

## Features

- **Taint Analysis**: Track data flow from sources (user input) to sinks (dangerous operations)
- **Multi-language Support**: Java, JavaScript/TypeScript, Python, Rust, Bash/Shell
- **High Accuracy**: 100% on OWASP Benchmark, 100% on Juliet Test Suite, 97.7% TPR on SecuriBench Micro
- **Universal**: Works in Node.js, browsers, and Cloudflare Workers
- **Zero External Dependencies**: Core analysis runs without network calls or external services
- **Browser Compatible**: Tree-sitter WASM for universal parsing
- **Configuration-Driven**: YAML/JSON patterns for sources, sinks, and sanitizers

## Related Packages

- **[circle-ir-ai](https://github.com/cogniumhq/circle-ir-ai)**: LLM-enhanced analysis layer — adds discovery mode, CLI, and benchmark runners on top of circle-ir

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

// Check for vulnerabilities
for (const flow of result.taint.flows || []) {
  console.log(`Found ${flow.sink_type} vulnerability`);
  console.log(`  Source: line ${flow.source_line}`);
  console.log(`  Sink: line ${flow.sink_line}`);
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

Analyze source code and return Circle-IR output.

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

> With [circle-ir-ai](https://github.com/cogniumhq/circle-ir-ai) LLM discovery mode, CWE-Bench-Java reaches **81.7%** (98/120 with Claude Opus).

## Documentation

- [Circle-IR Specification](docs/SPEC.md) - IR format specification
- [Architecture Guide](docs/ARCHITECTURE.md) - Detailed system architecture
- [Contributing Guide](CONTRIBUTING.md) - How to contribute
- [Changelog](CHANGELOG.md) - Version history
- [TODO](TODO.md) - Pending improvements and roadmap

## License

ISC
