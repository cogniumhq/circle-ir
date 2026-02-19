# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.3.0] - 2025-02-19

### Added

- **Logger Dependency Injection**: New `setLogger()` function allows consumers to inject custom loggers (pino, winston, etc.)
- **Logger Exports**: `setLogger`, `configureLogger`, `setLogLevel`, `getLogLevel`, `logger` now exported from main index

### Changed

- **Zero-dependency Logger**: Replaced pino with a simple console-based logger (zero dependencies, browser-compatible)
- **Removed Dead Code**: Deleted unused modules (advisory-db, cargo-parser, dependency-scanner) that were not part of taint analysis
- **Cleaned skipMethods**: Removed benchmark-specific method names from interprocedural analysis skip list

### Removed

- `pino` dependency (replaced with zero-dependency console logger + DI)
- `pino-pretty` devDependency
- Unused barrel exports: `isInDangerousPosition`, `formatVerificationResult`
- Dead analysis modules: `advisory-db.ts`, `cargo-parser.ts`, `dependency-scanner.ts`

## [3.1.0] - 2025-02-11

### Changed

- **npm-ready Package**: Added proper exports map, module field, sideEffects flag, and publishConfig
- **WASM Path Resolution**: Fixed path resolution to work when installed as npm package (resolves relative to module location)
- **Browser Compatibility**: Used Function constructor pattern to hide Node.js imports from bundlers

### Fixed

- WASM files now correctly resolve whether circle-ir is run from source or installed via npm
- Browser builds no longer fail due to Node.js module imports

## [3.0.0] - 2025-02-01

### Added

- **Core SAST Library**: Complete taint analysis engine for detecting security vulnerabilities
- **Multi-language Support**: Java, JavaScript/TypeScript, Python, Rust
- **Universal Core**: Environment-agnostic library works in Node.js, browsers, and Cloudflare Workers
- **Vulnerability Detection**: SQL injection, command injection, XSS, path traversal, LDAP injection, XPath injection, deserialization, SSRF, code injection, XXE
- **Configuration-driven Analysis**: YAML-based source/sink definitions
- **Browser Demo**: Interactive HTML example for browser-based analysis

### Benchmark Results

- **OWASP Benchmark**: +100% (TPR: 100%, FPR: 0%, 1415/1415 test cases)
- **Juliet Test Suite**: +100% (156/156 test cases)
- **SecuriBench Micro**: 97.7% TPR, 6.7% FPR (105/108 vulns detected)
- **CWE-Bench-Java**: 65.5% (509/777 CVEs)

### Technical Highlights

- Tree-sitter WASM parsing for accurate AST generation
- Constant propagation for false positive elimination
- Inter-procedural taint analysis
- Sanitizer recognition (PreparedStatement, ESAPI, etc.)
- Per-index collection taint tracking
- Language plugin architecture

[3.3.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.0
[3.1.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.1.0
[3.0.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.0.0
