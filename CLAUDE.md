# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Guardrails

- **TypeScript throughout** - All code must be written in TypeScript with strict mode enabled. No `any` types without explicit justification.
- **Unit test coverage ≥75%** - All new code must have unit tests. Run coverage reports to verify threshold before merging.
- **Universal core library** - The core library (`src/core/`, `src/analysis/`, `src/types/`) must be environment-agnostic. No Node.js-specific APIs in core code. Platform-specific code belongs only in entry points (`src/browser.ts`, `src/worker.ts`).
- **circle-ir spec alignment** - All IR types and structures must conform to `docs/SPEC.md`. When implementing new features, update the spec's Implementation Status table (TypeScript column) accordingly.

## Project Overview

circle-ir is the core TypeScript SAST library for taint analysis. It detects data flow vulnerabilities by tracking data from user-controlled sources (HTTP inputs, environment variables, etc.) to dangerous sinks (SQL queries, command execution, etc.) using Tree-sitter for parsing.

This is the **core library** in the cognitim monorepo. For CLI, benchmarks, and LLM-enhanced analysis, see `circle-ir-ai`.

## Build Commands

```bash
npm run build           # Compile TypeScript to dist/
npm run build:browser   # Bundle for browser (ESM) -> dist/browser/circle-ir.js
npm run build:worker    # Bundle for Cloudflare Workers -> dist/worker/index.js
npm run build:all       # Run all builds

npm run typecheck       # Type check without emitting
npm test                # Run all tests
npm run test:watch      # Run tests in watch mode
npm run test:coverage   # Run tests with coverage report (must be ≥75%)
```

## Architecture

For detailed architecture, see:
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Full system architecture
- **[docs/SPEC.md](docs/SPEC.md)** - Circle-IR specification

**Multi-target build system:**
- Node.js build via `tsc` (ES2022, strict mode)
- Browser bundle via esbuild (ESM format)
- Core library bundle for universal environments

**Source structure:**
- `src/core/` - Parsing and IR generation using web-tree-sitter
- `src/analysis/` - Taint flow analysis engine
- `src/types/` - TypeScript type definitions
- `src/languages/` - Language plugins (Java, JavaScript, Python, Rust)
- `src/resolution/` - Cross-file resolution and type hierarchy
- Entry point: `src/browser.ts` (browser-specific initialization)

**Configuration-driven analysis:**
The `configs/` directory contains YAML definitions for taint sources and sinks:

- `configs/sources/` - Taint sources (HTTP params, headers, cookies, env vars, DB results, file I/O)
- `configs/sinks/` - Dangerous operations (SQL injection, command execution, XSS, path traversal, deserialization, LDAP/XPath injection)

Each config entry specifies: method/class/annotation, vulnerability type, CWE mapping, severity level, and which argument positions are tainted.

**Key design patterns:**
- Taint tracking from sources to sinks with sanitizer support
- Annotation-based source detection (Spring: @RequestParam, @RequestBody; JAX-RS: @QueryParam, @PathParam)
- Severity levels: critical, high, medium, low

## Key Analysis Components

1. **Constant Propagation Engine** (`src/analysis/constant-propagation.ts`)
   - Tracks variable values through assignments
   - Detects dead code via condition evaluation
   - Per-key collection taint tracking (map.put/map.get)
   - **List index tracking**: Precisely tracks list.add/remove/get operations with index shifting
   - Iterative refinement with fixpoint approach
   - Conservative taint preservation in conditional branches
   - **Inter-procedural analysis**: Tracks methods that always return constants, sanitized values, or their parameters

2. **Taint Flow Analysis** (`src/analysis/taint-propagation.ts`)
   - Source-to-sink path detection
   - Integration with constant propagation for false positive elimination
   - Sanitizer recognition (PreparedStatement, ESAPI, escapeHtml, etc.)
   - Array taint propagation (e.g., `{param}` initializer)

3. **DFG Verifier** (`src/analysis/dfg-verifier.ts`)
   - Verifies data flow paths between sources and sinks
   - Used for flow confirmation

4. **Path Finder** (`src/analysis/path-finder.ts`)
   - Finds taint paths through the DFG
   - Generates human-readable path descriptions

## Circle-IR Specification

The IR format is defined in `docs/SPEC.md` (Circle-IR 3.0). Key structures:

- **Meta** - File metadata, language, LOC, hash
- **Types** - Classes, interfaces, enums with methods and fields
- **Calls** - Method invocations with arguments and receivers
- **CFG** - Control flow graph (blocks + edges)
- **DFG** - Data flow graph (defs + uses)
- **Taint** - Sources, sinks, and sanitizers
- **Imports/Exports** - Cross-file resolution

The spec includes an Implementation Status table tracking Python (reference) vs TypeScript (this repo) progress. Update the TypeScript column when implementing features.

**Implementation phases from spec:**
1. **Phase 1 (Core)**: Meta, Types, Calls, CFG, DFG, Taint sources/sinks, Imports
2. **Phase 2 (Enhanced)**: Exports, Call resolution, Sanitizers, DFG chains
3. **Phase 3 (LLM Integration)**: Unresolved items, Enriched metadata, Findings
4. **Phase 4 (Project-Level)**: Cross-file analysis, Type hierarchy, Taint paths

## Test Coverage

- 572 tests passing
- 75%+ coverage required
- See `TODO.md` for areas needing additional test coverage

## Architecture Review Checklist

When reviewing or modifying circle-ir, verify these requirements:

### Independence (Critical)
- [ ] **No AI/LLM dependencies** - circle-ir must NOT depend on circle-ir-ai, OpenAI, Anthropic, or any LLM libraries
- [ ] **No cross-package imports** - Only import from within circle-ir, never from circle-ir-ai or circle-pack
- [ ] **Minimal dependencies** - Only allowed: `web-tree-sitter`, `yaml`, `pino` (logging)

### Language Abstraction
- [ ] **Plugin-based architecture** - All language-specific code in `src/languages/plugins/`
- [ ] **No hardcoded language checks** in core analysis (except necessary AST handling)
- [ ] **Configuration-driven** - Source/sink patterns in `configs/`, not hardcoded

### Code Quality
- [ ] **No dead code** - Remove unused exports, commented code blocks, unused files
- [ ] **No temporary files** - No `.tmp`, `.temp`, `.bak` files committed
- [ ] **No build artifacts** - `dist/`, `*.tgz`, `coverage/` must be gitignored

### Documentation
- [ ] **README.md** - API documentation and usage examples
- [ ] **docs/SPEC.md** - Circle-IR specification (update Implementation Status when adding features)
- [ ] **docs/ARCHITECTURE.md** - System design and ADRs
- [ ] **CHANGELOG.md** - Version history with semver
- [ ] **TODO.md** - Pending improvements and known issues

### Testing
- [ ] **Coverage ≥75%** - Run `npm run test:coverage` to verify
- [ ] **All tests pass** - Run `npm test` before committing
- [ ] **Key areas tested** - See TODO.md for coverage gaps to address

### Release Readiness
- [ ] **Semver compliance** - Version in package.json follows semantic versioning
- [ ] **npm-ready** - package.json has: name, version, description, main, types, exports, repository, license
- [ ] **Clean build** - `npm run build:all` succeeds without errors

## Language Support Priorities

Current language support status (see TODO.md for details):

| Priority | Language | Status | Next Steps |
|----------|----------|--------|------------|
| - | Java | Complete | Maintenance only |
| - | JavaScript/TS | Complete | Maintenance only |
| P1 | Python | Partial | Add Django, Flask, FastAPI patterns |
| P3 | Rust | Partial | Add Axum, SQLx patterns |

## Common Tasks

### Adding a New Taint Source
1. Add pattern to `configs/sources/<framework>.yaml` or create new file
2. Include: method/class, taint type, severity, CWE mapping
3. Add test case in `tests/` directory
4. Update TODO.md if part of a larger effort

### Adding a New Taint Sink
1. Add pattern to `configs/sinks/<category>.yaml` (sql, command, xss, path, etc.)
2. Include: method signature, CWE, severity, vulnerable argument positions
3. Add test case in `tests/` directory
4. Update CHANGELOG.md

### Adding Language Support
1. Create plugin in `src/languages/plugins/<language>.ts` extending `BaseLanguagePlugin`
2. Add Tree-sitter WASM grammar to `wasm/` directory
3. Create source configs in `configs/sources/<language>.json`
4. Create sink configs in `configs/sinks/<language>.json`
5. Add comprehensive tests
6. Update TODO.md with completion status
