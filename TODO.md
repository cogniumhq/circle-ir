# TODO - circle-ir

This file tracks pending improvements and known issues for the circle-ir core library.

## Priority Legend
- **P0**: Critical - blocks release
- **P1**: High - should be done soon
- **P2**: Medium - nice to have
- **P3**: Low - future improvement

---

## Architecture

### Completed

- [x] **CodeGraph abstraction** (`src/graph/code-graph.ts`) — lazy Map indexes built once per analysis; eliminates duplicate index-building that previously existed independently in `taint-propagation.ts`, `dfg-verifier.ts`, `path-finder.ts`, `interprocedural.ts`. O(N) scan in `interprocedural.ts` hot loop replaced with `graph.usesAtLine()`.
- [x] **AnalysisPass interface + AnalysisPipeline** (`src/graph/analysis-pass.ts`) — 6 sequential typed passes; `analyzer.ts` reduced from ~2100 to ~610 lines. Passes: `TaintMatcherPass`, `ConstantPropagationPass`, `LanguageSourcesPass`, `SinkFilterPass`, `TaintPropagationPass`, `InterproceduralPass`.
- [x] **Cross-file analysis wired** (`src/graph/project-graph.ts`, `src/analysis/passes/cross-file-pass.ts`) — `ProjectGraph` wraps multiple `CodeGraph` instances with lazy `SymbolTable`, `TypeHierarchyResolver`, `CrossFileResolver`. `analyzeProject()` public API returns `ProjectAnalysis` with type hierarchy, cross-file calls, and taint paths.

### Pending

- [ ] **P2**: TypeHierarchy integration into taint matching (Phase 4) — pass `TypeHierarchyResolver` to `TaintMatcherPass` for Java; `PreparedStatement.execute()` correctly matched as subtype of `Statement.execute()` without duplicating sink configs. See `src/resolution/type-hierarchy.ts` (`couldBeType()`).
- [ ] **P2**: Pass-level unit tests (`tests/analysis/passes/*.test.ts`) — each of the 6 passes is independently testable with a minimal `PassContext`; currently only exercised end-to-end via `analyzer.test.ts`.

---

## Test Coverage Improvements

Current overall coverage: ~77%. Target: ≥75% (met).
`src/resolution/**` is excluded from coverage metrics — it is exercised by integration tests in `tests/analysis/project-graph.test.ts`.

| File | Coverage | Priority | Notes |
|------|----------|----------|-------|
| `src/languages/plugins/bash.ts` | ~60% | P2 | Bash language plugin |
| `src/languages/plugins/python.ts` | ~13% | P2 | Python plugin; most paths reachable only with real Python IR |
| `src/languages/plugins/rust.ts` | ~13% | P3 | Rust plugin; low usage |

### Test Tasks

- [ ] **P2**: Add tests for Bash plugin edge cases (command substitution, here-docs)
- [ ] **P2**: Add tests for `dfg.ts` inter-procedural data flow
- [ ] **P2**: Add pass-level unit tests for the 6 AnalysisPass implementations

---

## Language Support

### Current Status

| Language | Benchmark Score | Sources/Sinks Coverage | Priority |
|----------|-----------------|------------------------|----------|
| Java | 100% OWASP, 100% Juliet | ✅ Complete (Spring, JAX-RS, Servlet) | Maintenance |
| JavaScript/TS | 100% NodeGoat | ✅ Complete (Express, Fastify, Koa, Prisma) | P2 additions |
| Python | 63.8% CWE-Bench | ✅ Complete (Flask, Django, FastAPI) | P2 improvements |
| Rust | 100% CWE-Bench | ⚠️ Partial (needs Axum, SQLx) | P3 |
| Bash/Shell | 68.2% TPR, 0% FPR | ⚠️ Basic (read source only) | P2 |
| Go | - | ❌ Not started | P3 |

### Pending Language Improvements

#### Python (Complete — 63.8% on CWE-Bench-Java)
- [x] Add Django source patterns (request.GET, request.POST, request.FILES)
- [x] Add Flask source patterns (request.args, request.form, request.json)
- [x] Add FastAPI source patterns (query_params, path_params)
- [x] Add Flask sink patterns (render_template_string, subprocess)
- [x] Add SQLAlchemy sink patterns (text(), execute())
- [x] Add XPath injection detection with apostrophe sanitizer recognition
- [x] Add trust boundary violation detection (flask.session writes)
- [ ] Add Jinja2 XSS sink patterns (P2)
- [ ] Add MyBatis/Django ORM additional raw query patterns (P2)

#### JavaScript/TypeScript (P2 - Medium Priority)
- [x] Add Fastify source/sink patterns
- [x] Add Koa source/sink patterns
- [x] Add Prisma ORM unsafe raw query sinks
- [ ] Add Next.js API route patterns (P2)
- [ ] Add TypeORM sink patterns (P2)
- [ ] **P2**: Narrow `.value` dom_input source pattern to require DOM context (currently matches any `.value` property access, causing FPs on internal objects like `ConstantValue.value`)
- [ ] **P3**: Add constant-propagation awareness to `new Function()` sink detection (suppress when all arguments are string literals)

#### Rust (P3 - Lower Priority)
- [ ] Add Axum framework patterns
- [ ] Add SQLx sink patterns
- [ ] Add Reqwest SSRF patterns
- [ ] Add Serde deserialization patterns

#### Java (P3 - Maintenance)
- [ ] Add Micronaut framework patterns
- [ ] Add Quarkus framework patterns
- [ ] Add MyBatis sink patterns

---

## Code Quality

### Cleanup Tasks

- [ ] **P1**: Add `*.tgz` to .gitignore (npm pack artifacts)
- [ ] **P2**: Remove or document `advisory-db.json` (1.1MB file)
- [ ] **P2**: Implement type resolution TODO in `java.ts:line 427`

### Documentation

- [x] README.md - API documentation
- [x] docs/SPEC.md - Circle-IR specification
- [x] docs/ARCHITECTURE.md - System architecture
- [x] CONTRIBUTING.md - Contribution guidelines
- [x] CHANGELOG.md - Version history
- [x] CLAUDE.md - AI assistant guidance
- [x] TODO.md - This file

---

## Release Checklist

Before any release:

- [ ] All tests pass (`npm test`)
- [ ] Coverage ≥75% (`npm run test:coverage`)
- [ ] TypeScript compiles (`npm run typecheck`)
- [ ] Build succeeds (`npm run build:all`)
- [ ] CHANGELOG.md updated
- [ ] Version bumped in package.json (semver)
- [ ] No temporary files committed

---

## Future Considerations

### P3 - Long Term

- [ ] Support for Go language (P3 - tree-sitter-go available on npm when ready)
- [ ] Support for C/C++ (limited - no GC tracking)
- [ ] Support for PHP
- [ ] Support for Ruby
- [ ] WebAssembly optimization for browser bundle
- [ ] Streaming analysis for large files
- [ ] Incremental analysis (cache unchanged files)

---

*Last updated: 2026-03-25*
