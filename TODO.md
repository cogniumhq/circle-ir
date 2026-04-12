# TODO - circle-ir

Working plan and task tracker for the circle-ir SAST library.

**Canonical pass/metric reference:** [`docs/PASSES.md`](docs/PASSES.md)
**Scope:** SAST analysis + metrics only. LLM, clustering, semantic understanding → circle-ir-ai.

---

## Phase Overview

| Phase | Status | Focus |
|-------|--------|-------|
| 0 — Architecture foundation | ✅ Complete | CodeGraph, AnalysisPipeline, ProjectGraph, taxonomy types |
| 1 — High-impact SAST passes | ✅ Complete | All 17 passes done (Groups 1-4, v3.9.4) |
| 2 — Metrics engine | ✅ Complete | MetricRunner, 24 metrics (core 20 + 4 composite), wired into `analyze()` (v3.9.5) |
| 4 — Advanced graphs + passes | Pending | Dominator tree, exception flow, type hierarchy wired |

> Phase 3 (LLM passes) and Phase 5 (semantic understanding) are circle-ir-ai scope.
> Phase numbering matches COGNIUM_IMPLEMENTATION_GUIDE §10.

---

## Phase 0 — Architecture Foundation ✅ Complete

All items complete. 1013/1013 tests passing.

- [x] **CodeGraph** (`src/graph/code-graph.ts`) — lazy Map indexes; `loopBodies()` via CFG back-edges
- [x] **AnalysisPass interface + AnalysisPipeline** — 6 passes, `category: PassCategory`, `context.addFinding()`, `PipelineRunResult { results, findings }`
- [x] **ProjectGraph + CrossFilePass + `analyzeProject()`** — cross-file taint paths, type hierarchy, inter-file calls
- [x] **Taxonomy types** (`src/types/index.ts`) — `PassCategory`, `SastFinding` (SARIF 2.1.0 + CWE), `MetricCategory`, `MetricValue` (CK suite + Halstead + McCabe), `FileMetrics`; `CircleIR.findings?`, `CircleIR.metrics?`

---

## Phase 1 — High-Impact SAST Passes ✅ Complete

**Goal:** Every developer sees value on first scan. All passes use existing graphs or one new cheap graph.

### Group 1: 5 quick wins (existing graphs only) ✅ Done (v3.9.1)

Passes that need only `ast` and/or `cfg` — no new graph required.

- [x] **#22 `dead-code`** (CWE-561, warning) — CFG block unreachable from entry
- [x] **#24 `missing-await`** (CWE-252, warning) — async call without `await`, Promise discarded
- [x] **#45 `n-plus-one`** (CWE-1049, warning) — DB/API call inside `loopBodies()`
- [x] **#35 `missing-public-doc`** (—, note) — exported function/type with no doc block
- [x] **#36 `todo-in-prod`** (—, note) — TODO/FIXME/HACK in non-test file

### Group 2: 5 reliability + performance passes ✅ Done (v3.9.2)

- [x] **#20 `null-deref`** (CWE-476, error) — nullable source → dereference, no null guard on all CFG paths
- [x] **#21 `resource-leak`** (CWE-772, error) — resource opened, not closed on exception exit path
- [x] **#28 `unchecked-return`** (CWE-252, warning) — return value ignored; majority of callers check it
- [x] **#48 `sync-io-async`** (CWE-1050, warning) — blocking I/O inside async function
- [x] **#50 `string-concat-loop`** (CWE-1046, warning) — `string +=` inside `loopBodies()`

### Group 3: Scope graph + 3 passes ✅ Done (v3.9.3)

- [x] Build `src/graph/scope-graph.ts` — `ScopeGraph` with declaration-keyword awareness; `defsInMethod()` + `hasDeclaredDef()`
- [x] **#79 `variable-shadowing`** (CWE-1109, warning) — inner scope re-declares outer name
- [x] **#81 `leaked-global`** (CWE-1109, warning) — assignment without declaration (JS/TS accidental global)
- [x] **#82 `unused-variable`** (CWE-561, note) — declared, no reads on any reachable path

### Group 4: Import graph + 4 passes ✅ Done (v3.9.4)

New graph: **import/module graph** (file → imported files, from `CircleIR.imports`; cross-file via `ProjectGraph`).

- [x] Build `src/graph/import-graph.ts` — `ImportGraph` wrapping per-file imports into a directed graph; Tarjan's SCC for cycle detection
- [x] **#68 `circular-dependency`** (CWE-1047, warning) — cycle in module import graph
- [x] **#71 `orphan-module`** (—, note) — file with no incoming imports and not an entry point
- [x] **#72 `dependency-fan-out`** (—, note) — module imports 20+ other modules
- [x] **#33 `stale-doc-ref`** (—, note) — doc comment references symbol not in scope/imports

### Phase 1 Gate
Scan 5 real-world repos. New passes must find real issues with ≤5% false positives per category.

---

## Phase 2 — Metrics Engine ✅ Complete

**Goal:** Turn findings into quantitative scores. Core 20 metrics + 4 composite scores.

All items complete (v3.9.5). 1013/1013 tests passing.

- [x] **MetricRunner** (`src/analysis/metrics/metric-runner.ts`) — orchestrates 9 metric passes; each pass receives `accumulated` results from prior passes
- [x] Add `metrics?` population to `analyze()` — `ir.metrics: FileMetrics` is now always populated
- [x] **Complexity metrics** — `cyclomatic_complexity` (v(G) per method), `WMC`, `loop_complexity`, `condition_complexity`, Halstead suite (`halstead_volume`, `halstead_difficulty`, `halstead_effort`, `halstead_bugs`), `data_flow_complexity`
- [x] **Size metrics** — `LOC`, `NLOC`, `comment_density`, `function_count`
- [x] **Coupling metrics** — `CBO`, `RFC`, `CBO_avg`, `RFC_avg`
- [x] **Inheritance metrics** — `DIT`, `NOC`, `DIT_max`, `NOC_total`
- [x] **Cohesion metrics** — `LCOM`, `LCOM_avg`
- [x] **Documentation metric** — `doc_coverage`
- [x] **4 composite scores** — `maintainability_index`, `code_quality_index`, `bug_hotspot_score`, `refactoring_roi`

Pending (Phase 2 extensions, lower priority):
- [ ] Remaining complexity metrics: `cognitive_complexity`, `nesting_depth_max/avg`, `path_count`, `variable_liveness_span`, `fan_in/out_data`, `state_mutation_count`
- [ ] Remaining size metrics: `parameter_count`, `statements`
- [ ] Remaining coupling metrics: `Ca`, `Ce`, `instability`, `import_depth`, `dep_graph_density`, `api_surface_ratio`, `internal_reuse`, `module_cycle_count`
- [ ] Remaining cohesion metrics: `LCOM4`, `TCC`
- [ ] Duplication metrics: `duplicate_ratio`, `clone_count`
- [ ] `cognium metrics` CLI command (`cognium metrics ./src --format json`)

See `docs/PASSES.md §G` for complete metric name/formula reference.

---

## Phase 4 — Advanced Graphs + Passes

Requires new graphs: **dominator tree**, **exception flow graph**, **type hierarchy wired into taint matching**.
Numbers follow COGNIUM_IMPLEMENTATION_GUIDE §10 Week 12-14.

### New graphs

- [x] **Dominator tree** (`src/graph/dominator-graph.ts`) — Cooper et al. algorithm; `dominates(a, b)`, `strictlyDominates(a, b)`, `immediateDominator(n)`, `dominated(n)` (done in v3.9.8)
- [x] **Exception flow graph** (`src/graph/exception-flow-graph.ts`) — try/catch CFG edge indexing; `ExceptionFlowGraph` class (done in v3.9.9)
- [x] **TypeHierarchy wired to taint matching** — pass `TypeHierarchyResolver` to `TaintMatcherPass`; `PreparedStatement.execute()` matched as subtype of `Statement.execute()` without duplicate configs (see `src/resolution/type-hierarchy.ts:couldBeType()`) (done in v3.11.0)

### Reliability passes (dominator + exception)

- [x] **#23 `infinite-loop`** (CWE-835) — CFG cycle with no exit edge (done in v3.9.8)
- [x] **#25 `double-close`** (CWE-675) — resource `close()` reachable on 2+ paths that both execute (done in v3.9.9)
- [x] **#26 `use-after-close`** (CWE-672) — read of variable after the resource was released (done in v3.9.9)
- [x] **#53 `missing-guard-dom`** (CWE-285) — auth check doesn't dominate sensitive operation (done in v3.11.0)
- [x] **#54 `cleanup-verify`** (CWE-772) — resource cleanup doesn't post-dominate acquisition (done in v3.11.0)
- [x] **#74 `unhandled-exception`** (CWE-390) — throw/raise not covered by any try/catch (JS/TS, Python) (done in v3.9.9)
- [x] **#75 `broad-catch`** (CWE-396) — `catch(Exception)` / bare except (Java, Python) (done in v3.9.9)
- [x] **#76 `swallowed-exception`** (CWE-390) — catch block: no re-throw, no log, no error return (done in v3.9.9)

### Performance passes (existing graphs)

- [x] **#46 `redundant-loop-computation`** (CWE-1050) — loop-invariant `.length`/`.size()`/`Math.*` (done in v3.9.8)
- [x] **#47 `unbounded-collection`** (CWE-770) — collection grows in loop with no size check (done in v3.9.8)
- [x] **P22 `serial-await`** (—) — sequential awaits with no data dependency, JS/TS only (done in v3.9.8)
- [x] **P33 `react-inline-jsx`** (—) — inline object/function in JSX props (done in v3.9.8)

### Architecture passes (type hierarchy)

- [x] **#62 `deep-inheritance`** (CWE-1086) — inheritance depth > 5 levels (done in v3.9.8)
- [x] **#64 `missing-override`** (—) — method matches supertype signature, lacks `@Override` (done in v3.11.0)
- [x] **#66 `unused-interface-method`** (—) — interface method never called through that interface (done in v3.11.0)

---

## Ongoing: Architecture Improvements

### Completed

- [x] **P2**: Pass-level unit tests (`tests/analysis/passes/*.test.ts`) — each pass testable with minimal `PassContext` fixture
- [x] **P2**: `ScopeGraph` implementation for Phase 1 Group 3 (done in v3.9.3)
- [x] **P2**: `ImportGraph` implementation for Phase 1 Group 4 (done in v3.9.4)
- [x] **P2**: Implement type resolution TODO in `src/languages/plugins/java.ts` — `buildVarTypeMap` + `WeakMap` cache (done in v3.12.0)

### Unified CodeGraph Refactor (low priority)

**Status: NOT BUILT.** `CodeGraph` today is a lazy index wrapper over `CircleIR` — it provides
query helpers (`defsAtLine()`, `callsAtLine()`, `loopBodies()`) but is not a true unified graph.
Passes still build separate graph structures independently.

**Current state — 6 disjoint graph classes:**

| Graph | Location | Built by |
|---|---|---|
| `CodeGraph` | `src/graph/code-graph.ts` | Once per file in `analyze()` — lazy indexes over IR |
| `DominatorGraph` | `src/graph/dominator-graph.ts` | On-demand per pass (missing-guard-dom, cleanup-verify) |
| `ExceptionFlowGraph` | `src/graph/exception-flow-graph.ts` | On-demand per pass (broad-catch, unhandled-exception, swallowed-exception) |
| `ScopeGraph` | `src/graph/scope-graph.ts` | On-demand per pass (variable-shadowing, leaked-global) |
| `ProjectGraph` | `src/graph/project-graph.ts` | Multi-file analysis wrapper |
| `ImportGraph` | `src/graph/import-graph.ts` | Tarjan SCC for circular deps, orphan modules |

**What the full refactor would do:**

- [ ] **Typed edge store** — single edge abstraction with ~15 types (`ast`, `controls`, `dataFlows`, `calls`, `taints`, `dominates`, `throws`, `inherits`, etc.) instead of separate graph classes
- [ ] **Shared graph instances** — `DominatorGraph`, `ExceptionFlowGraph`, `ScopeGraph` built once per file and cached on `CodeGraph`, not rebuilt by each pass
- [ ] **AST integration** — Tree-sitter AST nodes accessible through CodeGraph (currently passed separately to constant propagation)
- [ ] **Unified query API** — single entry point for all graph queries instead of `graph.ir.cfg` + `new DominatorGraph(cfg)` + `new ExceptionFlowGraph(cfg, ...)` etc.

**Why it's deferred:** All 36+ passes work fine with current structures. ~1,500 LOC refactor for cleaner internals but no new analysis capabilities. Purely a developer-ergonomics improvement for circle-ir contributors.

---

## Ongoing: Test Coverage

Current coverage: 86.56% stmts / 73.09% branches / 91.28% functions / 88.85% lines. Target: ≥75% stmts (met).
`src/resolution/**` is excluded — exercised via `tests/analysis/project-graph.test.ts`.

| File | Coverage | Priority | Notes |
|------|----------|----------|-------|
| `src/languages/plugins/bash.ts` | improved | ✅ done | `bash-coverage.test.ts` added in v3.12.0 |
| `src/languages/plugins/python.ts` | improved | ✅ done | `python-ir.test.ts` added in v3.12.0 |
| `src/languages/plugins/rust.ts` | ~13% | P3 | Rust plugin — low usage |

- [x] **P2**: Add tests for Bash plugin edge cases (done in v3.12.0 — `tests/languages/bash-coverage.test.ts`)
- [x] **P2**: Add tests for `dfg.ts` inter-procedural data flow (done in v3.12.0 — `tests/analysis/interprocedural.test.ts`)

---

## Ongoing: Language Support

### Current Status

| Language | Benchmark | Sources/Sinks | Priority |
|----------|-----------|---------------|----------|
| Java | 100% OWASP, 100% Juliet | ✅ Complete (Spring, JAX-RS, Servlet) | Maintenance |
| JavaScript/TS | 100% NodeGoat | ✅ Complete (Express, Fastify, Koa, Prisma) | P2 additions |
| Python | 63.8% CWE-Bench | ✅ Complete (Flask, Django, FastAPI) | P2 improvements |
| Rust | 100% CWE-Bench | ⚠️ Partial (needs Axum, SQLx) | P3 |
| Bash/Shell | 68.2% TPR, 0% FPR | ⚠️ Basic (read source only) | P2 |

### Pending Language Additions

**Python (P2):**
- [ ] Add Jinja2 XSS sink patterns
- [ ] Add MyBatis/Django ORM additional raw query patterns

**JavaScript/TypeScript (P2):**
- [ ] Add Next.js API route patterns
- [ ] Add TypeORM sink patterns
- [ ] Narrow `.value` dom_input source to require DOM context (FP on `ConstantValue.value`)
- [ ] P3: Constant-propagation awareness for `new Function()` sink (suppress all-literal args)

**Java (P3):**
- [ ] Add Micronaut framework patterns
- [ ] Add Quarkus framework patterns
- [ ] Add MyBatis sink patterns

**Rust (P3):**
- [ ] Add Axum framework patterns
- [ ] Add SQLx sink patterns
- [ ] Add Reqwest SSRF patterns

---

## Release Checklist

Before any release:

- [ ] All tests pass (`npm test`)
- [ ] Coverage ≥75% (`npm run test:coverage`)
- [ ] TypeScript compiles (`npm run typecheck`)
- [ ] Build succeeds (`npm run build:all`)
- [ ] `docs/PASSES.md` updated with any new pass status changes
- [ ] `CHANGELOG.md` updated
- [ ] Version bumped in `package.json` (semver)
- [ ] No temporary files committed

---

*Last updated: 2026-04-08*
