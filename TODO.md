# TODO - circle-ir

Working plan and task tracker for the circle-ir SAST library.

**Canonical pass/metric reference:** [`docs/PASSES.md`](docs/PASSES.md)
**Scope:** SAST analysis + metrics only. LLM, clustering, semantic understanding → circle-ir-ai.

---

## Phase Overview

| Phase | Status | Focus |
|-------|--------|-------|
| 0 — Architecture foundation | ✅ Complete | CodeGraph, AnalysisPipeline, ProjectGraph, taxonomy types |
| 1 — High-impact SAST passes | 🔄 In Progress | Groups 1-3 done (13 passes); Group 4 pending |
| 2 — Metrics engine | Pending | MetricRunner, 38 metrics, `cognium metrics` command |
| 4 — Advanced graphs + passes | Pending | Dominator tree, exception flow, type hierarchy wired |

> Phase 3 (LLM passes) and Phase 5 (semantic understanding) are circle-ir-ai scope.
> Phase numbering matches COGNIUM_IMPLEMENTATION_GUIDE §10.

---

## Phase 0 — Architecture Foundation ✅ Complete

All items complete. 921/921 tests passing.

- [x] **CodeGraph** (`src/graph/code-graph.ts`) — lazy Map indexes; `loopBodies()` via CFG back-edges
- [x] **AnalysisPass interface + AnalysisPipeline** — 6 passes, `category: PassCategory`, `context.addFinding()`, `PipelineRunResult { results, findings }`
- [x] **ProjectGraph + CrossFilePass + `analyzeProject()`** — cross-file taint paths, type hierarchy, inter-file calls
- [x] **Taxonomy types** (`src/types/index.ts`) — `PassCategory`, `SastFinding` (SARIF 2.1.0 + CWE), `MetricCategory`, `MetricValue` (CK suite + Halstead + McCabe), `FileMetrics`; `CircleIR.findings?`, `CircleIR.metrics?`

---

## Phase 1 — High-Impact SAST Passes 🔄 In Progress

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

### Group 4: Import graph + 4 passes (~200 LOC graph + ~560 LOC passes)

New graph: **import/module graph** (file → imported files, from `CircleIR.imports`; cross-file via `ProjectGraph`).

- [ ] Build `src/graph/import-graph.ts` — `ImportGraph` wrapping per-file imports into a directed graph; Tarjan's SCC for cycle detection
- [ ] **#68 `circular-dependency`** (CWE-1047, warning) — cycle in module import graph
- [ ] **#71 `orphan-module`** (—, note) — file with no incoming imports and not an entry point
- [ ] **#72 `dependency-fan-out`** (—, note) — module imports 20+ other modules
- [ ] **#33 `stale-doc-ref`** (—, note) — doc comment references symbol not in scope/imports

### Phase 1 Gate
Scan 5 real-world repos. New passes must find real issues with ≤5% false positives per category.

---

## Phase 2 — Metrics Engine

**Goal:** Turn findings into quantitative scores. Add `cognium metrics` command.

- [ ] **MetricRunner** — orchestrates metric computation, outputs `FileMetrics[]` per file
- [ ] Add `metrics?` population to `analyze()` and `analyzeProject()` return values
- [ ] **Complexity metrics** (17 metrics) — `v(G)`, `cognitive_complexity`, `nesting_depth_max/avg`, `path_count`, `loop_complexity`, `condition_complexity`, Halstead suite, `data_flow_complexity`, `variable_liveness_span`, `fan_in/out_data`, `state_mutation_count`
- [ ] **Size metrics** (7 metrics) — `LOC`, `NLOC`, `comment_density`, `WMC`, `function_count`, `parameter_count`, `statements`
- [ ] **Coupling metrics** (10 metrics) — `CBO`, `RFC`, `Ca`, `Ce`, `instability`, `import_depth`, `dep_graph_density`, `api_surface_ratio`, `internal_reuse`, `module_cycle_count`
- [ ] **Inheritance metrics** (2 metrics) — `DIT`, `NOC`
- [ ] **Cohesion metrics** (3 metrics) — `LCOM`, `LCOM4`, `TCC`
- [ ] **Documentation metric** — `doc_coverage`
- [ ] **Duplication metrics** (2 metrics) — `duplicate_ratio`, `clone_count`
- [ ] **4 composite scores** — `maintainability_index`, `code_quality_index`, `bug_hotspot_score`, `refactoring_roi`

See `docs/PASSES.md §G` for complete metric name/formula reference.

### Phase 2 Gate
`cognium metrics ./src --format json` produces valid `FileMetrics[]`. Composite scores tell a compelling story alongside Phase 1 findings.

---

## Phase 4 — Advanced Graphs + Passes

Requires new graphs: **dominator tree**, **exception flow graph**, **type hierarchy wired into taint matching**.
Numbers follow COGNIUM_IMPLEMENTATION_GUIDE §10 Week 12-14.

### New graphs

- [ ] **Dominator tree** (`src/graph/dominator-graph.ts`) — Lengauer-Tarjan from CFG; `dominates(a, b)`, `postDominates(a, b)`, `immediateDominator(n)`
- [ ] **Exception flow graph** (`src/graph/exception-graph.ts`) — throw → catch edges; uncaught propagation via call graph
- [ ] **TypeHierarchy wired to taint matching** — pass `TypeHierarchyResolver` to `TaintMatcherPass`; `PreparedStatement.execute()` matched as subtype of `Statement.execute()` without duplicate configs (see `src/resolution/type-hierarchy.ts:couldBeType()`)

### Reliability passes (dominator + exception)

- [ ] **#23 `infinite-loop`** (CWE-835) — CFG cycle with no exit edge dependent on mutable state
- [ ] **#25 `double-close`** (CWE-675) — resource `close()` reachable on 2+ paths that both execute
- [ ] **#26 `use-after-close`** (CWE-672) — read of variable after the resource was released
- [ ] **#53 `missing-guard-dom`** (—) — auth check doesn't dominate sensitive operation
- [ ] **#54 `cleanup-verify`** (CWE-772) — resource cleanup doesn't post-dominate acquisition
- [ ] **#74 `unhandled-exception`** (CWE-390) — exception propagates through call chain with no catch
- [ ] **#75 `broad-catch`** (CWE-396) — `catch(Exception)` when only subtypes are thrown
- [ ] **#76 `swallowed-exception`** (CWE-390) — catch block: no re-throw, no log, no error return

### Performance passes (existing graphs)

- [ ] **#46 `redundant-loop-computation`** (CWE-1050) — loop-invariant expression computed every iteration
- [ ] **#47 `unbounded-collection`** (CWE-770) — collection grows in loop with no size check
- [ ] **P22 `serial-await`** (—) — sequential awaits with no data dependency (use Promise.all)
- [ ] **P33 `react-inline-jsx`** (—) — inline object/function in JSX props (defeats React.memo)

### Architecture passes (type hierarchy)

- [ ] **#62 `deep-inheritance`** (CWE-1086) — inheritance depth > 5 levels
- [ ] **#64 `missing-override`** (—) — method matches supertype signature, lacks `@Override`
- [ ] **#66 `unused-interface-method`** (—) — interface method never called through that interface

---

## Ongoing: Architecture Improvements

- [ ] **P2**: Pass-level unit tests (`tests/analysis/passes/*.test.ts`) — each pass testable with minimal `PassContext` fixture; currently only exercised end-to-end
- [ ] **P2**: `ScopeGraph` implementation for Phase 1 Group 3 (above)
- [ ] **P2**: `ImportGraph` implementation for Phase 1 Group 4 (above)
- [ ] **P2**: Implement type resolution TODO in `src/languages/plugins/java.ts:427`

---

## Ongoing: Test Coverage

Current coverage: ~77%. Target: ≥75% (met).
`src/resolution/**` is excluded — exercised via `tests/analysis/project-graph.test.ts`.

| File | Coverage | Priority | Notes |
|------|----------|----------|-------|
| `src/languages/plugins/bash.ts` | ~60% | P2 | Bash language plugin |
| `src/languages/plugins/python.ts` | ~13% | P2 | Python plugin — needs real Python IR fixtures |
| `src/languages/plugins/rust.ts` | ~13% | P3 | Rust plugin — low usage |

- [ ] **P2**: Add tests for Bash plugin edge cases (command substitution, here-docs)
- [ ] **P2**: Add tests for `dfg.ts` inter-procedural data flow

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

## Code Quality

- [ ] **P2**: Remove or document `advisory-db.json` (1.1 MB file — purpose unclear)

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

*Last updated: 2026-03-25*
