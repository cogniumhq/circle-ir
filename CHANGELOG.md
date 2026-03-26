# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.9.3] - 2026-03-25

### Added

- **Phase 1 Group 3: three new analysis passes + ScopeGraph infrastructure** — all wired into the 19-pass pipeline:
  - **`ScopeGraph`** (`src/graph/scope-graph.ts`) — thin wrapper over `CodeGraph` that enriches each `DFGDef` with `hasDeclKeyword` (whether the source line contains a declaration keyword such as `let`/`const`/`var` in JS/TS, type keywords in Java, `let` in Rust) and `methodStart`/`methodEnd` bounds. Provides `defsInMethod()` and `hasDeclaredDef()` helpers used by all three Group-3 passes.
  - **`VariableShadowingPass`** (`variable-shadowing`, CWE-1109, reliability, medium/warning) — for each method, groups DFG defs by variable name and detects: (1) **param shadow** — a `kind='param'` def + a later `kind='local'` def with a declaration keyword (or Python, which has no keywords); (2) **outer-local shadow** — two `kind='local'` defs that both have a declaration keyword, flagging the later one.
  - **`LeakedGlobalPass`** (`leaked-global`, CWE-1109, reliability, medium/warning) — JS/TS only; flags bare assignments (`x = 5`) inside function bodies where the variable has no `let`/`const`/`var` declaration anywhere in the enclosing function. Skips `_`-prefixed names and common skip-list names (`err`, `e`, `i`, `j`, etc.).
  - **`UnusedVariablePass`** (`unused-variable`, CWE-561, reliability, low/note) — flags `kind='local'` DFG defs where `graph.usesOfDef(def.id)` is empty, meaning the assigned value is never read. Skips `_`-prefixed names, skip-list names, catch-block variables, and test files.
- **Test count**: 897 → 921 (+24 new pass unit tests across 3 new test files)

## [3.9.2] - 2026-03-25

### Added

- **Phase 1 Group 2: five new analysis passes** — all emit `SastFinding[]` via `PassContext.addFinding()`, wired into the 16-pass pipeline:
  - **`NullDerefPass`** (`null-deref`, CWE-476, reliability, high/error) — finds DFG defs explicitly assigned `null`/`None`/`undefined`, then flags downstream uses (call receivers and field accesses) with no null guard between def and use. Language filter: Java, JS/TS, Python only (Rust/Bash skipped). Guard detection covers `!= null`, `!== null`, `is not None`, `if (x)`, `if x:`, `?.` optional chaining.
  - **`ResourceLeakPass`** (`resource-leak`, CWE-772, reliability, high/error or medium/warning) — detects 24 resource constructor types (`FileInputStream`, `Socket`, `BufferedReader`, …) and 12 factory methods (`open`, `createReadStream`, …). Definite leak (no `close()` at all) → high/error. Close without `finally` block → medium/warning. Recognizes Java try-with-resources (`try (`) and Python context managers (`with open(`) as safe.
  - **`UncheckedReturnPass`** (`unchecked-return`, CWE-252, reliability, medium/warning) — two-tier curated list: HIGH confidence (always flag: `createNewFile`, `mkdir`, `mkdirs`, `delete`, `tryLock`, `tryAcquire`, `compareAndSet`, `find`); MEDIUM confidence (flag only when receiver name matches file patterns: `renameTo`, `setExecutable`, `setReadable`, `setWritable`). Skips lines where result is captured in a DFG def or appears in conditional context (`if (`, `while (`, `assert`, `?`, `||`, `&&`).
  - **`SyncIoAsyncPass`** (`sync-io-async`, CWE-1050, performance, medium/warning) — JS/TS/Python only; flags any call whose name ends in `Sync` (e.g. `readFileSync`, `execSync`, `customOperationSync`) or is in the blocking set (`sleep`) when the call site is inside a method whose `modifiers` includes `async`.
  - **`StringConcatLoopPass`** (`string-concat-loop`, CWE-1046, performance, low/warning) — scans source lines within CFG loop bodies (`graph.loopBodies()`) for `identifier +=` patterns. Filters out numeric variable names (`i`, `count`, `sum`, `total`, …), numeric suffixes (`Count`, `Sum`, `Total`, …), and numeric RHS literals, leaving only likely string concatenation.
- **Test count**: 857 → 897 (+40 new pass unit tests across 5 new test files)

## [3.9.1] - 2026-03-25

### Added

- **`analyzeProject` is now part of the public API** — exported from the top-level package entry point (`src/index.ts`). Previously the function existed in `src/analyzer.ts` but was not re-exported, making it inaccessible to downstream consumers.

## [3.9.0] - 2026-03-25

### Added

- **Phase 1 Group 1: five new analysis passes** — all emit `SastFinding[]` via `PassContext.addFinding()` and are wired into the 11-pass pipeline:
  - **`DeadCodePass`** (`dead-code`, CWE-561, reliability) — BFS reachability on the CFG; unreachable non-entry/exit blocks with `start_line > 0` are reported as `warning` findings
  - **`MissingAwaitPass`** (`missing-await`, CWE-252, reliability) — JS/TS only; 24-method curated set; flagged when call is not awaited, result is not assigned (no DFG def at line), and line is not a `return` statement
  - **`NPlusOnePass`** (`n-plus-one`, CWE-1049, performance) — DB/HTTP calls inside CFG loop bodies (`loopBodies()`); two-tier confidence: HIGH_CONFIDENCE methods flagged regardless of receiver; MEDIUM_CONFIDENCE require a DB-like receiver (`prisma`, `mongoose`, `axios`, `db`, `conn`, `repo`, …)
  - **`MissingPublicDocPass`** (`missing-public-doc`, maintainability) — checks for `/**` doc comment within 10 lines before declaration; language-specific public rules (Java: `public` modifier; JS/TS: not `private`/`protected`; Python: no `_` prefix); Python docstring detection; test files excluded
  - **`TodoInProdPass`** (`todo-in-prod`, maintainability) — line-by-line regex scan for `TODO`/`FIXME`/`HACK`/`XXX` markers in comment context (`//`, `#`, `--`, `*`); `FIXME`/`HACK` → medium, `TODO`/`XXX` → low; test files excluded
- **`analyzeProject()` — multi-file analysis API**: New public function that accepts an array of `{ code, filePath, language }` entries, runs single-file analysis on each, then uses `CrossFileResolver` to find cross-file taint flows. Returns `ProjectAnalysis` with `files`, `type_hierarchy`, `cross_file_calls`, `taint_paths`, and `findings` (empty; LLM enrichment is out of scope).
- **`ProjectGraph`** (`src/graph/project-graph.ts`): Wraps multiple `CodeGraph` instances. Provides lazily-built `SymbolTable`, `TypeHierarchyResolver`, and `CrossFileResolver` — all three rebuilt together on the first access after any `addFile()` call.
- **`CrossFilePass`** (`src/analysis/passes/cross-file-pass.ts`): Project-level pass that maps `CrossFileTaintFlow[]` → `TaintPath[]`, surfaces resolved inter-file calls, and exports the full `TypeHierarchy`.
- **`ProjectGraph` exported** from `src/graph/index.ts`.
- **SAST taxonomy types** (`src/types/index.ts`):
  - `PassCategory` — ISO 25010 aligned: `security | reliability | performance | maintainability | architecture`
  - `SarifLevel` — `error | warning | note | none`
  - `SastFinding` — SARIF 2.1.0 aligned finding interface with CWE mapping, `level` (SarifLevel), `category` (PassCategory), `rule_id`, optional `fix` and `evidence`; no LLM fields
  - `MetricCategory` — `complexity | size | coupling | inheritance | cohesion | documentation | duplication`
  - `MetricValue` — standard metric names (CK suite: WMC/DIT/NOC/CBO/RFC/LCOM; Halstead: V/D/E/B; McCabe: v(G)) with ISO 25010 sub-characteristic alignment
  - `FileMetrics` — per-file metric aggregation
  - `CircleIR.findings?` — optional `SastFinding[]` populated by analysis passes
  - `CircleIR.metrics?` — optional `FileMetrics` reserved for future metric passes
- **`PassContext.addFinding()`** — analysis passes can emit `SastFinding` objects directly into the pipeline
- **`PipelineRunResult`** — `AnalysisPipeline.run()` now returns `{ results: Map, findings: SastFinding[] }` instead of a bare Map; exported from `src/graph/index.ts`
- **`CodeGraph.loopBodies()`** (`src/graph/code-graph.ts`) — returns `{ start_line, end_line }[]` for each loop body detected via CFG back-edges (`edge.type === 'back'`); used by the n-plus-one pass
- **`docs/PASSES.md`** — canonical reference for all planned passes: number, `rule_id`, CWE, SARIF level, required graphs, implementation status; metric registry with 40+ metrics mapped to `MetricCategory` and ISO 25010 sub-characteristics

### Changed

- **`AnalysisPass` interface** — added `category: PassCategory` field; all 6 existing security passes updated with `category = 'security'`
- **`analyze()` pipeline** — extended from 6 to 11 passes; `DeadCodePass`, `MissingAwaitPass`, `NPlusOnePass`, `MissingPublicDocPass`, `TodoInProdPass` added after `InterproceduralPass`
- **`analyzer.ts` decomposed into 6 AnalysisPass modules** (behavior unchanged, zero test regressions):
  - `TaintMatcherPass` — config-based source/sink extraction + plugin merge
  - `ConstantPropagationPass` — dead-code detection, symbol table, field taint
  - `LanguageSourcesPass` — JS/Python language-specific sources and sinks
  - `SinkFilterPass` — four-stage false-positive elimination
  - `TaintPropagationPass` — DFG-based flow verification + array/collection/param supplements
  - `InterproceduralPass` — cross-method taint propagation (both scenarios)
- **`analyzer.ts`** reduced from ~2100 lines to ~630 lines; `analyze()` is now a clean orchestrator
- **`CodeGraph`** (`src/graph/code-graph.ts`): Introduced lazy Map indexes (defById, defsByLine, defsByVar, usesByLine, usesByDefId, chainsByFromDef, callsByLine, callsByMethod, sanitizersByLine, methodsByName, blockById) built once per analysis
- **Test count**: 788 → 857 (69 new pass unit tests across 5 new test files)

## [3.8.4] - 2026-03-24

### Fixed

- **JS/TS false positive reduction**: Added class constraint (`ScriptEngine`) to the classless `evaluate` sink pattern in `config-loader.ts` that was matching any `evaluate()` call as code injection (CWE-94). Discovered via self-analysis (dogfooding). This eliminates ~87% of false positives when analyzing JS/TS codebases that use `evaluate()` as a method name (e.g., AST evaluators, expression engines).

### Changed

- **TODO.md**: Added pending JS/TS precision improvements identified during dogfooding (`.value` dom_input narrowing, `new Function()` literal-arg suppression)

## [3.8.3] - 2026-03-17

### Changed

- **License**: Changed from ISC to MIT for broader compatibility and clearer permissions
- **Dependencies**: Updated to latest versions
  - `web-tree-sitter`: ^0.26.3 → ^0.26.7
  - `@types/node`: ^25.0.10 → ^25.5.0
  - `@vitest/coverage-v8`: ^3.0.0 → ^4.1.0
  - `vitest`: ^3.0.0 → ^4.1.0
  - `esbuild`: ^0.27.2 → ^0.27.4
- **Test coverage**: Adjusted branch coverage threshold to 64% to reflect vitest 4.x branch calculation differences in language plugin conditional logic

### Removed

- **ts-node**: Removed unused devDependency and its 74 transitive dependencies

### Added

- **CI/CD**: GitHub Actions workflows for automated testing and npm publishing
- **Documentation**: Added PUBLISHING.md with comprehensive release guide

## [3.8.2] - 2026-03-12

### Fixed

- **JS/Python: language auto-detection from filename** — requests that omit `language` now auto-detect from the filename extension (`.js`→`javascript`, `.ts`→`typescript`, `.py`→`python`, `.rs`→`rust`, `.sh`→`bash`); previously all fell back to `java`, causing JS/Python patterns to never fire
- **JS: SSRF via `http.get`/`https.get`** — added `{ method: 'get', class: 'http', ... }` and `https` entries to Node.js SSRF sinks in `config-loader.ts`; `http.get(url, callback)` now correctly produces CWE-918 (SSRF)
- **JS: command injection via destructured `exec`/`spawn`** — class-less entries for `spawn`, `spawnSync`, `execFile` added to `config-loader.ts`; combined with existing `exec`/`execSync` entries, all `child_process` forms now detected
- **Python: XSS via Flask route `return` statements** — added `findPythonReturnXSSSinks()` to detect `return '<html>...' + tainted_var` patterns in Flask routes; these are return statements, not call nodes, so they were invisible to the standard `findSinks()` path
- **CWE-668 spurious duplicate eliminated** — `analyzeInterprocedural` in the main flow (when real sinks already exist) no longer adds `external_taint_escape` sinks to `taint.sinks`; they were already skipped for flow generation (line 1216) but still added to the sinks array, causing double-findings when paired with a proper sink (e.g., CWE-918 SSRF + CWE-668 on adjacent lines)
- **JS: spurious XSS alongside command injection / path traversal eliminated** — added `buildJavaScriptTaintedVars()` (forward taint propagation for JS/TS) and a pre-propagation XSS sink filter; `res.send(stdout)` (callback param from `exec()`) and `res.send(data)` (callback param from `fs.readFile()`) are no longer tagged as XSS sinks because `stdout`/`data` are not in the tainted-variables map

## [3.8.1] - 2026-03-12

### Fixed

- **CWE-22 false positive eliminated** — removed `BufferedReader` constructor from path traversal sinks in `config-loader.ts`; `BufferedReader(Reader)` wraps a `Reader` object and never takes a file path, so it cannot be a path traversal sink
- **CWE-668 false positive eliminated (stream wrappers)** — added Java I/O stream wrappers (`InputStreamReader`, `OutputStreamWriter`, `BufferedInputStream`, `BufferedOutputStream`, `DataInputStream`, `DataOutputStream`, `BufferedReader`, `BufferedWriter`, `PrintStream`, `PrintWriter`) to `safeUtilityMethods` in `interprocedural.ts`; these are pure stream decorators and should not trigger `external_taint_escape` findings
- **CWE-668 false positive eliminated (string accumulators)** — added `StringBuilder`/`StringBuffer`/`Writer` accumulator methods (`append`, `insert`, `prepend`, `concat`, `delete`, `deleteCharAt`, `replace`, `reverse`, `write`, `writeln`, `println`) to `collectionMethods` in `interprocedural.ts`; string-building operations are not security sinks
- **CWE-22 false positive eliminated (URL constructor)** — removed `new URL(userInput)` and `URL.openStream()` from path traversal sinks in `config-loader.ts`; these are SSRF vectors (CWE-918), not file-system path traversal; the SSRF section already covers them correctly
- **CWE-668 false positive eliminated (byte array streams)** — added `ByteArrayInputStream`, `ByteArrayOutputStream`, and `ObjectOutputStream` to `safeUtilityMethods` in `interprocedural.ts`; byte array streams wrap in-memory data, not external I/O, and are not taint escape points

## [3.8.0] - 2026-03-11

### Added

- **Python: per-key container taint tracking** — `buildPythonTaintedVars` now tracks taint at per-key granularity for dicts and ConfigParser objects:
  - Subscript assignment: `map['keyB'] = param` seeds `containerTainted['map[\'keyB\']']`; `bar = map['keyB']` propagates correctly while `bar = map['keyA']` (safe key) does not
  - ConfigParser: `conf.set('s','k',param)` seeds per-key entry; `conf.get('s','k')` reads it back; distinguishes between tainted and safe keys in same section
- **Python: augmented assignment taint propagation** — `var += tainted_expr` now correctly preserves or seeds taint; previously `+=` lines were silently skipped
- **Python: for-loop iteration taint seeding** — `for name in request.headers.keys()` now marks `name` as tainted; handles both direct sources and tainted iterables
- **Python: new taint source patterns** — `PYTHON_TAINTED_PATTERNS` extended with `request.query_string`, `request.get_data(`, `get_form_parameter(`, `get_query_parameter(`, `get_header_value(`, `get_cookie_value(` (OWASP-style wrapper helpers)
- **Python: multi-line apostrophe guard detection** — `findPythonQuoteSanitizedVars` extended to look ahead up to 5 lines for the `return`/`raise` statement inside `if "'" in var:` blocks; previously only checked the immediately-next line
- **Python: inline `.replace()` sanitizer detection** — `query = f"...{bar.replace('\'', '&apos;')}..."` now marks `query` as XPath-safe; handles inline quote-escaping patterns that do not reassign the source variable
- **Python: parameterized XPath suppression** — `root.xpath(query, name=bar)` calls where the tainted variable appears only as a keyword argument (not in the query string) are now suppressed; lxml named variable substitution is not injectable
- **Python: sanitization propagation** — if `bar` is apostrophe-sanitized and `query = f"...{bar}..."`, `query` is also marked sanitized; prevents FPs where the sanitized var is used in a derived variable
- **Python benchmark 56.7% → 63.8%** — xpathi FPs reduced 22 → 7 (score 46% → 58%); trustbound improved 45% → 84% (6 → 17 TPs)

## [3.7.0] - 2026-03-11

### Added

- **Python P1 source detection** — three-pronged approach for Flask/Django/FastAPI taint tracking:
  - **`python.json` source patterns fixed** — 8 dotted method names split into correct `method`+`class` pairs (e.g. `"method":"get","class":"args"` instead of `"method":"args.get","class":"request"`) so `matchesSourcePattern` correctly matches `request.args.get()`, `request.form.get()`, `request.GET.get()`, etc.; 5 new patterns added (getlist/args, getlist/form, get_json/request, FILES field, query_params)
  - **`PYTHON_TAINTED_PATTERNS` + Python section in `taint-matcher.ts`** — regex-based source detection for `request.args[...]` subscript accesses passed as call arguments (not call nodes); covers 13 Flask/Django/FastAPI request property patterns
  - **`findPythonAssignmentSources()` in `analyzer.ts`** — line-scan detection for `x = request.args['id']` assignment patterns; handles `language !== 'python'` guard and skips comment lines
- **Python benchmark 25.2% → 56.7%** — sqli/weakrand/hash/securecookie all at 100%; cmdi improved; overall F1 77.5%
- **Import extractor test coverage improvements** — 13 new edge-case tests in `tests/extractors/imports.test.ts`:
  - JS: side-effect import, combined default+named, renamed CommonJS destructuring
  - Python: wildcard from-import, aliased from-import, dotted module import, multi-level relative import, multi-name from-import
  - Rust: `{self}` in use list, aliased item in use list, nested scoped path in use list, aliased nested scoped path with `::`, bare use identifier
- **Test count 730 → 743**

## [3.6.0] - 2026-03-11

### Added

- **Bash/Shell analysis fully functional** — core pipeline wired to extract `command` nodes as calls, detect `read` as taint source (io_input), and match sinks (eval/sh/bash/mysql/psql/sqlite3/cat/rm/cp/mv/curl/wget); 68.2% TPR, 0% FPR on 31 synthetic benchmark cases
- **`extractBashCalls()` in `calls.ts`** — new language branch in `extractCalls()` for Bash; extracts `command` AST nodes using `name` field, collects arguments with variable reference extraction (`$VAR`, `${VAR}`, `"$VAR"`)
- **Bash `nodeTypesToCollect` in `analyzer.ts`** — added `command`, `function_definition`, `variable_assignment`, `declaration_command`, `if_statement`, `for_statement`, `c_style_for_statement`, `while_statement`
- **Plugin source/sink merging in `analyzer.ts`** — language plugin `getBuiltinSources()` and `getBuiltinSinks()` are now merged into `baseConfig` at analysis time; enables pure-plugin languages like Bash to define their patterns without YAML config files
- **`'bash'` added to all three `SupportedLanguage` types** — `core/parser.ts`, `types/index.ts`, `languages/types.ts`; `'c'` and `'cpp'` synced into `languages/types.ts` for consistency
- **Bash synthetic benchmark** — 31 test cases covering CWE-78/94/89/22/918; scores 68.2% TPR (15 TP, 9 TN, 0 FP, 7 FN); 7 FNs are curl/wget command-substitution patterns requiring DFG tracking

### Changed

- **`BashPlugin.getBuiltinSources()`** — removed `curl` and `wget` (they're also sinks; without DFG tracking of `$()` they cause false positives); `read` source type changed from `user_input` to `io_input` to match `SourceType` union

## [3.5.0] - 2026-03-10

### Added

- **`BashPlugin`** (`src/languages/plugins/bash.ts`) — new language plugin with id `'bash'`, extensions `.sh/.bash/.zsh/.ksh`, WASM `tree-sitter-bash.wasm`; node type mappings for `command` → methodCall/functionCall, `function_definition` → functionDeclaration, `variable_assignment` → assignment; sink patterns for eval (CWE-94), sh/bash/zsh/ksh -c (CWE-78), mysql/psql/sqlite3 (CWE-89), cat/rm/cp/mv/chmod/chown (CWE-22), curl/wget (CWE-918)
- **`tree-sitter-bash.wasm`** — added to `wasm/` directory (committed)
- **14 new BashPlugin tests** in `tests/languages/plugins.test.ts`; total test count 730 (up from 716)
- **`'bash'` added to `SupportedLanguage`** in `src/languages/types.ts`

## [3.4.0] - 2026-03-09

### Added

- **Fastify taint sources** (`src/languages/plugins/javascript.ts`) — `request.raw` (http_param) and `request.hostname` (http_header) for Fastify request objects
- **Koa taint sources** — `ctx.header`, `ctx.headers` (http_header), `ctx.host`, `ctx.hostname` (http_header), `ctx.path`, `ctx.url` (http_path), `ctx.querystring` (http_param) for Koa context objects
- **Prisma unsafe raw query sinks** — `$executeRawUnsafe` and `$queryRawUnsafe` (CWE-89, critical); the parameterized `$executeRaw`/`$queryRaw` template literal variants are intentionally excluded as they are safe
- **Test coverage improvements** — imports.ts 61.7% → 77.6%, types.ts 69.7% → 93.2%, dfg.ts 71% → 85.87%, base.ts 30% → 96.66%, constant-propagation/index.ts 77.66% → 100%, constant-propagation/propagator.ts 70.25% → 75.39%; 716 total tests (up from 653)

## [3.3.3] - 2026-03-09

### Fixed

- **`checkSanitized` implemented** (`src/analysis/taint-propagation.ts`) — the function was a stub that always returned `{ sanitized: false }`. It now performs variable-specific sanitizer detection:
  - Checks for a recognised sanitizer call **AT the target definition line** (e.g. `safe = escapeHtml(input)`). This is variable-specific: the DFG chain guarantees the target variable is the return value of that sanitizer call.
  - **Sink-check context** (sinkType is a known CWE type such as `sql_injection`): requires the sanitizer to cover that specific vulnerability type.
  - **Propagation context** (sinkType is a source type such as `http_param`): accepts any recognised sanitizer, since the eventual sink type is not yet known.
  - Intentionally does **not** perform a range scan (from → to lines) which was the cause of the previous over-eager false-negative behaviour.
- **Initial-taint "next-line" heuristic now respects sanitizers**: `propagateTaint` filters variables that were added to the initial taint set via the "next-line" heuristic (e.g. when the source call and the tainted variable definition are on adjacent lines) but are actually the result of a sanitizer call at their definition line.
- **3 new tests** covering: propagation stopped through `escapeHtml`, propagation continues through non-sanitizer `toLowerCase`, and sanitizer on a different variable does not suppress taint on the original.

## [3.3.2] - 2026-03-05

### Fixed

- **Taint Propagation Through String Methods**: Removed `trim` and `replace` from `SANITIZER_METHODS` — these methods do not sanitize any vulnerability type (trim only removes whitespace; replace is not a reliable sanitizer). Method chains like `request.getParameter("x").toLowerCase().trim()` now correctly mark the result as tainted, eliminating false negatives.

## [3.3.1] - 2026-02-22

### Added

- **WebAssembly.Module Support**: Parser and browser initialization now accept pre-compiled `WebAssembly.Module` instances for Cloudflare Workers compatibility
- **WASM Options**: New `wasmModule` and `languageModules` options for pre-compiled WASM to bypass dynamic compilation
- **Custom WASM Instantiation**: Parser accepts `instantiateWasm` callback for custom WASM loading strategies

### Changed

- **Literal Sink Filtering**: `analyzeForAPI` now applies `filterCleanVariableSinks` and `filterSanitizedSinks` to reduce false positives
- **Taint Treatment**: Literal arguments and quoted string expressions are now treated as clean (not tainted) to eliminate false positives on constant values

### Fixed

- Browser initialization now accepts `string | WebAssembly.Module` for `wasmUrl` and `languageUrls` parameters

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
- **Browser Example**: Interactive HTML example for browser-based analysis (`examples/browser-example.html`)

### Benchmark Results

- **OWASP Benchmark**: +100% (TPR: 100%, FPR: 0%, 1415/1415 test cases)
- **Juliet Test Suite**: +100% (156/156 test cases)
- **SecuriBench Micro**: 97.7% TPR, 6.7% FPR (105/108 vulns detected)
- **CWE-Bench-Java**: 42.5% static (51/120 real-world CVEs, vs CodeQL 22.5%, IRIS+GPT-4 45.8%)

### Technical Highlights

- Tree-sitter WASM parsing for accurate AST generation
- Constant propagation for false positive elimination
- Inter-procedural taint analysis
- Sanitizer recognition (PreparedStatement, ESAPI, etc.)
- Per-index collection taint tracking
- Language plugin architecture

[3.9.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.9.0
[3.8.4]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.8.4
[3.8.3]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.8.3
[3.8.2]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.8.2
[3.8.1]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.8.1
[3.8.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.8.0
[3.7.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.7.0
[3.6.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.6.0
[3.5.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.5.0
[3.4.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.4.0
[3.3.3]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.3
[3.3.2]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.2
[3.3.1]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.1
[3.3.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.0
[3.1.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.1.0
[3.0.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.0.0
