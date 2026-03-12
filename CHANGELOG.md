# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

### Changed

- `circle-ir-ai`: `Record<SupportedLanguage, T>` exhaustive objects updated to include `bash` key in `dead-code/detector.ts`, `llm/language-context.ts`, `project/analyzer.ts`, `project/two-phase-analyzer.ts`, `security-scan/scanner.ts`

## [3.6.0] - 2026-03-11

### Added

- **Bash/Shell analysis fully functional** — core pipeline wired to extract `command` nodes as calls, detect `read` as taint source (io_input), and match sinks (eval/sh/bash/mysql/psql/sqlite3/cat/rm/cp/mv/curl/wget); 68.2% TPR, 0% FPR on 31 synthetic benchmark cases
- **`extractBashCalls()` in `calls.ts`** — new language branch in `extractCalls()` for Bash; extracts `command` AST nodes using `name` field, collects arguments with variable reference extraction (`$VAR`, `${VAR}`, `"$VAR"`)
- **Bash `nodeTypesToCollect` in `analyzer.ts`** — added `command`, `function_definition`, `variable_assignment`, `declaration_command`, `if_statement`, `for_statement`, `c_style_for_statement`, `while_statement`
- **Plugin source/sink merging in `analyzer.ts`** — language plugin `getBuiltinSources()` and `getBuiltinSinks()` are now merged into `baseConfig` at analysis time; enables pure-plugin languages like Bash to define their patterns without YAML config files
- **`'bash'` added to all three `SupportedLanguage` types** — `core/parser.ts`, `types/index.ts`, `languages/types.ts`; `'c'` and `'cpp'` synced into `languages/types.ts` for consistency
- **Bash synthetic benchmark** (`circle-ir-ai`) — 31 test cases covering CWE-78/94/89/22/918; scores 68.2% TPR (15 TP, 9 TN, 0 FP, 7 FN); 7 FNs are curl/wget command-substitution patterns requiring DFG tracking

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
- **CI/CD** — Docker workflow now triggers on `circle-pack-v*` tags in addition to bare `v*` tags

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
- **CWE-Bench-Java**: 81.7% with LLM (98/120 projects, vs CodeQL 22.5%, IRIS+GPT-4 45.8%)

### Technical Highlights

- Tree-sitter WASM parsing for accurate AST generation
- Constant propagation for false positive elimination
- Inter-procedural taint analysis
- Sanitizer recognition (PreparedStatement, ESAPI, etc.)
- Per-index collection taint tracking
- Language plugin architecture

[3.3.1]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.1
[3.3.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.0
[3.1.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.1.0
[3.0.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.0.0
