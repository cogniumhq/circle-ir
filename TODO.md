# TODO - circle-ir

This file tracks pending improvements and known issues for the circle-ir core library.

## Priority Legend
- **P0**: Critical - blocks release
- **P1**: High - should be done soon
- **P2**: Medium - nice to have
- **P3**: Low - future improvement

---

## Test Coverage Improvements

Current overall coverage: ~80%. Target: ≥75% (met). Areas below threshold that need attention:

| File | Coverage | Priority | Notes |
|------|----------|----------|-------|
| `src/analysis/advisory-db.ts` | 8.86% | P2 | Rust advisory database lookup |
| `src/analysis/cargo-parser.ts` | 3.48% | P2 | Cargo.toml/Cargo.lock parsing |
| `src/analysis/dependency-scanner.ts` | 6.3% | P2 | Dependency vulnerability scanning |
| `src/analysis/constant-propagation/index.ts` | 42.71% | P1 | Core constant propagation entry |
| `src/core/extractors/imports.ts` | 61.7% | P1 | Import extraction logic |
| `src/core/extractors/types.ts` | 69.69% | P2 | Type extraction logic |
| `src/core/extractors/dfg.ts` | 70.97% | P2 | Data flow graph extraction |
| `src/languages/plugins/base.ts` | 30% | P1 | Base language plugin |

### Test Tasks

- [ ] **P1**: Add tests for `constant-propagation/index.ts` edge cases
- [ ] **P1**: Add tests for `imports.ts` cross-file resolution scenarios
- [ ] **P1**: Add tests for `base.ts` language plugin abstract methods
- [ ] **P2**: Add tests for Rust dependency scanning (advisory-db, cargo-parser, dependency-scanner)
- [ ] **P2**: Add tests for `types.ts` complex type hierarchies
- [ ] **P2**: Add tests for `dfg.ts` inter-procedural data flow

---

## Language Support

### Current Status

| Language | Parser | Sources | Sinks | Benchmark Score | Priority |
|----------|--------|---------|-------|-----------------|----------|
| Java | ✅ Complete | ✅ Spring, JAX-RS, Servlet | ✅ SQL, Cmd, XSS, Path, LDAP | 100% OWASP | - |
| JavaScript/TS | ✅ Complete | ✅ Express, Node.js | ✅ SQL, Cmd, XSS, Path | 100% NodeGoat | - |
| Python | ✅ Complete | ⚠️ Basic | ⚠️ Basic | 25.2% OWASP | P1 |
| Rust | ✅ Complete | ⚠️ Actix, Rocket | ⚠️ Diesel, Tokio | 100% CWE-Bench | - |
| Bash/Shell | ✅ Complete | ⚠️ Basic (read, curl, wget) | ⚠️ Basic (eval, sh -c, mysql, cat) | Not benchmarked | P2 |
| Go | ❌ No parser | - | - | - | P3 |

### Pending Language Improvements

#### Python (P1 - High Priority)
- [ ] Add Django source patterns (request.GET, request.POST, request.FILES)
- [ ] Add Django sink patterns (ORM raw queries, template rendering)
- [ ] Add Flask source patterns (request.args, request.form, request.json)
- [ ] Add Flask sink patterns (render_template_string, subprocess)
- [ ] Add FastAPI source patterns (Query, Path, Body parameters)
- [ ] Add SQLAlchemy sink patterns (text(), execute())
- [ ] Add Jinja2 XSS sink patterns
- [ ] Improve Python benchmark score from 25.2% to >75%

#### JavaScript/TypeScript (P2 - Medium Priority)
- [ ] Add Fastify source/sink patterns
- [ ] Add Koa source/sink patterns
- [ ] Add Next.js API route patterns
- [ ] Add Prisma ORM sink patterns
- [ ] Add TypeORM sink patterns

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

*Last updated: 2025-02-12*
