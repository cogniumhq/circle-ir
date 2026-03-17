# TODO - circle-ir

This file tracks pending improvements and known issues for the circle-ir core library.

## Priority Legend
- **P0**: Critical - blocks release
- **P1**: High - should be done soon
- **P2**: Medium - nice to have
- **P3**: Low - future improvement

---

## Test Coverage Improvements

Current overall coverage: ~80%. Target: ≥75% (met).

| File | Coverage | Priority | Notes |
|------|----------|----------|-------|
| `src/languages/plugins/bash.ts` | ~60% | P2 | Bash language plugin |

### Test Tasks

- [ ] **P2**: Add tests for Bash plugin edge cases (command substitution, here-docs)
- [ ] **P2**: Add tests for `dfg.ts` inter-procedural data flow

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

*Last updated: 2026-03-14*
