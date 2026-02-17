# Circle-IR Playground Demo

A browser-based interactive demo for Circle-IR static analysis.

## Quick Start

```bash
# From the project root
npx tsx demo/server.ts
```

Then open http://localhost:3000 in your browser.

## Features

- **Multi-language support**: Java, JavaScript/TypeScript, Python, Rust
- **Pre-loaded examples**: SQL Injection, XSS, Command Injection, Path Traversal
- **Real-time analysis**: Using the full Circle-IR engine
- **Beautiful UI**: Dark theme, syntax highlighting, clear results

## Demo Flow

1. Select a language from the dropdown
2. Choose an example vulnerability or paste your own code
3. Click **Analyze** (or press Ctrl+Enter)
4. View detected vulnerabilities, sources, and sinks

## Example Vulnerabilities Included

| Language | Examples |
|----------|----------|
| Java | SQL Injection, Command Injection, XSS, Path Traversal |
| JavaScript | SQL Injection, Command Injection, XSS, Path Traversal |
| Python | SQL Injection, Command Injection, XSS, Path Traversal |
| Rust | SQL Injection, Command Injection, Path Traversal |

Each language also includes a "Safe Code" example showing proper mitigation.

## Deployment Options

### Local Development
```bash
npx tsx demo/server.ts
```

### Static Hosting (Demo Mode)
The `index.html` can be served statically. Without the API backend, it uses
pattern matching for demonstration purposes.

## API Endpoint

When running with the server, the `/api/analyze` endpoint accepts:

```json
POST /api/analyze
{
  "code": "String of source code",
  "language": "java" | "javascript" | "python" | "rust"
}
```

Returns:
```json
{
  "success": true,
  "vulnerabilities": [...],
  "sources": [...],
  "sinks": [...]
}
```

## Keyboard Shortcuts

- `Ctrl+Enter` / `Cmd+Enter`: Analyze code
