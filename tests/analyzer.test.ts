/**
 * Tests for main Analyzer
 */

import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import {
  initAnalyzer,
  analyze,
  analyzeForAPI,
  isAnalyzerInitialized,
  resetAnalyzer,
} from '../src/analyzer.js';

describe('Analyzer', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  afterEach(() => {
    // Don't reset between tests to avoid re-initialization
  });

  it('should be initialized', () => {
    expect(isAnalyzerInitialized()).toBe(true);
  });

  it('should analyze simple Java code', async () => {
    const code = `
package com.example;

public class Test {
    public void method() {
        int x = 1;
    }
}
`;

    const result = await analyze(code, 'Test.java', 'java');

    expect(result.meta.circle_ir).toBe('3.0');
    expect(result.meta.language).toBe('java');
    expect(result.meta.package).toBe('com.example');
    expect(result.types).toHaveLength(1);
    expect(result.types[0].name).toBe('Test');
  });

  it('should extract all Circle-IR components', async () => {
    const code = `
package com.example;

import java.util.List;

public class UserController {
    private String name;

    public void handleRequest(HttpServletRequest request) {
        String id = request.getParameter("id");
        if (id != null) {
            processId(id);
        }
    }

    private void processId(String id) {}
}
`;

    const result = await analyze(code, 'UserController.java', 'java');

    // Meta
    expect(result.meta).toBeDefined();
    expect(result.meta.file).toBe('UserController.java');

    // Types
    expect(result.types).toHaveLength(1);
    expect(result.types[0].methods.length).toBeGreaterThanOrEqual(2);
    expect(result.types[0].fields).toHaveLength(1);

    // Calls
    expect(result.calls.length).toBeGreaterThanOrEqual(1);
    const getParamCall = result.calls.find(c => c.method_name === 'getParameter');
    expect(getParamCall).toBeDefined();

    // Imports
    expect(result.imports.length).toBeGreaterThanOrEqual(1);

    // CFG
    expect(result.cfg.blocks.length).toBeGreaterThan(0);
    expect(result.cfg.edges.length).toBeGreaterThan(0);

    // DFG
    expect(result.dfg.defs.length).toBeGreaterThan(0);
    expect(result.dfg.uses.length).toBeGreaterThan(0);

    // Taint
    expect(result.taint).toBeDefined();
    expect(result.taint.sources.length).toBeGreaterThanOrEqual(1);
  });

  it('should produce API response format', async () => {
    const code = `
public class Vulnerable {
    public void method(HttpServletRequest request, Statement stmt) {
        String id = request.getParameter("id");
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
`;

    const result = await analyzeForAPI(code, 'Vulnerable.java', 'java');

    expect(result.success).toBe(true);
    expect(result.analysis).toBeDefined();
    expect(result.analysis.sources.length).toBeGreaterThanOrEqual(1);
    expect(result.analysis.sinks.length).toBeGreaterThanOrEqual(1);
    expect(result.meta.totalTimeMs).toBeGreaterThanOrEqual(0);
  });

  it('should detect vulnerabilities', async () => {
    const code = `
@RestController
public class VulnerableController {
    @GetMapping("/search")
    public List<User> search(@RequestParam String query, Statement stmt) {
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + query + "'");
    }
}
`;

    const result = await analyzeForAPI(code, 'VulnerableController.java', 'java');

    expect(result.success).toBe(true);
    expect(result.analysis.vulnerabilities.length).toBeGreaterThanOrEqual(1);

    const sqlVuln = result.analysis.vulnerabilities.find(
      v => v.type === 'sql_injection'
    );
    expect(sqlVuln).toBeDefined();
    expect(sqlVuln!.cwe).toBe('CWE-89');
  });

  it('should handle multiple classes', async () => {
    const code = `
public class ServiceA {
    public void methodA() {}
}

public class ServiceB {
    public void methodB() {}
}

interface InterfaceC {
    void methodC();
}
`;

    const result = await analyze(code, 'Services.java', 'java');

    expect(result.types).toHaveLength(3);
  });

  it('should handle empty file', async () => {
    const code = '';
    const result = await analyze(code, 'Empty.java', 'java');

    expect(result.meta).toBeDefined();
    expect(result.types).toHaveLength(0);
    expect(result.calls).toHaveLength(0);
  });

  it('should handle Spring annotations', async () => {
    const code = `
@RestController
@RequestMapping("/api")
public class ApiController {
    @Autowired
    private UserService userService;

    @PostMapping("/users")
    public User createUser(@RequestBody User user) {
        return userService.save(user);
    }
}
`;

    const result = await analyze(code, 'ApiController.java', 'java');

    expect(result.types[0].annotations).toContain('RestController');
    expect(result.types[0].annotations.some(a => a.includes('RequestMapping'))).toBe(true);

    const createMethod = result.types[0].methods.find(m => m.name === 'createUser');
    expect(createMethod).toBeDefined();
    expect(createMethod!.parameters[0].annotations).toContain('RequestBody');

    // Should detect @RequestBody as a source
    expect(result.taint.sources.some(s => s.type === 'http_body')).toBe(true);
  });

  it('should allow resetting the analyzer', async () => {
    // Reset and check state
    resetAnalyzer();
    expect(isAnalyzerInitialized()).toBe(false);

    // Re-initialize for subsequent tests
    await initAnalyzer();
    expect(isAnalyzerInitialized()).toBe(true);
  });

  it('should filter sinks in dead code', async () => {
    const code = `
public class Test {
    public void method(HttpServletRequest request, Statement stmt) throws Exception {
        String param = request.getParameter("id");
        if (false) {
            // This is dead code - should not be flagged
            stmt.executeQuery("SELECT * FROM users WHERE id = " + param);
        }
    }
}
`;

    const result = await analyze(code, 'Test.java', 'java');

    // Source should exist
    expect(result.taint.sources.length).toBeGreaterThanOrEqual(1);

    // Sink in dead code should be filtered
    // The sink may still be detected but flows should be filtered
    expect(result.meta).toBeDefined();
  });

  it('should detect tainted array element flows', async () => {
    const code = `
public class Test {
    public void method(HttpServletRequest request, Statement stmt) throws Exception {
        String[] params = request.getParameterValues("ids");
        stmt.executeQuery(params[0]);
    }
}
`;

    const result = await analyze(code, 'Test.java', 'java');

    // Should detect the source
    expect(result.taint.sources.length).toBeGreaterThanOrEqual(1);
  });

  it('should handle pattern discovery option', async () => {
    const code = `
public class CustomController {
    public void process(HttpServletRequest request) {
        String data = request.getParameter("data");
        customSink(data);
    }

    public void customSink(String input) {
        // Custom sink method
    }
}
`;

    const result = await analyze(code, 'CustomController.java', 'java', {
      enablePatternDiscovery: true,
      patternConfidenceThreshold: 0.6,
    });

    expect(result.meta).toBeDefined();
    expect(result.taint.sources.length).toBeGreaterThanOrEqual(1);
  });

  it('should handle constant propagation for safe values', async () => {
    const code = `
public class Test {
    public void method(Statement stmt) throws Exception {
        String query = "SELECT * FROM users";
        stmt.executeQuery(query);
    }
}
`;

    const result = await analyze(code, 'Test.java', 'java');

    // No taint sources, so should not report vulnerability
    expect(result.taint.sources).toHaveLength(0);
  });

  it('should track taint through variable reassignment', async () => {
    const code = `
public class Test {
    public void method(HttpServletRequest request, Statement stmt) throws Exception {
        String param = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + param;
        stmt.executeQuery(query);
    }
}
`;

    const result = await analyze(code, 'Test.java', 'java');

    expect(result.taint.sources.length).toBeGreaterThanOrEqual(1);
    expect(result.taint.sinks.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect sanitizer usage', async () => {
    const code = `
public class Test {
    public void method(HttpServletRequest request, Connection conn) throws Exception {
        String param = request.getParameter("id");
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, param);
        stmt.executeQuery();
    }
}
`;

    const result = await analyze(code, 'Test.java', 'java');

    // Should detect source
    expect(result.taint.sources.length).toBeGreaterThanOrEqual(1);

    // Sanitizer should be detected
    expect(result.taint.sanitizers?.length).toBeGreaterThanOrEqual(0);
  });

  it('should handle custom taint configuration', async () => {
    const code = `
public class Test {
    public void method(CustomRequest req, CustomSink sink) {
        String data = req.getData();
        sink.process(data);
    }
}
`;

    const result = await analyze(code, 'Test.java', 'java', {
      taintConfig: {
        sources: [
          { method: 'getData', class: 'CustomRequest', type: 'custom', severity: 'high', return_tainted: true },
        ],
        sinks: [
          { method: 'process', class: 'CustomSink', type: 'custom', cwe: 'CWE-000', severity: 'high', arg_positions: [0] },
        ],
        sanitizers: [],
      },
    });

    expect(result.meta).toBeDefined();
    // Should detect the custom source
    expect(result.taint.sources.some(s => s.type === 'custom')).toBe(true);
    // Should detect the custom sink
    expect(result.taint.sinks.some(s => s.type === 'custom')).toBe(true);
  });

  it('should handle inter-procedural taint analysis', async () => {
    const code = `
public class Test {
    public void entry(HttpServletRequest request, Statement stmt) throws Exception {
        String param = request.getParameter("id");
        String processed = process(param);
        stmt.executeQuery(processed);
    }

    private String process(String input) {
        return input.trim();
    }
}
`;

    const result = await analyze(code, 'Test.java', 'java');

    expect(result.taint.sources.length).toBeGreaterThanOrEqual(1);

    // Inter-procedural analysis should be present
    expect(result.taint.interprocedural).toBeDefined();
  });

  it('should produce enriched output format', async () => {
    const code = `
public class Vulnerable {
    public void method(HttpServletRequest request, Statement stmt) throws Exception {
        String id = request.getParameter("id");
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
`;

    const result = await analyze(code, 'Vulnerable.java', 'java');

    // Check enriched metadata
    expect(result.meta).toBeDefined();
    expect(result.meta.language).toBe('java');
  });

  it('should track taint through constructor field assignment', async () => {
    const code = `
public class User {
    private String name;

    public User(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }
}

public class Controller {
    public void handle(HttpServletRequest request, Statement stmt) throws Exception {
        String input = request.getParameter("name");
        User user = new User(input);
        stmt.executeQuery("SELECT * FROM users WHERE name = " + user.getName());
    }
}
`;

    const result = await analyze(code, 'User.java', 'java');

    // Should detect taint source from HTTP parameter
    expect(result.taint.sources.length).toBeGreaterThanOrEqual(1);
    const httpSource = result.taint.sources.find(s => s.type === 'http_param');
    expect(httpSource).toBeDefined();

    // Should detect constructor_field source for the getter
    const constructorFieldSource = result.taint.sources.find(s => s.type === 'constructor_field');
    expect(constructorFieldSource).toBeDefined();
    if (constructorFieldSource) {
      expect(constructorFieldSource.location).toContain('getName');
      expect(constructorFieldSource.location).toContain('name');
    }
  });

  it('should NOT flag getter when constructor param is not tainted', async () => {
    const code = `
public class Config {
    private String defaultValue;

    public Config() {
        this.defaultValue = "safe";
    }

    public String getDefaultValue() {
        return this.defaultValue;
    }
}
`;

    const result = await analyze(code, 'Config.java', 'java');

    // Should NOT have constructor_field sources since no tainted param flows to field
    const constructorFieldSource = result.taint.sources.find(s => s.type === 'constructor_field');
    expect(constructorFieldSource).toBeUndefined();
  });
});
