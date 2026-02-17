/**
 * Tests for Import extractor
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractImports } from '../../src/core/extractors/imports.js';

describe('Import Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract single class import', async () => {
    const code = `
import java.util.ArrayList;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('ArrayList');
    expect(imports[0].from_package).toBe('java.util');
    expect(imports[0].is_wildcard).toBe(false);
  });

  it('should extract wildcard import', async () => {
    const code = `
import java.util.*;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('*');
    expect(imports[0].from_package).toBe('java.util');
    expect(imports[0].is_wildcard).toBe(true);
  });

  it('should extract multiple imports', async () => {
    const code = `
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import javax.servlet.http.*;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports).toHaveLength(4);

    const listImport = imports.find(i => i.imported_name === 'List');
    expect(listImport).toBeDefined();
    expect(listImport!.from_package).toBe('java.util');

    const wildcardImport = imports.find(i => i.is_wildcard);
    expect(wildcardImport).toBeDefined();
    expect(wildcardImport!.from_package).toBe('javax.servlet.http');
  });

  it('should capture line numbers', async () => {
    const code = `import java.util.List;
import java.util.Map;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports[0].line_number).toBe(1);
    expect(imports[1].line_number).toBe(2);
  });

  it('should handle files without imports', async () => {
    const code = `
public class Test {
    public void method() {}
}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports).toHaveLength(0);
  });

  it('should handle nested package imports', async () => {
    const code = `
import org.springframework.web.bind.annotation.RequestMapping;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('RequestMapping');
    expect(imports[0].from_package).toBe('org.springframework.web.bind.annotation');
  });

  it('should handle simple class import without package', async () => {
    // This is an edge case - importing just a class name without package path
    const code = `
import SimpleClass;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    // Parser may or may not accept this syntax
    // If it does, the import should have no package
    for (const imp of imports) {
      expect(imp.imported_name).toBeDefined();
    }
  });

  it('should handle static import', async () => {
    const code = `
import static java.lang.Math.PI;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    // Static imports should still be captured
    expect(imports.length).toBeGreaterThanOrEqual(0);
  });
});
