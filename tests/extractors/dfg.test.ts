/**
 * Tests for DFG builder
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { buildDFG } from '../../src/core/extractors/dfg.js';

describe('DFG Builder', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract parameter definitions', async () => {
    const code = `
public class Test {
    public void method(String name, int count) {
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    const paramDefs = dfg.defs.filter(d => d.kind === 'param');
    expect(paramDefs).toHaveLength(2);

    const nameDef = paramDefs.find(d => d.variable === 'name');
    expect(nameDef).toBeDefined();

    const countDef = paramDefs.find(d => d.variable === 'count');
    expect(countDef).toBeDefined();
  });

  it('should extract local variable definitions', async () => {
    const code = `
public class Test {
    public void method() {
        int x = 1;
        String s = "hello";
        double y = 2.0;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    const localDefs = dfg.defs.filter(d => d.kind === 'local');
    expect(localDefs.length).toBeGreaterThanOrEqual(3);

    expect(localDefs.some(d => d.variable === 'x')).toBe(true);
    expect(localDefs.some(d => d.variable === 's')).toBe(true);
    expect(localDefs.some(d => d.variable === 'y')).toBe(true);
  });

  it('should extract field definitions', async () => {
    const code = `
public class Test {
    private String name;
    private int count;
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    const fieldDefs = dfg.defs.filter(d => d.kind === 'field');
    expect(fieldDefs).toHaveLength(2);

    expect(fieldDefs.some(d => d.variable === 'name')).toBe(true);
    expect(fieldDefs.some(d => d.variable === 'count')).toBe(true);
  });

  it('should extract variable uses', async () => {
    const code = `
public class Test {
    public int method(int x) {
        int y = x + 1;
        return y;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // Should have uses of x and y
    const xUses = dfg.uses.filter(u => u.variable === 'x');
    const yUses = dfg.uses.filter(u => u.variable === 'y');

    expect(xUses.length).toBeGreaterThanOrEqual(1);
    expect(yUses.length).toBeGreaterThanOrEqual(1);
  });

  it('should link uses to reaching definitions', async () => {
    const code = `
public class Test {
    public int method(int x) {
        int y = x + 1;
        return y;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // Find the definition of x (parameter)
    const xDef = dfg.defs.find(d => d.variable === 'x' && d.kind === 'param');
    expect(xDef).toBeDefined();

    // Find the use of x in y = x + 1
    const xUse = dfg.uses.find(u => u.variable === 'x');
    expect(xUse).toBeDefined();
    expect(xUse!.def_id).toBe(xDef!.id);
  });

  it('should handle assignments as definitions', async () => {
    const code = `
public class Test {
    public void method() {
        int x = 1;
        x = 2;
        x = 3;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // Should have 3 definitions of x
    const xDefs = dfg.defs.filter(d => d.variable === 'x');
    expect(xDefs.length).toBeGreaterThanOrEqual(3);
  });

  it('should handle increment/decrement as def and use', async () => {
    const code = `
public class Test {
    public void method() {
        int i = 0;
        i++;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // i++ is both a use and a def
    const iDefs = dfg.defs.filter(d => d.variable === 'i');
    const iUses = dfg.uses.filter(u => u.variable === 'i');

    expect(iDefs.length).toBeGreaterThanOrEqual(2); // declaration + increment
    expect(iUses.length).toBeGreaterThanOrEqual(1); // increment uses the value
  });

  it('should track line numbers', async () => {
    const code = `public class Test {
    public void method() {
        int x = 1;
        int y = x;
    }
}`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    const xDef = dfg.defs.find(d => d.variable === 'x');
    expect(xDef).toBeDefined();
    expect(xDef!.line).toBe(3);
  });

  it('should handle for loop variable', async () => {
    const code = `
public class Test {
    public void method() {
        for (int i = 0; i < 10; i++) {
            System.out.println(i);
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // For loop variables are tracked through uses at minimum
    // The variable i should appear in uses from the condition and body
    const iUses = dfg.uses.filter(u => u.variable === 'i');
    expect(iUses.length).toBeGreaterThanOrEqual(1);
  });

  it('should handle enhanced for loop variable', async () => {
    const code = `
public class Test {
    public void method(List<String> items) {
        for (String item : items) {
            System.out.println(item);
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // Should have definition for item
    const itemDefs = dfg.defs.filter(d => d.variable === 'item');
    expect(itemDefs.length).toBeGreaterThanOrEqual(1);
  });

  it('should compute DFG chains', async () => {
    const code = `
public class Test {
    public int method(int x) {
        int y = x + 1;
        int z = y * 2;
        return z;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // Should have chains
    expect(dfg.chains).toBeDefined();
    expect(dfg.chains!.length).toBeGreaterThanOrEqual(1);

    // Should have chain from x to y
    const xDef = dfg.defs.find(d => d.variable === 'x' && d.kind === 'param');
    const yDef = dfg.defs.find(d => d.variable === 'y');
    expect(xDef).toBeDefined();
    expect(yDef).toBeDefined();

    const xToYChain = dfg.chains!.find(
      c => c.from_def === xDef!.id && c.to_def === yDef!.id && c.via === 'x'
    );
    expect(xToYChain).toBeDefined();

    // Should have chain from y to z
    const zDef = dfg.defs.find(d => d.variable === 'z');
    expect(zDef).toBeDefined();

    const yToZChain = dfg.chains!.find(
      c => c.from_def === yDef!.id && c.to_def === zDef!.id && c.via === 'y'
    );
    expect(yToZChain).toBeDefined();
  });

  it('should handle chains with multiple uses in same definition', async () => {
    const code = `
public class Test {
    public int method(int a, int b) {
        int sum = a + b;
        return sum;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    expect(dfg.chains).toBeDefined();

    // Should have chains from a and b to sum
    const aDef = dfg.defs.find(d => d.variable === 'a');
    const bDef = dfg.defs.find(d => d.variable === 'b');
    const sumDef = dfg.defs.find(d => d.variable === 'sum');

    expect(aDef).toBeDefined();
    expect(bDef).toBeDefined();
    expect(sumDef).toBeDefined();

    const aToSumChain = dfg.chains!.find(
      c => c.from_def === aDef!.id && c.to_def === sumDef!.id
    );
    const bToSumChain = dfg.chains!.find(
      c => c.from_def === bDef!.id && c.to_def === sumDef!.id
    );

    expect(aToSumChain).toBeDefined();
    expect(bToSumChain).toBeDefined();
  });
});
