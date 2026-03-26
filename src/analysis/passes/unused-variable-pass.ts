/**
 * Pass #82: unused-variable (CWE-561, category: reliability)
 *
 * Detects local variables that are declared but whose value is never read.
 * This includes variables whose value is overwritten before any read
 * (the initial assignment is "dead" from a data-flow perspective).
 *
 * Detection strategy:
 *   1. For each `kind='local'` DFG def:
 *      - Skip intentional throwaway names (`_`, `err`, `e`, loop variables…).
 *      - Skip variables in `catch` blocks (common pattern to capture but ignore
 *        exceptions: `catch (err) { ... }`).
 *      - Call `graph.usesOfDef(def.id)` — returns uses with `def_id === defId`.
 *      - If the result is empty, no code ever reads the value stored by this
 *        definition → flag as unused.
 *
 * Notes:
 *   - Test files are excluded to reduce noise (test helpers often define
 *     variables for side-effect checks).
 *   - Parameters (`kind='param'`) are excluded — unused parameters are common
 *     in callbacks and overriding methods and produce too many false positives.
 *   - Fields (`kind='field'`) are excluded — class fields are often read via
 *     `this.x` in ways the DFG may not track precisely.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Variable names that are intentionally declared-but-not-read. */
const SKIP_NAMES = new Set([
  '_', 'unused',
  'e', 'err', 'error', 'ex', 'exception',
  'i', 'j', 'k', 'n', 'idx', 'index',
]);

export interface UnusedVariableResult {
  unusedVars: Array<{ line: number; variable: string }>;
}

export class UnusedVariablePass implements AnalysisPass<UnusedVariableResult> {
  readonly name = 'unused-variable';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): UnusedVariableResult {
    const { graph, code } = ctx;
    const file = graph.ir.meta.file;

    // Skip test files — test scaffolding often has unused vars intentionally
    if (/[./](?:test|spec)[./]/.test(file) || /\.(?:test|spec)\.[jt]s$/.test(file)) {
      return { unusedVars: [] };
    }

    const codeLines = code.split('\n');
    const unusedVars: UnusedVariableResult['unusedVars'] = [];
    const reported = new Set<string>(); // deduplicate by variable+line

    for (const def of graph.ir.dfg.defs) {
      if (def.kind !== 'local') continue;

      const variable = def.variable;

      // Skip intentional throwaway / loop variable names
      if (variable.startsWith('_')) continue;
      if (SKIP_NAMES.has(variable)) continue;

      // Skip catch-block variables (e.g. `catch (err)`)
      const lineText = codeLines[def.line - 1] ?? '';
      if (/\bcatch\s*\(/.test(lineText)) continue;

      // No uses of this specific definition → unused
      const uses = graph.usesOfDef(def.id);
      if (uses.length > 0) continue;

      const key = `${variable}-${def.line}`;
      if (reported.has(key)) continue;
      reported.add(key);

      unusedVars.push({ line: def.line, variable });

      ctx.addFinding({
        id: `unused-variable-${file}-${def.line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-561',
        severity: 'low',
        level: 'note',
        message: `'${variable}' is assigned but its value is never read`,
        file,
        line: def.line,
        snippet: lineText.trim(),
        fix: `Remove the assignment or use the value of '${variable}'`,
        evidence: { variable },
      });
    }

    return { unusedVars };
  }
}
