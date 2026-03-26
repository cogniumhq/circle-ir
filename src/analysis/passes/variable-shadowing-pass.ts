/**
 * Pass #79: variable-shadowing (CWE-1109, category: reliability)
 *
 * Detects when an inner scope declares a variable with the same name as an
 * outer-scope declaration or function parameter, hiding the outer binding and
 * making code harder to reason about.
 *
 * Detection strategy:
 *   1. Build a ScopeGraph to identify which defs are true declarations vs
 *      bare reassignments.
 *   2. For each method, group DFG defs by variable name.
 *   3. Flag two kinds of shadowing within the same method:
 *      - Param shadow  : a `kind='param'` def + a later `kind='local'` def
 *        that is a real declaration (has a decl keyword, or Python which has
 *        no keywords but every local assignment implicitly shadows a param).
 *      - Outer-local shadow : two or more `kind='local'` defs that both have
 *        a declaration keyword (e.g. `let x = 1` then `let x = 2` in a
 *        nested block).
 *
 * Note on Python: Python variables have function scope (not block scope), so
 * two assignments to the same name within a function do NOT shadow each other.
 * However, a local assignment that shares a name with a parameter DOES shadow
 * the parameter (from the assignment point onward). The pass flags that case
 * for Python regardless of `hasDeclKeyword` (since Python has no decl keywords).
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { ScopeGraph } from '../../graph/scope-graph.js';

export interface VariableShadowingResult {
  shadows: Array<{
    /** Line of the shadowing (inner) declaration. */
    line: number;
    variable: string;
    /** Line of the shadowed (outer) declaration or parameter. */
    shadowedAt: number;
    kind: 'param' | 'outer-local';
  }>;
}

export class VariableShadowingPass implements AnalysisPass<VariableShadowingResult> {
  readonly name = 'variable-shadowing';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): VariableShadowingResult {
    const { graph, code, language } = ctx;
    const file = graph.ir.meta.file;
    const scope = new ScopeGraph(graph, code, language);
    const shadows: VariableShadowingResult['shadows'] = [];
    const reported = new Set<string>(); // deduplicate by variable+line

    for (const type of graph.ir.types) {
      for (const method of type.methods) {
        const entries = scope.defsInMethod(method.start_line, method.end_line);

        // Group entries by variable name
        const byVar = new Map<string, typeof entries>();
        for (const entry of entries) {
          const existing = byVar.get(entry.def.variable);
          if (existing) {
            existing.push(entry);
          } else {
            byVar.set(entry.def.variable, [entry]);
          }
        }

        for (const [variable, varEntries] of byVar) {
          if (varEntries.length < 2) continue;

          const params  = varEntries.filter(e => e.def.kind === 'param');
          const locals  = varEntries.filter(e => e.def.kind === 'local');

          // -------------------------------------------------------
          // Case 1: Param shadowed by a local declaration
          // -------------------------------------------------------
          if (params.length > 0 && locals.length > 0) {
            const paramEntry = params[0]!;

            for (const local of locals) {
              // For Python: every assignment to a param name shadows it.
              // For other languages: only flag if the line is a real declaration.
              if (language !== 'python' && !local.hasDeclKeyword) continue;
              if (local.def.line <= paramEntry.def.line) continue;

              const key = `${variable}-${local.def.line}`;
              if (reported.has(key)) continue;
              reported.add(key);

              shadows.push({
                line: local.def.line,
                variable,
                shadowedAt: paramEntry.def.line,
                kind: 'param',
              });

              ctx.addFinding({
                id: `variable-shadowing-${file}-${local.def.line}`,
                pass: this.name,
                category: this.category,
                rule_id: this.name,
                cwe: 'CWE-1109',
                severity: 'medium',
                level: 'warning',
                message:
                  `'${variable}' shadows the parameter declared at line ${paramEntry.def.line}`,
                file,
                line: local.def.line,
                fix: `Rename the inner variable to avoid hiding the parameter '${variable}'`,
                evidence: {
                  variable,
                  outer_kind: 'param',
                  outer_line: paramEntry.def.line,
                },
              });
            }
            continue; // skip outer-local check when params are involved
          }

          // -------------------------------------------------------
          // Case 2: Outer local shadowed by an inner local declaration
          // -------------------------------------------------------
          if (locals.length >= 2) {
            // Python has no decl keywords → skip outer-local shadow for Python
            if (language === 'python') continue;

            // Only consider entries that are true declarations
            const declLocals = locals
              .filter(e => e.hasDeclKeyword)
              .sort((a, b) => a.def.line - b.def.line);

            if (declLocals.length < 2) continue;

            const outerEntry = declLocals[0]!;

            for (let i = 1; i < declLocals.length; i++) {
              const inner = declLocals[i]!;
              const key = `${variable}-${inner.def.line}`;
              if (reported.has(key)) continue;
              reported.add(key);

              shadows.push({
                line: inner.def.line,
                variable,
                shadowedAt: outerEntry.def.line,
                kind: 'outer-local',
              });

              ctx.addFinding({
                id: `variable-shadowing-${file}-${inner.def.line}`,
                pass: this.name,
                category: this.category,
                rule_id: this.name,
                cwe: 'CWE-1109',
                severity: 'medium',
                level: 'warning',
                message:
                  `'${variable}' shadows the outer declaration at line ${outerEntry.def.line}`,
                file,
                line: inner.def.line,
                fix: `Rename the inner variable to avoid hiding the outer '${variable}'`,
                evidence: {
                  variable,
                  outer_kind: 'local',
                  outer_line: outerEntry.def.line,
                },
              });
            }
          }
        }
      }
    }

    return { shadows };
  }
}
