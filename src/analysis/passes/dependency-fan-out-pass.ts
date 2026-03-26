/**
 * Pass #72: dependency-fan-out
 *
 * Flags modules that import an excessive number of other modules (≥20).
 * High fan-out is a coupling smell that makes modules hard to test and modify
 * independently.
 *
 * Category: architecture | Severity: low | Level: note | CWE: none
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { SastFinding } from '../../types/index.js';

export interface DependencyFanOutResult {
  importCount: number;
  exceeded: boolean;
}

const FAN_OUT_THRESHOLD = 20;

export class DependencyFanOutPass implements AnalysisPass<DependencyFanOutResult> {
  readonly name = 'dependency-fan-out';
  readonly category = 'architecture' as const;

  run(ctx: PassContext): DependencyFanOutResult {
    const importCount = ctx.graph.ir.imports.length;
    const exceeded    = importCount >= FAN_OUT_THRESHOLD;

    if (exceeded) {
      const finding: SastFinding = {
        id:       `dependency-fan-out-${ctx.graph.ir.meta.file.replace(/[^a-z0-9]/gi, '-')}`,
        pass:     'dependency-fan-out',
        category: 'architecture',
        rule_id:  'dependency-fan-out',
        severity: 'low',
        level:    'note',
        message:  `Module imports ${importCount} dependencies (threshold: ${FAN_OUT_THRESHOLD}). High fan-out increases coupling and makes the module harder to test.`,
        file:     ctx.graph.ir.meta.file,
        line:     1,
        evidence: { importCount, threshold: FAN_OUT_THRESHOLD },
      };
      ctx.addFinding(finding);
    }

    return { importCount, exceeded };
  }
}
