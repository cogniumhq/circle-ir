/**
 * Pass #22: dead-code (CWE-561, category: reliability)
 *
 * Detects CFG blocks that are structurally unreachable from the entry block
 * (i.e., no path of control-flow edges leads to them). This is pure CFG
 * reachability — independent of constant-propagation or taint analysis.
 *
 * Examples: code after an unconditional `return`/`throw`, branches of
 * `if (false)` where the condition is a literal (compiler-level dead code).
 *
 * Note: semantic dead code eliminated by constant propagation (e.g.,
 * `if (DEBUG_MODE) { ... }` where DEBUG_MODE is a compile-time constant)
 * is handled by ConstantPropagationPass, not this pass.
 */

import type { CFGBlock } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

export interface DeadCodePassResult {
  /** CFG blocks with no incoming reachable path from the entry block. */
  deadBlocks: CFGBlock[];
}

export class DeadCodePass implements AnalysisPass<DeadCodePassResult> {
  readonly name = 'dead-code';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): DeadCodePassResult {
    const { graph } = ctx;
    const { blocks, edges } = graph.ir.cfg;
    const file = graph.ir.meta.file;

    if (blocks.length === 0) return { deadBlocks: [] };

    // Build outgoing adjacency: block id → reachable block ids
    const outgoing = new Map<number, number[]>();
    for (const edge of edges) {
      let list = outgoing.get(edge.from);
      if (!list) { list = []; outgoing.set(edge.from, list); }
      list.push(edge.to);
    }

    // Find entry: prefer type='entry', then first block with no incoming edges,
    // then the block with the lowest id as a last resort.
    const hasIncoming = new Set(edges.map(e => e.to));
    const entryBlock =
      blocks.find(b => b.type === 'entry') ??
      blocks.find(b => !hasIncoming.has(b.id)) ??
      blocks.reduce((a, b) => (a.id < b.id ? a : b));

    // BFS from entry to mark all reachable block ids.
    const reachable = new Set<number>([entryBlock.id]);
    const queue: number[] = [entryBlock.id];
    while (queue.length > 0) {
      const id = queue.shift()!;
      for (const next of outgoing.get(id) ?? []) {
        if (!reachable.has(next)) {
          reachable.add(next);
          queue.push(next);
        }
      }
    }

    // Collect unreachable blocks that are worth reporting:
    // - not the entry or exit sentinel blocks
    // - have a positive start line (skip synthetic 0-line blocks)
    const deadBlocks: CFGBlock[] = [];
    for (const block of blocks) {
      if (reachable.has(block.id)) continue;
      if (block.type === 'entry' || block.type === 'exit') continue;
      if (block.start_line <= 0) continue;

      deadBlocks.push(block);

      const loc = block.start_line === block.end_line
        ? `line ${block.start_line}`
        : `lines ${block.start_line}–${block.end_line}`;

      ctx.addFinding({
        id: `dead-code-${file}-${block.start_line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-561',
        severity: 'low',
        level: 'warning',
        message: `Dead code at ${loc}: block is unreachable from any entry point`,
        file,
        line: block.start_line,
        end_line: block.end_line > block.start_line ? block.end_line : undefined,
        fix: 'Remove the unreachable block or fix the control flow that precedes it',
      });
    }

    return { deadBlocks };
  }
}
