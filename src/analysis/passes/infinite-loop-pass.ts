/**
 * Pass #28: infinite-loop (CWE-835, category: reliability)
 *
 * Detects loops with no reachable exit edge — i.e., loops that can run
 * forever because every execution path through the loop body leads back to
 * the loop header without a break, return, throw, or continue-to-outer.
 *
 * Detection strategy:
 *   1. Identify loop headers: back-edge targets in the CFG (`edge.type === 'back'`).
 *   2. For each loop, collect the loop body blocks via BFS from the header,
 *      stopping at back-edge sources (the "tail" blocks).
 *   3. Check whether any block in the body has an outgoing edge that exits
 *      the loop (target not in body set and not back to header).
 *   4. As a text-level fallback, scan source lines in the loop body for
 *      `return`, `throw`/`raise`, `break`, `System.exit` keywords.
 *   5. Emit a finding at the loop header's start_line if no exit is found.
 *
 * Languages: Java, JavaScript, TypeScript, Python, Rust. Skip Bash.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Exit keywords to scan for as a text-level fallback. */
const EXIT_KEYWORDS = /\b(return|throw|raise|break|System\.exit|process\.exit|os\._exit|exit!\()\b/;

export interface InfiniteLoopResult {
  potentialInfiniteLoops: Array<{ headerLine: number; bodyEndLine: number }>;
}

export class InfiniteLoopPass implements AnalysisPass<InfiniteLoopResult> {
  readonly name = 'infinite-loop';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): InfiniteLoopResult {
    const { graph, code, language } = ctx;

    if (language === 'bash') {
      return { potentialInfiniteLoops: [] };
    }

    const { blocks, edges } = graph.ir.cfg;
    if (blocks.length === 0) return { potentialInfiniteLoops: [] };

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');

    // Build adjacency maps
    const outgoing = new Map<number, Array<{ to: number; type: string }>>();
    for (const edge of edges) {
      const list = outgoing.get(edge.from) ?? [];
      list.push({ to: edge.to, type: edge.type });
      outgoing.set(edge.from, list);
    }

    // Find back-edges: each back-edge defines a loop
    const backEdges = edges.filter(e => e.type === 'back');

    const potentialInfiniteLoops: InfiniteLoopResult['potentialInfiniteLoops'] = [];
    const reportedHeaders = new Set<number>();

    for (const backEdge of backEdges) {
      const headerId = backEdge.to;
      const tailId = backEdge.from;

      const header = graph.blockById.get(headerId);
      const tail = graph.blockById.get(tailId);
      if (!header || !tail) continue;

      // Deduplicate: one finding per header
      if (reportedHeaders.has(headerId)) continue;

      // Collect loop body blocks via BFS from header, stopping at tail
      const bodyIds = new Set<number>();
      const queue: number[] = [headerId];
      bodyIds.add(headerId);

      while (queue.length > 0) {
        const cur = queue.shift()!;
        for (const { to, type } of outgoing.get(cur) ?? []) {
          // Don't follow back edges (stay inside the loop)
          if (type === 'back') continue;
          if (!bodyIds.has(to)) {
            bodyIds.add(to);
            queue.push(to);
          }
        }
        // Stop expanding from tail (the back-edge source)
        if (cur === tailId) break;
      }

      // Check for any exit edge: an edge from a body block to a non-body block
      let hasExit = false;
      for (const bodyId of bodyIds) {
        for (const { to, type } of outgoing.get(bodyId) ?? []) {
          if (type === 'back') continue;
          if (!bodyIds.has(to)) {
            hasExit = true;
            break;
          }
        }
        if (hasExit) break;
      }

      if (hasExit) continue;

      // Text-level fallback: scan source lines for exit keywords
      const bodyStart = header.start_line;
      const bodyEnd = tail.end_line;
      let hasKeywordExit = false;
      for (let ln = bodyStart; ln <= bodyEnd && ln <= codeLines.length; ln++) {
        if (EXIT_KEYWORDS.test(codeLines[ln - 1] ?? '')) {
          hasKeywordExit = true;
          break;
        }
      }

      if (hasKeywordExit) continue;

      reportedHeaders.add(headerId);
      potentialInfiniteLoops.push({ headerLine: header.start_line, bodyEndLine: bodyEnd });

      const loc = bodyStart === bodyEnd
        ? `line ${bodyStart}`
        : `lines ${bodyStart}–${bodyEnd}`;

      ctx.addFinding({
        id: `infinite-loop-${file}-${header.start_line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-835',
        severity: 'medium',
        level: 'warning',
        message:
          `Potential infinite loop: no reachable break, return, or throw found in loop body (${loc})`,
        file,
        line: header.start_line,
        end_line: bodyEnd > header.start_line ? bodyEnd : undefined,
        fix: 'Ensure the loop has a reachable exit condition (break, return, or throw) on all paths',
      });
    }

    return { potentialInfiniteLoops };
  }
}
