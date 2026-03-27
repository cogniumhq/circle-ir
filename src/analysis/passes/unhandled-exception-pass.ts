/**
 * Pass #30: unhandled-exception (CWE-390, category: reliability)
 *
 * Detects explicit throw/raise statements that are not covered by any
 * try/catch in the same function.  Uncaught exceptions surface as
 * unhandled-rejection crashes (Node.js) or propagate unexpectedly to
 * callers who may not anticipate them.
 *
 * Detection strategy (conservative, low false-positive):
 *   1. Build ExceptionFlowGraph.  Derive "covered" line ranges as
 *      [tryBlock.start_line, catchBlock.start_line − 1] for each pair.
 *   2. Scan source lines for explicit throw/raise keywords.
 *   3. Skip if the throw line is already inside a catch block (re-throw).
 *   4. Skip if the throw line falls within any covered range.
 *   5. Emit one finding per enclosing method (avoid duplicate findings for
 *      multiple throws in the same uncovered method).
 *
 * Languages: JavaScript, TypeScript, Python only.
 *   - Java: checked exceptions are intentionally propagated via `throws`;
 *     too noisy without type hierarchy support.
 *   - Rust/Bash: no traditional throw/raise; skip.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { ExceptionFlowGraph } from '../../graph/exception-flow-graph.js';

const JS_THROW_RE = /^\s*throw\s+/;
const PYTHON_RAISE_RE = /^\s*raise\b/;

export interface UnhandledExceptionResult {
  unhandled: Array<{ line: number; method: string }>;
}

export class UnhandledExceptionPass implements AnalysisPass<UnhandledExceptionResult> {
  readonly name = 'unhandled-exception';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): UnhandledExceptionResult {
    const { graph, code, language } = ctx;

    if (language !== 'javascript' && language !== 'typescript' && language !== 'python') {
      return { unhandled: [] };
    }

    const { cfg } = graph.ir;
    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');

    const exGraph = new ExceptionFlowGraph(cfg, graph.blockById);

    // Build covered ranges: [tryBlock.start_line, catchBlock.start_line - 1]
    const coveredRanges: Array<{ start: number; end: number }> = [];
    for (const pair of exGraph.pairs) {
      if (pair.catchBlock.start_line > pair.tryBlock.start_line) {
        coveredRanges.push({
          start: pair.tryBlock.start_line,
          end: pair.catchBlock.start_line - 1,
        });
      }
    }

    // Collect catch-block start lines (to detect re-throws)
    const catchStarts = new Set<number>(
      exGraph.pairs.map(p => p.catchBlock.start_line),
    );

    const throwRe = language === 'python' ? PYTHON_RAISE_RE : JS_THROW_RE;

    const unhandled: UnhandledExceptionResult['unhandled'] = [];
    const reportedMethods = new Set<string>();

    for (let ln = 1; ln <= codeLines.length; ln++) {
      const lineText = codeLines[ln - 1] ?? '';
      if (!throwRe.test(lineText)) continue;

      // Skip re-throws inside catch blocks
      let inCatch = false;
      for (const cs of catchStarts) {
        if (ln >= cs) { inCatch = true; break; }
      }
      // More precise: only skip if ln is actually within a catch body
      // (not just any line after a catch start). Use method boundary check.
      // Simplified: if the line is >= any catch start within the same method, skip.
      // Better heuristic: check if any pair has catchBlock.start_line <= ln
      // and the throw is inside that catch body (ln <= methodEnd of that catch).
      // We use a simple check: if the throw line is >= a catch start and
      // the enclosing method contains the corresponding try, treat as re-throw.
      inCatch = false;
      for (const pair of exGraph.pairs) {
        if (ln >= pair.catchBlock.start_line) {
          // Check same method
          const mThrow = graph.methodAtLine(ln);
          const mCatch = graph.methodAtLine(pair.catchBlock.start_line);
          if (
            mThrow &&
            mCatch &&
            mThrow.method.start_line === mCatch.method.start_line
          ) {
            inCatch = true;
            break;
          }
        }
      }
      if (inCatch) continue;

      // Check if covered by a try/catch range
      const isCovered = coveredRanges.some(r => ln >= r.start && ln <= r.end);
      if (isCovered) continue;

      // Deduplicate by enclosing method
      const methodInfo = graph.methodAtLine(ln);
      const methodKey = methodInfo
        ? `${methodInfo.method.start_line}-${methodInfo.method.end_line}`
        : `global-${ln}`;

      if (reportedMethods.has(methodKey)) continue;
      reportedMethods.add(methodKey);

      const methodName = methodInfo?.method.name ?? '<anonymous>';
      unhandled.push({ line: ln, method: methodName });

      const snippet = lineText.trim();
      ctx.addFinding({
        id: `unhandled-exception-${file}-${ln}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-390',
        severity: 'medium',
        level: 'warning',
        message:
          `Unhandled exception: \`throw\` at line ${ln} in \`${methodName}\` is not inside ` +
          `a try/catch — callers receive an unexpected exception`,
        file,
        line: ln,
        snippet,
        fix: 'Wrap throwing code in a try/catch, or document the exception in the function signature',
        evidence: { method: methodName },
      });
    }

    return { unhandled };
  }
}
