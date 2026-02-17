/**
 * Taint Propagation Engine
 *
 * Tracks taint through variable assignments, method returns, and field accesses
 * using the DFG (Data Flow Graph) to find precise source-to-sink paths.
 */

import type {
  DFG,
  DFGDef,
  DFGUse,
  DFGChain,
  CallInfo,
  TaintSource,
  TaintSink,
  TaintSanitizer,
  SinkType,
} from '../types/index.js';

/**
 * Represents a tainted variable at a specific point in the code.
 */
export interface TaintedVariable {
  variable: string;
  defId: number;
  line: number;
  sourceType: string;
  sourceLine: number;
  confidence: number;
}

/**
 * Represents a taint flow from source to sink.
 */
export interface TaintFlow {
  source: TaintSource;
  sink: TaintSink;
  path: TaintFlowStep[];
  sanitized: boolean;
  sanitizer?: TaintSanitizer;
  confidence: number;
}

/**
 * A step in the taint flow path.
 */
export interface TaintFlowStep {
  variable: string;
  line: number;
  type: 'source' | 'assignment' | 'use' | 'return' | 'field' | 'sink';
  description: string;
}

/**
 * Result of taint propagation analysis.
 */
export interface TaintPropagationResult {
  taintedVars: TaintedVariable[];
  flows: TaintFlow[];
  reachableSinks: Map<TaintSink, TaintSource[]>;
}

/**
 * Propagate taint through the dataflow graph.
 */
export function propagateTaint(
  dfg: DFG,
  calls: CallInfo[],
  sources: TaintSource[],
  sinks: TaintSink[],
  sanitizers: TaintSanitizer[]
): TaintPropagationResult {
  const taintedVars: TaintedVariable[] = [];
  const flows: TaintFlow[] = [];
  const reachableSinks = new Map<TaintSink, TaintSource[]>();

  // Build lookup maps
  const defById = new Map<number, DFGDef>();
  const defsByLine = new Map<number, DFGDef[]>();
  const usesByLine = new Map<number, DFGUse[]>();
  const callsByLine = new Map<number, CallInfo[]>();
  const sanitizersByLine = new Map<number, TaintSanitizer[]>();

  for (const def of dfg.defs) {
    defById.set(def.id, def);
    const existing = defsByLine.get(def.line) ?? [];
    existing.push(def);
    defsByLine.set(def.line, existing);
  }

  for (const use of dfg.uses) {
    const existing = usesByLine.get(use.line) ?? [];
    existing.push(use);
    usesByLine.set(use.line, existing);
  }

  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const san of sanitizers) {
    const existing = sanitizersByLine.get(san.line) ?? [];
    existing.push(san);
    sanitizersByLine.set(san.line, existing);
  }

  // Step 1: Identify initial tainted definitions (from sources)
  const initialTaint = findInitialTaint(sources, dfg, callsByLine, defsByLine);
  taintedVars.push(...initialTaint);

  // Step 2: Propagate taint through def-use chains
  const propagatedTaint = propagateThroughChains(
    initialTaint,
    dfg.chains ?? [],
    defById,
    sanitizersByLine
  );
  taintedVars.push(...propagatedTaint);

  // Combine all tainted definitions
  const allTaintedDefIds = new Set<number>();
  const taintByDefId = new Map<number, TaintedVariable>();
  for (const tv of taintedVars) {
    allTaintedDefIds.add(tv.defId);
    taintByDefId.set(tv.defId, tv);
  }

  // Step 3: Check which sinks are reachable from tainted variables
  for (const sink of sinks) {
    const usesAtSink = usesByLine.get(sink.line) ?? [];
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    // Check if any argument to the sink call is tainted
    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        if (arg.variable) {
          // Find if this variable use is tainted
          for (const use of usesAtSink) {
            if (use.variable === arg.variable && use.def_id !== null) {
              if (allTaintedDefIds.has(use.def_id)) {
                const taintInfo = taintByDefId.get(use.def_id);
                if (taintInfo) {
                  // Check if sanitized
                  const isSanitized = checkSanitized(
                    taintInfo.line,
                    sink.line,
                    sink.type,
                    sanitizersByLine
                  );

                  if (!isSanitized.sanitized) {
                    // Find the source
                    const source = sources.find(s => s.line === taintInfo.sourceLine);
                    if (source) {
                      // Record the flow
                      const flow = buildTaintFlow(
                        source,
                        sink,
                        taintInfo,
                        dfg,
                        defById
                      );
                      flows.push(flow);

                      // Record reachable sink
                      const existingSources = reachableSinks.get(sink) ?? [];
                      if (!existingSources.some(s => s.line === source.line)) {
                        existingSources.push(source);
                      }
                      reachableSinks.set(sink, existingSources);
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return { taintedVars, flows, reachableSinks };
}

/**
 * Find initial tainted definitions from sources.
 */
function findInitialTaint(
  sources: TaintSource[],
  dfg: DFG,
  callsByLine: Map<number, CallInfo[]>,
  defsByLine: Map<number, DFGDef[]>
): TaintedVariable[] {
  const tainted: TaintedVariable[] = [];

  for (const source of sources) {
    // Find definitions on the same line as the source
    const defsOnLine = defsByLine.get(source.line) ?? [];

    for (const def of defsOnLine) {
      tainted.push({
        variable: def.variable,
        defId: def.id,
        line: def.line,
        sourceType: source.type,
        sourceLine: source.line,
        confidence: source.confidence,
      });
    }

    // Also check the next line (for cases like: String x = request.getParameter("foo"))
    const defsNextLine = defsByLine.get(source.line + 1) ?? [];
    for (const def of defsNextLine) {
      // Only include if there's a call on the source line
      const callsOnSourceLine = callsByLine.get(source.line) ?? [];
      if (callsOnSourceLine.length > 0) {
        tainted.push({
          variable: def.variable,
          defId: def.id,
          line: def.line,
          sourceType: source.type,
          sourceLine: source.line,
          confidence: source.confidence * 0.9, // Slightly lower confidence
        });
      }
    }
  }

  return tainted;
}

/**
 * Propagate taint through def-use chains.
 */
function propagateThroughChains(
  initialTaint: TaintedVariable[],
  chains: DFGChain[],
  defById: Map<number, DFGDef>,
  sanitizersByLine: Map<number, TaintSanitizer[]>
): TaintedVariable[] {
  const propagated: TaintedVariable[] = [];
  const taintedDefIds = new Set<number>(initialTaint.map(t => t.defId));
  const taintInfoByDefId = new Map<number, TaintedVariable>();

  for (const t of initialTaint) {
    taintInfoByDefId.set(t.defId, t);
  }

  // Build adjacency list for chains
  const chainsByFromDef = new Map<number, DFGChain[]>();
  for (const chain of chains) {
    const existing = chainsByFromDef.get(chain.from_def) ?? [];
    existing.push(chain);
    chainsByFromDef.set(chain.from_def, existing);
  }

  // BFS to propagate taint
  const queue = [...initialTaint.map(t => t.defId)];
  const visited = new Set<number>(queue);

  while (queue.length > 0) {
    const currentDefId = queue.shift()!;
    const currentTaint = taintInfoByDefId.get(currentDefId);
    if (!currentTaint) continue;

    const outgoingChains = chainsByFromDef.get(currentDefId) ?? [];

    for (const chain of outgoingChains) {
      if (visited.has(chain.to_def)) continue;

      const targetDef = defById.get(chain.to_def);
      if (!targetDef) continue;

      // Check if there's a sanitizer between source and this def
      const sanitizeCheck = checkSanitized(
        currentTaint.sourceLine,
        targetDef.line,
        currentTaint.sourceType,
        sanitizersByLine
      );

      if (!sanitizeCheck.sanitized) {
        const newTaint: TaintedVariable = {
          variable: targetDef.variable,
          defId: targetDef.id,
          line: targetDef.line,
          sourceType: currentTaint.sourceType,
          sourceLine: currentTaint.sourceLine,
          confidence: currentTaint.confidence * 0.95, // Decay confidence slightly
        };

        propagated.push(newTaint);
        taintedDefIds.add(targetDef.id);
        taintInfoByDefId.set(targetDef.id, newTaint);
        visited.add(targetDef.id);
        queue.push(targetDef.id);
      }
    }
  }

  return propagated;
}

/**
 * Check if a taint flow is sanitized between two points.
 */
function checkSanitized(
  _fromLine: number,
  _toLine: number,
  _sinkType: string,
  _sanitizersByLine: Map<number, TaintSanitizer[]>
): { sanitized: boolean; sanitizer?: TaintSanitizer } {
  // NOTE: The previous line-based sanitizer check was too aggressive.
  // It would mark a flow as sanitized if ANY sanitizer existed between
  // source and sink lines, even if that sanitizer was applied to a
  // different variable (e.g., clean = sanitize(name); println(name);)
  //
  // The correct approach is to rely on:
  // 1. DFG-based tracking - the tainted variable must flow through a sanitizer
  // 2. The analyzer's sanitizedVars from constant propagation - which correctly
  //    tracks which specific variables were sanitized
  //
  // For now, return false and let the higher-level filtering handle sanitization.
  // This prevents false negatives where unsanitized variables are incorrectly
  // marked as safe just because a sanitizer exists somewhere on adjacent lines.
  return { sanitized: false };
}

/**
 * Build a taint flow path from source to sink.
 */
function buildTaintFlow(
  source: TaintSource,
  sink: TaintSink,
  taintInfo: TaintedVariable,
  dfg: DFG,
  defById: Map<number, DFGDef>
): TaintFlow {
  const path: TaintFlowStep[] = [];

  // Start with source
  path.push({
    variable: taintInfo.variable,
    line: source.line,
    type: 'source',
    description: `Tainted data enters via ${source.type}`,
  });

  // Add intermediate assignments if we can trace them
  // For now, just add the tainted variable assignment
  if (taintInfo.line !== source.line) {
    path.push({
      variable: taintInfo.variable,
      line: taintInfo.line,
      type: 'assignment',
      description: `Tainted value assigned to ${taintInfo.variable}`,
    });
  }

  // End with sink
  path.push({
    variable: taintInfo.variable,
    line: sink.line,
    type: 'sink',
    description: `Tainted value reaches ${sink.type} sink`,
  });

  return {
    source,
    sink,
    path,
    sanitized: false,
    confidence: taintInfo.confidence * 0.9, // Factor in path length
  };
}

/**
 * Analyze method returns to propagate taint through return values.
 */
export function analyzeMethodReturns(
  dfg: DFG,
  calls: CallInfo[],
  taintedVars: TaintedVariable[]
): TaintedVariable[] {
  const additionalTaint: TaintedVariable[] = [];
  const taintedDefIds = new Set(taintedVars.map(t => t.defId));

  // Find return statements that return tainted values
  const returnDefs = dfg.defs.filter(d => d.kind === 'return');

  // For each return def, check if the returned value is tainted
  for (const returnDef of returnDefs) {
    // Find uses on the same line that might be the returned value
    const usesOnLine = dfg.uses.filter(u => u.line === returnDef.line);

    for (const use of usesOnLine) {
      if (use.def_id !== null && taintedDefIds.has(use.def_id)) {
        // This return statement returns a tainted value
        // Now find calls to this method and taint their results
        // (This would require method-level analysis which we'll add later)
      }
    }
  }

  return additionalTaint;
}

/**
 * Calculate confidence score for a taint flow.
 */
export function calculateFlowConfidence(flow: TaintFlow): number {
  let confidence = 1.0;

  // Factor 1: Source confidence
  confidence *= flow.source.confidence;

  // Factor 2: Path length (longer paths = less confident)
  const pathLength = flow.path.length;
  confidence *= Math.pow(0.95, pathLength - 2); // -2 for source and sink

  // Factor 3: Sanitization
  if (flow.sanitized) {
    confidence = 0;
  }

  return Math.max(0, Math.min(1, confidence));
}

/**
 * Get summary statistics for taint propagation.
 */
export function getTaintStats(result: TaintPropagationResult): {
  totalTaintedVars: number;
  totalFlows: number;
  flowsBySinkType: Map<string, number>;
  avgConfidence: number;
} {
  const flowsBySinkType = new Map<string, number>();

  for (const flow of result.flows) {
    const count = flowsBySinkType.get(flow.sink.type) ?? 0;
    flowsBySinkType.set(flow.sink.type, count + 1);
  }

  const avgConfidence = result.flows.length > 0
    ? result.flows.reduce((sum, f) => sum + f.confidence, 0) / result.flows.length
    : 0;

  return {
    totalTaintedVars: result.taintedVars.length,
    totalFlows: result.flows.length,
    flowsBySinkType,
    avgConfidence,
  };
}
