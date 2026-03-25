/**
 * Analysis Pass Interface
 *
 * Defines the contract for modular analysis passes that operate on a CodeGraph.
 * Passes are run sequentially by AnalysisPipeline; each pass reads prior results
 * via context.getResult() and returns a typed result stored under its name.
 */

import type { TaintConfig } from '../types/config.js';
import type { CodeGraph } from './code-graph.js';

/**
 * Context passed to every pass during pipeline execution.
 * Provides shared inputs and access to results from previously-run passes.
 */
export interface PassContext {
  /** The shared graph built once before the pipeline runs. */
  readonly graph: CodeGraph;
  /** Raw source code text. */
  readonly code: string;
  /** Language identifier (java, python, javascript, etc.). */
  readonly language: string;
  /** Merged taint configuration (sources + sinks patterns). */
  readonly config: TaintConfig;

  /**
   * Retrieve the result of a previously-run pass.
   * Throws if the pass has not run yet — check pass ordering.
   */
  getResult<T>(passName: string): T;

  /** Returns true if the named pass has already produced a result. */
  hasResult(passName: string): boolean;
}

/**
 * An analysis pass over a CodeGraph.
 * Each pass has a unique name used to key its result in the pipeline.
 */
export interface AnalysisPass<TResult = unknown> {
  readonly name: string;
  run(context: PassContext): TResult;
}

/**
 * Runs a sequence of AnalysisPasses, threading context between them.
 *
 * Usage:
 *   const results = new AnalysisPipeline()
 *     .add(new TaintMatcherPass(config))
 *     .add(new ConstantPropagationPass(tree))
 *     .run(graph, code, language, config);
 */
export class AnalysisPipeline {
  private readonly passes: AnalysisPass[] = [];

  add<T>(pass: AnalysisPass<T>): this {
    this.passes.push(pass);
    return this;
  }

  run(
    graph: CodeGraph,
    code: string,
    language: string,
    config: TaintConfig,
  ): Map<string, unknown> {
    const results = new Map<string, unknown>();

    const context: PassContext = {
      graph,
      code,
      language,
      config,
      getResult<T>(passName: string): T {
        if (!results.has(passName)) {
          throw new Error(
            `Pass '${passName}' result not available. Check pass ordering.`,
          );
        }
        return results.get(passName) as T;
      },
      hasResult(passName: string): boolean {
        return results.has(passName);
      },
    };

    for (const pass of this.passes) {
      const result = pass.run(context);
      results.set(pass.name, result);
    }

    return results;
  }
}
