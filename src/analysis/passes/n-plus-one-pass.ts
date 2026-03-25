/**
 * Pass #45: n-plus-one (CWE-1049, category: performance)
 *
 * Detects calls to database or external-API methods that occur inside a loop
 * body, producing N+1 round-trips instead of a single batch query.
 *
 * Detection uses two signals:
 *   1. The call line falls inside a loop body identified by a CFG back-edge
 *      (`graph.loopBodies()`).
 *   2. The method name (and optionally its receiver) matches a curated set of
 *      DB / HTTP / ORM patterns.
 *
 * Precision strategy:
 *   - High-confidence method names (e.g. `executeQuery`, `findUnique`) are
 *     flagged regardless of receiver.
 *   - Medium-confidence names (e.g. `find`, `save`, `get`) require a receiver
 *     that looks like a DB/HTTP client.
 */

import type { CallInfo } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/**
 * Methods that strongly imply a DB query or external I/O, regardless of receiver.
 * Only names with virtually no non-DB usage at this level of confidence.
 */
const HIGH_CONFIDENCE_DB_METHODS: ReadonlySet<string> = new Set([
  // JDBC / raw SQL
  'executeQuery', 'executeUpdate', 'prepareStatement', 'prepareCall',
  // Spring Data / JPA
  'findById', 'findAll', 'saveAll', 'deleteById', 'existsById',
  // Mongoose
  'findByIdAndUpdate', 'findByIdAndDelete',
  'findOneAndUpdate', 'findOneAndDelete',
  'countDocuments', 'aggregate', 'distinct',
  // Sequelize
  'findByPk', 'findAndCountAll', 'bulkCreate', 'bulkUpdate',
  // Prisma
  'findFirst', 'findUnique', 'findMany', 'createMany', 'updateMany', 'deleteMany',
  // Network
  'fetch',
]);

/**
 * Methods that may be DB/HTTP calls — flag only when the receiver looks like
 * a database or HTTP client.
 */
const MEDIUM_CONFIDENCE_DB_METHODS: ReadonlySet<string> = new Set([
  'query', 'execute', 'find', 'findOne',
  'save', 'create', 'update', 'delete', 'insert', 'upsert', 'remove',
  'get', 'post', 'put', 'patch', 'request',
  'load', 'lookup',
]);

/** Receiver names that indicate a DB or HTTP client. */
const DB_OR_HTTP_RECEIVER = /^(db|conn|connection|pool|client|repo|repository|orm|em|entityManager|sequelize|mongoose|prisma|axios|http|https|api|svc|service|dao|store|cache|gql|graphql)/i;

function isDbOrApiCall(call: CallInfo): boolean {
  if (HIGH_CONFIDENCE_DB_METHODS.has(call.method_name)) return true;
  if (MEDIUM_CONFIDENCE_DB_METHODS.has(call.method_name)) {
    return call.receiver != null && DB_OR_HTTP_RECEIVER.test(call.receiver);
  }
  return false;
}

export interface NPlusOnePassResult {
  /** Calls inside loop bodies that hit a DB or external API. */
  loopDbCalls: CallInfo[];
}

export class NPlusOnePass implements AnalysisPass<NPlusOnePassResult> {
  readonly name = 'n-plus-one';
  readonly category = 'performance' as const;

  run(ctx: PassContext): NPlusOnePassResult {
    const { graph } = ctx;
    const file = graph.ir.meta.file;

    const loops = graph.loopBodies();
    if (loops.length === 0) return { loopDbCalls: [] };

    const loopDbCalls: CallInfo[] = [];

    for (const call of graph.ir.calls) {
      if (!isDbOrApiCall(call)) continue;

      const line = call.location.line;
      const loop = loops.find(l => line >= l.start_line && line <= l.end_line);
      if (!loop) continue;

      loopDbCalls.push(call);

      ctx.addFinding({
        id: `n-plus-one-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-1049',
        severity: 'medium',
        level: 'warning',
        message:
          `N+1 query: \`${call.method_name}()\` is called inside a loop ` +
          `(loop lines ${loop.start_line}–${loop.end_line}) — consider batching`,
        file,
        line,
        fix: `Move \`${call.method_name}()\` outside the loop and batch the operation`,
        evidence: {
          loop_start: loop.start_line,
          loop_end: loop.end_line,
          receiver: call.receiver ?? undefined,
        },
      });
    }

    return { loopDbCalls };
  }
}
