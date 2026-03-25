/**
 * Circle-IR Analyzer
 *
 * Main entry point for analyzing source code and producing Circle-IR output.
 * This is the core static analyzer. LLM-based verification and discovery are out of scope for this library.
 *
 * The analysis pipeline runs six sequential passes over a shared CodeGraph:
 *   1. TaintMatcherPass        — config-based source/sink extraction
 *   2. ConstantPropagationPass — dead-code detection, symbol table, field taint
 *   3. LanguageSourcesPass     — language-specific sources/sinks (JS, Python, getters)
 *   4. SinkFilterPass          — four-stage false-positive elimination
 *   5. TaintPropagationPass    — DFG-based flow verification
 *   6. InterproceduralPass     — cross-method taint propagation
 */

import type { CircleIR, AnalysisResponse, Vulnerability, Enriched, ProjectAnalysis, ProjectMeta } from './types/index.js';
import type { TaintConfig } from './types/config.js';
import {
  initParser,
  parse,
  extractMeta,
  extractTypes,
  extractCalls,
  extractImports,
  extractExports,
  buildCFG,
  buildDFG,
  collectAllNodes,
  type SupportedLanguage,
} from './core/index.js';
import {
  analyzeTaint,
  getDefaultConfig,
  detectUnresolved,
  analyzeConstantPropagation,
  isFalsePositive,
} from './analysis/index.js';
import { registerBuiltinPlugins } from './languages/index.js';
import { logger } from './utils/logger.js';
import { CodeGraph, AnalysisPipeline, ProjectGraph } from './graph/index.js';
import { CrossFilePass } from './analysis/passes/cross-file-pass.js';

// Pass classes
import { TaintMatcherPass } from './analysis/passes/taint-matcher-pass.js';
import { ConstantPropagationPass } from './analysis/passes/constant-propagation-pass.js';
import { LanguageSourcesPass } from './analysis/passes/language-sources-pass.js';
import { SinkFilterPass, filterCleanVariableSinks, filterSanitizedSinks } from './analysis/passes/sink-filter-pass.js';
import { TaintPropagationPass } from './analysis/passes/taint-propagation-pass.js';
import { InterproceduralPass } from './analysis/passes/interprocedural-pass.js';

// Helpers used by analyzeForAPI
import {
  buildPythonTaintedVars,
  buildPythonSanitizedVars,
  findPythonTrustBoundaryViolations,
} from './analysis/passes/language-sources-pass.js';

// Pass result types (used to read typed results from the pipeline map)
import type { SinkFilterResult } from './analysis/passes/sink-filter-pass.js';
import type { InterproceduralPassResult } from './analysis/passes/interprocedural-pass.js';

export interface AnalyzerOptions {
  /**
   * Path to tree-sitter.wasm for parser initialization.
   */
  wasmPath?: string;

  /**
   * Pre-compiled WebAssembly.Module for tree-sitter.wasm.
   * For Cloudflare Workers where dynamic WASM compilation is blocked.
   */
  wasmModule?: WebAssembly.Module;

  /**
   * Paths to language-specific WASM files.
   */
  languagePaths?: Partial<Record<SupportedLanguage, string>>;

  /**
   * Pre-compiled WebAssembly.Module for language grammars.
   * For Cloudflare Workers where dynamic WASM compilation is blocked.
   */
  languageModules?: Partial<Record<SupportedLanguage, WebAssembly.Module>>;

  /**
   * Custom taint configuration.
   */
  taintConfig?: TaintConfig;
}

let initialized = false;

/**
 * Initialize the analyzer. Must be called before analyze().
 */
export async function initAnalyzer(options: AnalyzerOptions = {}): Promise<void> {
  if (initialized) return;

  // Register built-in language plugins
  registerBuiltinPlugins();

  await initParser({
    wasmPath: options.wasmPath,
    wasmModule: options.wasmModule,
    languagePaths: options.languagePaths,
    languageModules: options.languageModules,
  });

  initialized = true;
}

/**
 * Build enriched metadata section from analysis results.
 */
function buildEnriched(
  types: CircleIR['types'],
  _calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks']
): Enriched {
  // Classify functions by role based on analysis
  const functions: Enriched['functions'] = [];

  for (const type of types) {
    for (const method of type.methods) {
      // Determine role based on annotations and naming
      let role: 'controller' | 'service' | 'repository' | 'utility' = 'utility';
      let trustBoundary: 'entry_point' | 'internal' | 'external' = 'internal';

      // Check for controller annotations
      if (method.annotations.some(a =>
        a.includes('RequestMapping') ||
        a.includes('GetMapping') ||
        a.includes('PostMapping') ||
        a.includes('RestController') ||
        a.includes('Controller')
      )) {
        role = 'controller';
        trustBoundary = 'entry_point';
      }
      // Check for repository/DAO patterns
      else if (type.name.toLowerCase().includes('repository') ||
               type.name.toLowerCase().includes('dao') ||
               method.annotations.some(a => a.includes('Repository'))) {
        role = 'repository';
      }
      // Check for service patterns
      else if (type.name.toLowerCase().includes('service') ||
               method.annotations.some(a => a.includes('Service'))) {
        role = 'service';
      }

      // Determine risk level
      const hasSources = sources.some(s => s.method === method.name);
      const hasSinks = sinks.some(s => s.method === method.name);
      let risk: 'critical' | 'high' | 'medium' | 'low' = 'low';
      if (hasSinks) risk = 'high';
      else if (hasSources) risk = 'medium';

      // Only include functions with meaningful roles
      if (role !== 'utility' || risk !== 'low') {
        functions.push({
          method_name: `${type.name}.${method.name}`,
          role,
          risk,
          trust_boundary: trustBoundary,
          summary: `${role} method in ${type.name}`,
        });
      }
    }
  }

  return {
    functions: functions.length > 0 ? functions : undefined,
  };
}

// ---------------------------------------------------------------------------
// Node type collection — shared by analyze() and analyzeForAPI()
// ---------------------------------------------------------------------------

function getNodeTypesForLanguage(language: SupportedLanguage): Set<string> {
  switch (language) {
    case 'rust':
      return new Set([
        'call_expression', 'macro_invocation', 'function_item', 'struct_item',
        'impl_item', 'enum_item', 'trait_item', 'mod_item', 'use_declaration',
        'let_declaration', 'field_expression', 'scoped_identifier',
      ]);
    case 'python':
      return new Set([
        'call', 'function_definition', 'class_definition', 'import_statement',
        'import_from_statement', 'assignment', 'attribute', 'subscript',
      ]);
    case 'javascript':
    case 'typescript':
      return new Set([
        'call_expression', 'new_expression', 'class_declaration', 'function_declaration',
        'arrow_function', 'method_definition', 'variable_declaration', 'lexical_declaration',
        'import_statement', 'export_statement', 'member_expression', 'assignment_expression',
      ]);
    case 'bash':
      return new Set([
        'command', 'function_definition', 'variable_assignment', 'declaration_command',
        'if_statement', 'for_statement', 'c_style_for_statement', 'while_statement',
      ]);
    default:
      return new Set([
        'method_invocation', 'object_creation_expression', 'class_declaration',
        'method_declaration', 'constructor_declaration', 'field_declaration',
        'import_declaration', 'interface_declaration', 'enum_declaration',
      ]);
  }
}

// ---------------------------------------------------------------------------
// Main analysis function
// ---------------------------------------------------------------------------

/**
 * Analyze source code and produce Circle-IR output.
 */
export async function analyze(
  code: string,
  filePath: string,
  language: SupportedLanguage,
  options: AnalyzerOptions = {}
): Promise<CircleIR> {
  if (!initialized) {
    await initAnalyzer(options);
  }

  logger.debug('Analyzing file', { filePath, language, codeLength: code.length });

  // Parse the code
  const tree = await parse(code, language);
  logger.trace('Parsed AST', { rootNodeType: tree.rootNode.type });

  // Collect all node types in a single traversal for better performance
  const nodeCache = collectAllNodes(tree.rootNode, getNodeTypesForLanguage(language));

  // Extract all IR components
  const meta    = extractMeta(code, tree, filePath, language);
  const types   = extractTypes(tree, nodeCache, language);
  const calls   = extractCalls(tree, nodeCache, language);
  const imports = extractImports(tree, language);
  const exports = extractExports(types);
  const cfg     = buildCFG(tree, language);
  const dfg     = buildDFG(tree, nodeCache, language);

  // Build CodeGraph once — shared across all passes.
  // Taint is empty at construction time; sources/sinks/sanitizers are populated by passes.
  const graph = new CodeGraph({
    meta, types, calls, cfg, dfg,
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports, exports, unresolved: [], enriched: {},
  });

  const config = options.taintConfig ?? getDefaultConfig();

  // Run the analysis pipeline
  const results = new AnalysisPipeline()
    .add(new TaintMatcherPass())
    .add(new ConstantPropagationPass(tree))
    .add(new LanguageSourcesPass())
    .add(new SinkFilterPass())
    .add(new TaintPropagationPass())
    .add(new InterproceduralPass())
    .run(graph, code, language, config);

  const sinkFilter = results.get('sink-filter')    as SinkFilterResult;
  const interProc  = results.get('interprocedural') as InterproceduralPassResult;

  const taint: CircleIR['taint'] = {
    sources:    sinkFilter.sources,
    sinks:      [...sinkFilter.sinks, ...interProc.additionalSinks],
    sanitizers: sinkFilter.sanitizers,
    flows:      interProc.additionalFlows,
    interprocedural: interProc.interprocedural,
  };

  const unresolved = detectUnresolved(calls, types, dfg);
  const enriched   = buildEnriched(types, calls, taint.sources, taint.sinks);

  logger.debug('Analysis complete', {
    filePath,
    finalSources: taint.sources.length,
    finalSinks:   taint.sinks.length,
    flows:        taint.flows?.length ?? 0,
    unresolvedItems: unresolved.length,
  });

  return { meta, types, calls, cfg, dfg, taint, imports, exports, unresolved, enriched };
}

// ---------------------------------------------------------------------------
// Simplified API response format
// ---------------------------------------------------------------------------

/**
 * Analyze code and return a simplified API response format.
 */
export async function analyzeForAPI(
  code: string,
  filePath: string,
  language: SupportedLanguage,
  options: AnalyzerOptions = {}
): Promise<AnalysisResponse> {
  const startTime = performance.now();

  if (!initialized) {
    await initAnalyzer(options);
  }

  const parseStart = performance.now();
  const tree = await parse(code, language);
  const parseTime = performance.now() - parseStart;

  const analysisStart = performance.now();

  const nodeCache = collectAllNodes(tree.rootNode, getNodeTypesForLanguage(language));

  const types = extractTypes(tree, nodeCache, language);
  const calls = extractCalls(tree, nodeCache, language);

  // Run constant propagation
  const constPropResult = analyzeConstantPropagation(tree, code);

  const config = options.taintConfig ?? getDefaultConfig();
  const taint = analyzeTaint(calls, types, config);

  // Filter sinks in dead code
  let filteredSinks = taint.sinks.filter(sink => !constPropResult.unreachableLines.has(sink.line));

  // Filter sinks whose arguments are proven clean (string literals, constants, etc.)
  filteredSinks = filterCleanVariableSinks(
    filteredSinks,
    calls,
    constPropResult.tainted,
    constPropResult.symbols,
    undefined,
    constPropResult.sanitizedVars,
    constPropResult.synchronizedLines
  );

  // Filter sinks wrapped by sanitizers on the same line
  filteredSinks = filterSanitizedSinks(filteredSinks, taint.sanitizers ?? [], calls);

  // Python: reduce XPath false-positives using forward taint propagation +
  // apostrophe-guard sanitizer detection.
  let pythonTaintedVars: Map<string, number> = new Map();
  if (language === 'python') {
    pythonTaintedVars = buildPythonTaintedVars(code);
    const pythonSanitizedVars = buildPythonSanitizedVars(code, pythonTaintedVars);
    const sourceLines = code.split('\n');
    filteredSinks = filteredSinks.filter(sink => {
      if (sink.type !== 'xpath_injection') return true;
      const sinkLineText = sourceLines[sink.line - 1] ?? '';
      const taintedVarOnLine = [...pythonTaintedVars.keys()].find(v =>
        new RegExp(`\\b${v}\\b`).test(sinkLineText)
      );
      if (!taintedVarOnLine) return false;
      if (pythonSanitizedVars.has(taintedVarOnLine)) return false;
      if (new RegExp(`\\.xpath\\s*\\([^)]*\\b\\w+\\s*=\\s*\\b${taintedVarOnLine}\\b`).test(sinkLineText)) return false;
      return true;
    });
  }

  // Generate vulnerabilities from source-sink pairs
  const vulnerabilities = findVulnerabilities(taint.sources, filteredSinks, calls, constPropResult);

  // Python: detect trust boundary violations (flask.session[key] = taintedVal)
  if (language === 'python') {
    const trustViolations = findPythonTrustBoundaryViolations(code, pythonTaintedVars);
    for (const v of trustViolations) {
      const alreadyReported = vulnerabilities.some(
        existing => existing.sink.line === v.sinkLine && existing.type === 'trust_boundary'
      );
      if (!alreadyReported) {
        vulnerabilities.push({
          type: 'trust_boundary',
          cwe: 'CWE-501',
          severity: 'medium',
          source: { line: v.sourceLine, type: 'http_param' },
          sink: { line: v.sinkLine, type: 'trust_boundary' },
          confidence: 0.85,
        });
      }
    }
  }

  const analysisTime = performance.now() - analysisStart;
  const totalTime = performance.now() - startTime;

  return {
    success: true,
    analysis: {
      sources: taint.sources,
      sinks: filteredSinks,
      vulnerabilities,
    },
    meta: {
      parseTimeMs: Math.round(parseTime),
      analysisTimeMs: Math.round(analysisTime),
      totalTimeMs: Math.round(totalTime),
    },
  };
}

// ---------------------------------------------------------------------------
// Vulnerability matching (used by analyzeForAPI)
// ---------------------------------------------------------------------------

/**
 * Find potential vulnerabilities by matching sources to sinks.
 */
function findVulnerabilities(
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  calls?: CircleIR['calls'],
  constPropResult?: { tainted: Set<string>; symbols: Map<string, { type: string; value: unknown }> }
): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  const sourceToSinkMapping: Record<string, string[]> = {
    http_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'xpath_injection', 'ldap_injection', 'ssrf'],
    http_body: ['sql_injection', 'command_injection', 'deserialization', 'xxe', 'xss', 'code_injection'],
    http_header: ['sql_injection', 'xss', 'ssrf'],
    http_cookie: ['sql_injection', 'xss'],
    http_path: ['path_traversal', 'sql_injection', 'ssrf'],
    http_query: ['sql_injection', 'command_injection', 'xss', 'ssrf'],
    io_input: ['command_injection', 'path_traversal', 'deserialization', 'xxe', 'code_injection', 'xss'],
    env_input: ['command_injection', 'path_traversal'],
    db_input: ['xss', 'sql_injection'],
    file_input: ['deserialization', 'xxe', 'path_traversal', 'command_injection', 'code_injection', 'xss'],
    network_input: ['sql_injection', 'command_injection', 'xss', 'ssrf'],
    config_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'ssrf'],
    interprocedural_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'xpath_injection', 'ldap_injection', 'ssrf', 'code_injection'],
    plugin_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'code_injection'],
    constructor_field: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'xpath_injection', 'ldap_injection', 'ssrf', 'code_injection', 'deserialization', 'xxe'],
  };

  for (const source of sources) {
    const potentialSinks = sourceToSinkMapping[source.type] ?? [];

    for (const sink of sinks) {
      if (potentialSinks.includes(sink.type)) {
        // Check if we have constant propagation data to verify actual taint flow
        if (calls && constPropResult) {
          const sinkCall = calls.find(c => c.location.line === sink.line);
          if (sinkCall) {
            if (sink.type === 'sql_injection' && sinkCall.arguments.length > 0) {
              const queryArg = sinkCall.arguments[0];
              if (queryArg.variable) {
                const isConstant = constPropResult.symbols.has(queryArg.variable) &&
                  constPropResult.symbols.get(queryArg.variable)?.type === 'string';
                const isTainted = constPropResult.tainted.has(queryArg.variable);
                if (isConstant && !isTainted) {
                  continue;
                }
              }
              if (queryArg.expression) {
                const hasConcatenation = queryArg.expression.includes('+');
                if (!hasConcatenation) {
                  const anyArgTainted = sinkCall.arguments.some(arg =>
                    arg.variable && constPropResult.tainted.has(arg.variable)
                  );
                  if (!anyArgTainted || !queryArg.expression?.includes('+')) {
                    const queryValue = constPropResult.symbols.get(queryArg.variable || '')?.value;
                    if (typeof queryValue === 'string' &&
                        (queryValue.includes('?') || queryValue.includes('$') || queryValue.includes(':'))) {
                      continue;
                    }
                  }
                }
              }
            }
          }
        }

        const confidence = calculateVulnConfidence(source, sink);

        vulnerabilities.push({
          type: sink.type,
          cwe: sink.cwe,
          severity: sink.confidence > 0.9 ? 'critical' : 'high',
          source: {
            line: source.line,
            type: source.type,
          },
          sink: {
            line: sink.line,
            type: sink.type,
          },
          confidence,
        });
      }
    }
  }

  // Deduplicate vulnerabilities
  const vulnMap = new Map<string, typeof vulnerabilities[0]>();
  for (const vuln of vulnerabilities) {
    const key = `${vuln.source.line}:${vuln.sink.line}:${vuln.type}`;
    const existing = vulnMap.get(key);
    if (!existing || vuln.confidence > existing.confidence) {
      vulnMap.set(key, vuln);
    }
  }
  const dedupedVulns = Array.from(vulnMap.values());
  dedupedVulns.sort((a, b) => b.confidence - a.confidence);

  return dedupedVulns;
}

function calculateVulnConfidence(
  source: CircleIR['taint']['sources'][0],
  sink: CircleIR['taint']['sinks'][0]
): number {
  let confidence = 0.5;
  const lineDiff = Math.abs(source.line - sink.line);
  if (lineDiff < 10) {
    confidence += 0.3;
  } else if (lineDiff < 50) {
    confidence += 0.15;
  }
  if (source.severity === 'high') {
    confidence += 0.1;
  }
  confidence = confidence * sink.confidence;
  return Math.min(confidence, 1.0);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/**
 * Check if the analyzer is initialized.
 */
export function isAnalyzerInitialized(): boolean {
  return initialized;
}

/**
 * Reset the analyzer (mainly for testing).
 */
export function resetAnalyzer(): void {
  initialized = false;
}

// ---------------------------------------------------------------------------
// Project-level analysis (multi-file)
// ---------------------------------------------------------------------------

/**
 * Analyze a set of files as a project, finding cross-file taint flows.
 *
 * Runs single-file `analyze()` on each file in order, then uses
 * `ProjectGraph` + `CrossFileResolver` to surface flows that cross file
 * boundaries.  The per-file `CircleIR` outputs are preserved unchanged in
 * `ProjectAnalysis.files`.
 *
 * `findings` is always empty — it requires LLM enrichment which is out of
 * scope for this library (see CLAUDE.md and SPEC.md section 11).
 */
export async function analyzeProject(
  files: Array<{ code: string; filePath: string; language: SupportedLanguage }>,
  options: AnalyzerOptions = {},
): Promise<ProjectAnalysis> {
  const fileAnalyses: Array<{ file: string; analysis: CircleIR }> = [];
  const projectGraph = new ProjectGraph();
  const sourceLinesByFile = new Map<string, string[]>();

  // 1. Per-file analysis
  for (const { code, filePath, language } of files) {
    const ir = await analyze(code, filePath, language, options);
    fileAnalyses.push({ file: filePath, analysis: ir });
    projectGraph.addFile(filePath, new CodeGraph(ir));
    sourceLinesByFile.set(filePath, code.split('\n'));
  }

  // 2. Cross-file analysis
  const crossFileResult = new CrossFilePass().run(projectGraph, sourceLinesByFile);

  // 3. Assemble ProjectMeta
  const filePaths = files.map(f => f.filePath);
  const totalLoc  = fileAnalyses.reduce((sum, f) => sum + (f.analysis.meta.loc ?? 0), 0);
  const meta: ProjectMeta = {
    name:         deriveProjectName(filePaths),
    root:         deriveProjectRoot(filePaths),
    language:     files[0]?.language ?? 'java',
    total_files:  files.length,
    total_loc:    totalLoc,
    analyzed_at:  new Date().toISOString(),
  };

  return {
    meta,
    files: fileAnalyses,
    type_hierarchy:  crossFileResult.typeHierarchy,
    cross_file_calls: crossFileResult.crossFileCalls,
    taint_paths:     crossFileResult.taintPaths,
    findings: [],
  };
}

/** Derive a project name from the common root directory of the file paths. */
function deriveProjectName(paths: string[]): string {
  if (paths.length === 0) return 'unknown';
  const root = deriveProjectRoot(paths);
  return root.split('/').filter(Boolean).pop() ?? 'unknown';
}

/** Derive the common ancestor directory from a list of file paths. */
function deriveProjectRoot(paths: string[]): string {
  if (paths.length === 0) return '/';
  const segments = paths[0].split('/');
  let common = segments.slice(0, -1); // strip filename
  for (const p of paths.slice(1)) {
    const segs = p.split('/');
    common = common.filter((seg, i) => segs[i] === seg);
  }
  return common.join('/') || '/';
}

// Re-export isFalsePositive for consumers that use it directly
export { isFalsePositive };
