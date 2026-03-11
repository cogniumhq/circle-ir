/**
 * Circle-IR Analyzer
 *
 * Main entry point for analyzing source code and producing Circle-IR output.
 * This is the core analyzer - for LLM-enhanced analysis, use circle-ir-ai.
 */

import type { CircleIR, AnalysisResponse, Vulnerability, Enriched, TaintSource, TypeInfo, SourceType, SinkType } from './types/index.js';
import type { TaintConfig } from './types/config.js';
import type { FieldTaintInfo } from './analysis/constant-propagation/types.js';
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
import { analyzeTaint, getDefaultConfig, detectUnresolved, propagateTaint, analyzeInterprocedural, findTaintBridges, analyzeConstantPropagation, isFalsePositive, isCorrelatedPredicateFP } from './analysis/index.js';
import { registerBuiltinPlugins, getLanguagePlugin } from './languages/index.js';
import { logger } from './utils/logger.js';

/**
 * Find getter methods that return tainted fields from constructor assignments.
 * This enables detection of taint through: constructor param → field → getter return.
 */
function findGetterSources(
  types: TypeInfo[],
  instanceFieldTaint: Map<string, FieldTaintInfo>,
  sourceCode: string
): TaintSource[] {
  const sources: TaintSource[] = [];

  if (instanceFieldTaint.size === 0) {
    return sources;
  }

  // Iterate through all classes and methods
  for (const type of types) {
    for (const method of type.methods) {
      // Look for getter pattern: getXxx() returning a field
      const methodName = method.name;

      // Check for getter naming convention: getXxx, isXxx, or just xxx
      let potentialFieldName: string | null = null;
      if (methodName.startsWith('get') && methodName.length > 3) {
        // getField -> field (lowercase first letter)
        potentialFieldName = methodName.charAt(3).toLowerCase() + methodName.substring(4);
      } else if (methodName.startsWith('is') && methodName.length > 2) {
        // isField -> field
        potentialFieldName = methodName.charAt(2).toLowerCase() + methodName.substring(3);
      }

      // Check if the method body returns a tainted field
      // Simple check: method has no parameters and returns a field that's tracked as tainted
      if (method.parameters.length === 0) {
        // Check both the potential field name from naming convention and exact match
        const fieldsToCheck = potentialFieldName
          ? [potentialFieldName, methodName]
          : [methodName];

        for (const fieldName of fieldsToCheck) {
          const fieldTaint = instanceFieldTaint.get(fieldName);
          if (fieldTaint && fieldTaint.className === type.name) {
            sources.push({
              type: 'constructor_field',
              location: `${type.name}.${methodName}() returns tainted field '${fieldName}' (from constructor param '${fieldTaint.sourceParam}')`,
              severity: 'high',
              line: method.start_line,
              confidence: 0.95,
            });
            break; // Found a match, no need to check more fields
          }
        }
      }

      // Also check for direct field name match (e.g., method name() returns this.name)
      for (const [fieldName, fieldTaint] of instanceFieldTaint) {
        if (fieldTaint.className === type.name) {
          // Check if method name matches field name directly (common pattern)
          if (methodName === fieldName && method.parameters.length === 0) {
            // Avoid duplicates
            const alreadyAdded = sources.some(
              s => s.location.includes(`${type.name}.${methodName}()`)
            );
            if (!alreadyAdded) {
              sources.push({
                type: 'constructor_field',
                location: `${type.name}.${methodName}() returns tainted field '${fieldName}' (from constructor param '${fieldTaint.sourceParam}')`,
                severity: 'high',
                line: method.start_line,
                confidence: 0.95,
              });
            }
          }
        }
      }
    }
  }

  return sources;
}

/**
 * DOM XSS sink property patterns.
 * Used to detect sinks in property assignments like: element.innerHTML = value
 */
const JS_DOM_XSS_SINKS = [
  { pattern: /\.innerHTML\s*=/, type: 'xss' as const, cwe: 'CWE-79', severity: 'critical' as const },
  { pattern: /\.outerHTML\s*=/, type: 'xss' as const, cwe: 'CWE-79', severity: 'critical' as const },
  { pattern: /document\.write\s*\(/, type: 'xss' as const, cwe: 'CWE-79', severity: 'critical' as const },
  { pattern: /document\.writeln\s*\(/, type: 'xss' as const, cwe: 'CWE-79', severity: 'critical' as const },
  { pattern: /\.insertAdjacentHTML\s*\(/, type: 'xss' as const, cwe: 'CWE-79', severity: 'critical' as const },
  { pattern: /\.src\s*=/, type: 'xss' as const, cwe: 'CWE-79', severity: 'high' as const },
  { pattern: /\.href\s*=/, type: 'xss' as const, cwe: 'CWE-79', severity: 'high' as const },
];

/**
 * Tainted JavaScript property access patterns.
 * Used to detect sources in variable assignments like: var x = req.query.id
 */
const JS_TAINTED_PATTERNS = [
  { pattern: /\breq\.query\b/, type: 'http_param' as const },
  { pattern: /\breq\.params\b/, type: 'http_param' as const },
  { pattern: /\breq\.body\b/, type: 'http_body' as const },
  { pattern: /\breq\.headers\b/, type: 'http_header' as const },
  { pattern: /\breq\.cookies\b/, type: 'http_cookie' as const },
  { pattern: /\breq\.url\b/, type: 'http_path' as const },
  { pattern: /\breq\.path\b/, type: 'http_path' as const },
  { pattern: /\breq\.originalUrl\b/, type: 'http_path' as const },
  { pattern: /\breq\.files?\b/, type: 'file_input' as const },
  { pattern: /\brequest\.query\b/, type: 'http_param' as const },
  { pattern: /\brequest\.params\b/, type: 'http_param' as const },
  { pattern: /\brequest\.body\b/, type: 'http_body' as const },
  { pattern: /\brequest\.headers\b/, type: 'http_header' as const },
  { pattern: /\bctx\.query\b/, type: 'http_param' as const },
  { pattern: /\bctx\.params\b/, type: 'http_param' as const },
  { pattern: /\bctx\.request\b/, type: 'http_body' as const },
  { pattern: /\bprocess\.env\b/, type: 'env_input' as const },
  { pattern: /\bprocess\.argv\b/, type: 'io_input' as const },
  { pattern: /\blocation\.search\b/, type: 'http_param' as const },
  { pattern: /\blocation\.hash\b/, type: 'http_param' as const },
  { pattern: /\blocation\.href\b/, type: 'http_path' as const },
  { pattern: /\bdocument\.getElementById\b/, type: 'dom_input' as const },
  { pattern: /\bdocument\.querySelector\b/, type: 'dom_input' as const },
  { pattern: /\.value\b/, type: 'dom_input' as const },
];

/**
 * Find JavaScript taint sources from variable assignments.
 * Detects patterns like: var userId = req.query.id
 */
function findJavaScriptAssignmentSources(
  sourceCode: string,
  language: string
): TaintSource[] {
  const sources: TaintSource[] = [];

  // Only apply to JavaScript/TypeScript
  if (!['javascript', 'typescript'].includes(language)) {
    return sources;
  }

  const lines = sourceCode.split('\n');

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];
    const lineNumber = lineNum + 1;

    // Look for variable assignments: var/let/const x = ...
    // or simple assignments: x = ...
    const assignmentMatch = line.match(/(?:(?:var|let|const)\s+)?(\w+)\s*=\s*(.+)/);
    if (assignmentMatch) {
      const varName = assignmentMatch[1];
      const rhs = assignmentMatch[2];

      // Check if RHS contains a tainted pattern
      for (const { pattern, type } of JS_TAINTED_PATTERNS) {
        if (pattern.test(rhs)) {
          // Don't add duplicates
          const alreadyExists = sources.some(
            s => s.line === lineNumber && s.type === type
          );
          if (!alreadyExists) {
            sources.push({
              type,
              location: `${varName} = ${rhs.trim().substring(0, 50)}${rhs.length > 50 ? '...' : ''}`,
              severity: 'high',
              line: lineNumber,
              confidence: 1.0,
              variable: varName,
            });
          }
          break; // Found a match, no need to check more patterns
        }
      }
    }
  }

  return sources;
}

/**
 * Find DOM XSS sinks from property assignments in JavaScript.
 * Detects patterns like: element.innerHTML = userInput
 */
function findJavaScriptDOMSinks(
  sourceCode: string,
  language: string
): Array<{
  type: string;
  cwe: string;
  severity: string;
  line: number;
  location: string;
  method?: string;
}> {
  const sinks: Array<{
    type: string;
    cwe: string;
    severity: string;
    line: number;
    location: string;
    method?: string;
  }> = [];

  // Only apply to JavaScript/TypeScript
  if (!['javascript', 'typescript'].includes(language)) {
    return sinks;
  }

  const lines = sourceCode.split('\n');

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];
    const lineNumber = lineNum + 1;

    // Check for DOM XSS sink patterns
    for (const { pattern, type, cwe, severity } of JS_DOM_XSS_SINKS) {
      if (pattern.test(line)) {
        // Extract the method/property being assigned
        let method = 'innerHTML';
        if (line.includes('.outerHTML')) method = 'outerHTML';
        else if (line.includes('document.write(')) method = 'document.write';
        else if (line.includes('document.writeln(')) method = 'document.writeln';
        else if (line.includes('.insertAdjacentHTML')) method = 'insertAdjacentHTML';
        else if (line.includes('.src')) method = 'src';
        else if (line.includes('.href')) method = 'href';

        // Don't add duplicates
        const alreadyExists = sinks.some(
          s => s.line === lineNumber && s.cwe === cwe
        );
        if (!alreadyExists) {
          sinks.push({
            type,
            cwe,
            severity,
            line: lineNumber,
            location: line.trim().substring(0, 80),
            method,
          });
        }
        break;
      }
    }
  }

  return sinks;
}

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
  // Different languages have different AST node types
  const isJavaScript = language === 'javascript' || language === 'typescript';
  const isRust = language === 'rust';
  const isPython = language === 'python';
  let nodeTypesToCollect: Set<string>;
  if (isRust) {
    nodeTypesToCollect = new Set([
      // Rust AST nodes
      'call_expression',
      'macro_invocation',
      'function_item',
      'struct_item',
      'impl_item',
      'enum_item',
      'trait_item',
      'mod_item',
      'use_declaration',
      'let_declaration',
      'field_expression',
      'scoped_identifier',
    ]);
  } else if (isPython) {
    nodeTypesToCollect = new Set([
      // Python AST nodes
      'call',
      'function_definition',
      'class_definition',
      'import_statement',
      'import_from_statement',
      'assignment',
      'attribute',
      'subscript',
    ]);
  } else if (isJavaScript) {
    nodeTypesToCollect = new Set([
      // JavaScript/TypeScript AST nodes
      'call_expression',
      'new_expression',
      'class_declaration',
      'function_declaration',
      'arrow_function',
      'method_definition',
      'variable_declaration',
      'lexical_declaration',
      'import_statement',
      'export_statement',
      'member_expression',
      'assignment_expression',
    ]);
  } else if (language === 'bash') {
    nodeTypesToCollect = new Set([
      // Bash AST nodes
      'command',
      'function_definition',
      'variable_assignment',
      'declaration_command',
      'if_statement',
      'for_statement',
      'c_style_for_statement',
      'while_statement',
    ]);
  } else {
    nodeTypesToCollect = new Set([
      // Java AST nodes
      'method_invocation',
      'object_creation_expression',
      'class_declaration',
      'method_declaration',
      'constructor_declaration',
      'field_declaration',
      'import_declaration',
      'interface_declaration',
      'enum_declaration',
    ]);
  }
  const nodeCache = collectAllNodes(tree.rootNode, nodeTypesToCollect);

  // Extract all components using the cached nodes
  const meta = extractMeta(code, tree, filePath, language);
  const types = extractTypes(tree, nodeCache, language);
  const calls = extractCalls(tree, nodeCache, language);
  const imports = extractImports(tree, language);
  const exports = extractExports(types);
  const cfg = buildCFG(tree, language);
  const dfg = buildDFG(tree, nodeCache, language);

  // Extract @sanitizer annotated method names (from Javadoc comments)
  const sanitizerMethods: string[] = [];
  for (const type of types) {
    for (const method of type.methods) {
      if (method.annotations.includes('sanitizer')) {
        sanitizerMethods.push(method.name);
      }
    }
  }

  // First, do a preliminary taint analysis to find inter-procedural parameter sources
  // These need to be passed to constant propagation so it can track taint from method parameters
  let baseConfig = options.taintConfig ?? getDefaultConfig();

  // Merge language plugin built-in sources/sinks into the config.
  // This handles languages (e.g. Bash) whose patterns are defined on the plugin
  // rather than in YAML config files loaded by getDefaultConfig().
  if (!options.taintConfig) {
    const plugin = getLanguagePlugin(language);
    if (plugin) {
      const pluginSources = plugin.getBuiltinSources();
      const pluginSinks = plugin.getBuiltinSinks();
      if (pluginSources.length > 0 || pluginSinks.length > 0) {
        baseConfig = {
          ...baseConfig,
          sources: [
            ...baseConfig.sources,
            ...pluginSources.map(s => ({
              method: s.method,
              class: s.class,
              annotation: s.annotation,
              type: s.type as SourceType,
              severity: s.severity,
              return_tainted: s.returnTainted ?? false,
            })),
          ],
          sinks: [
            ...baseConfig.sinks,
            ...pluginSinks.map(s => ({
              method: s.method,
              class: s.class,
              type: s.type as SinkType,
              cwe: s.cwe,
              severity: s.severity,
              arg_positions: s.argPositions,
            })),
          ],
        };
      }
    }
  }

  const preliminaryTaint = analyzeTaint(calls, types, baseConfig);

  // Extract inter-procedural parameter sources
  const taintedParameters: Array<{ methodName: string; paramName: string }> = [];
  for (const source of preliminaryTaint.sources) {
    if (source.type === 'interprocedural_param') {
      // Location format: "ParamType paramName in methodName"
      const match = source.location.match(/(\S+)\s+(\S+)\s+in\s+(\S+)/);
      if (match) {
        taintedParameters.push({
          methodName: match[3],
          paramName: match[2],
        });
      }
    }
  }

  // Run constant propagation with tainted parameters
  const constPropResult = analyzeConstantPropagation(tree, code, {
    sanitizerMethods,
    taintedParameters,
  });

  // Analyze taint with config
  const taint = analyzeTaint(calls, types, baseConfig);

  // Add sources for getters that return tainted constructor fields
  const getterSources = findGetterSources(types, constPropResult.instanceFieldTaint, code);
  taint.sources.push(...getterSources);

  // Add sources for JavaScript variable assignments with tainted patterns
  const jsAssignmentSources = findJavaScriptAssignmentSources(code, language);
  taint.sources.push(...jsAssignmentSources);

  // Add sinks for JavaScript DOM XSS patterns (innerHTML, document.write, etc.)
  const jsDOMSinks = findJavaScriptDOMSinks(code, language);
  for (const domSink of jsDOMSinks) {
    // Avoid duplicates
    const alreadyExists = taint.sinks.some(
      s => s.line === domSink.line && s.cwe === domSink.cwe
    );
    if (!alreadyExists) {
      taint.sinks.push({
        type: 'xss',
        cwe: domSink.cwe,
        line: domSink.line,
        location: domSink.location,
        method: domSink.method,
        confidence: 1.0,
      });
    }
  }

  logger.debug('Initial taint analysis', {
    sources: taint.sources.length,
    sinks: taint.sinks.length,
    sanitizers: taint.sanitizers?.length ?? 0,
    getterSources: getterSources.length,
    jsDOMSinks: jsDOMSinks.length,
  });

  // Filter sinks that are in dead code (unreachable)
  taint.sinks = taint.sinks.filter(sink => !constPropResult.unreachableLines.has(sink.line));

  // Filter sinks that use clean array elements (strong updates)
  taint.sinks = filterCleanArraySinks(
    taint.sinks,
    calls,
    constPropResult.taintedArrayElements,
    constPropResult.symbols
  );

  // Filter sinks that use variables proven clean by constant propagation (strong updates)
  taint.sinks = filterCleanVariableSinks(
    taint.sinks,
    calls,
    constPropResult.tainted,
    constPropResult.symbols,
    dfg,
    constPropResult.sanitizedVars,
    constPropResult.synchronizedLines
  );

  // Filter sinks that are wrapped by sanitizers on the same line
  taint.sinks = filterSanitizedSinks(taint.sinks, taint.sanitizers ?? [], calls);

  // Propagate taint through dataflow to find verified flows
  if (taint.sources.length > 0 && taint.sinks.length > 0) {
    const propagationResult = propagateTaint(
      dfg,
      calls,
      taint.sources,
      taint.sinks,
      taint.sanitizers ?? []
    );

    // Filter flows using constant propagation (eliminate false positives)
    const verifiedFlows = propagationResult.flows.filter(flow => {
      // Check if the sink line is in dead code
      if (constPropResult.unreachableLines.has(flow.sink.line)) {
        return false;
      }

      // Check each step in the path - if any variable has a constant value, skip
      for (const step of flow.path) {
        const fpCheck = isFalsePositive(constPropResult, step.line, step.variable);
        if (fpCheck.isFalsePositive) {
          return false;
        }
      }

      // Check for correlated predicates: if the sink is under condition !C
      // and the taint was added under condition C, they're mutually exclusive
      if (isCorrelatedPredicateFP(constPropResult, flow)) {
        return false;
      }

      return true;
    });

    // Convert flows to TaintFlowInfo format
    taint.flows = verifiedFlows.map(flow => ({
      source_line: flow.source.line,
      sink_line: flow.sink.line,
      source_type: flow.source.type,
      sink_type: flow.sink.type,
      path: flow.path.map(step => ({
        variable: step.variable,
        line: step.line,
        type: step.type,
      })),
      confidence: flow.confidence,
      sanitized: flow.sanitized,
    }));

    // Add array element flows that DFG-based analysis might miss
    const arrayFlows = detectArrayElementFlows(
      calls,
      taint.sources,
      taint.sinks,
      constPropResult.taintedArrayElements,
      constPropResult.unreachableLines
    );
    if (arrayFlows && arrayFlows.length > 0) {
      if (!taint.flows) {
        taint.flows = [];
      }
      for (const flow of arrayFlows) {
        // Avoid duplicates
        if (!taint.flows.some(f => f.source_line === flow.source_line && f.sink_line === flow.sink_line)) {
          taint.flows.push(flow);
        }
      }
    }

    // Add collection/iterator flows that DFG-based analysis might miss
    const collectionFlows = detectCollectionFlows(
      calls,
      taint.sources,
      taint.sinks,
      constPropResult.tainted,
      constPropResult.unreachableLines
    );
    if (collectionFlows && collectionFlows.length > 0) {
      if (!taint.flows) {
        taint.flows = [];
      }
      for (const flow of collectionFlows) {
        // Avoid duplicates
        if (taint.flows.some(f => f.source_line === flow.source_line && f.sink_line === flow.sink_line)) {
          continue;
        }

        // Apply the same filtering as DFG-based flows
        const flowForCheck = {
          source: { line: flow.source_line, type: flow.source_type },
          sink: { line: flow.sink_line, type: flow.sink_type },
          path: flow.path.map(p => ({ variable: p.variable, line: p.line })),
        };
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (isCorrelatedPredicateFP(constPropResult, flowForCheck as any)) {
          continue;
        }

        // Check if any step in the path is a false positive
        let isFP = false;
        for (const step of flow.path) {
          const fpCheck = isFalsePositive(constPropResult, step.line, step.variable);
          if (fpCheck.isFalsePositive) {
            isFP = true;
            break;
          }
        }
        if (isFP) {
          continue;
        }

        taint.flows.push(flow);
      }
    }

    // Add direct parameter-to-sink flows that DFG might miss
    const paramFlows = detectParameterSinkFlows(
      types,
      calls,
      taint.sources,
      taint.sinks,
      constPropResult.unreachableLines
    );
    if (paramFlows && paramFlows.length > 0) {
      if (!taint.flows) {
        taint.flows = [];
      }
      for (const flow of paramFlows) {
        // Avoid duplicates
        if (!taint.flows.some(f => f.source_line === flow.source_line && f.sink_line === flow.sink_line)) {
          taint.flows.push(flow);
        }
      }
    }

    // Perform inter-procedural analysis
    const interProc = analyzeInterprocedural(
      types,
      calls,
      dfg,
      taint.sources,
      taint.sinks,
      taint.sanitizers ?? [],
      {
        taintedVariables: constPropResult.tainted,
      }
    );

    // Add inter-procedural sinks to the taint sinks and generate flows
    for (const sink of interProc.propagatedSinks) {
      if (!taint.sinks.some(s => s.line === sink.line)) {
        taint.sinks.push(sink);
      }
    }

    // Generate flows for inter-procedural propagated sinks
    // These sinks are inside called methods where tainted args were passed
    if (interProc.propagatedSinks.length > 0 && taint.sources.length > 0) {
      if (!taint.flows) {
        taint.flows = [];
      }

      // Build set of sanitizer method names to skip (methods with @sanitizer annotation)
      const sanitizerMethodNames = new Set<string>();
      for (const san of taint.sanitizers ?? []) {
        if (san.type === 'javadoc_sanitizer') {
          // Extract method name from "methodName()" format
          const match = san.method.match(/^(\w+)\(\)$/);
          if (match) sanitizerMethodNames.add(match[1]);
          else sanitizerMethodNames.add(san.method);
        }
      }

      for (const sink of interProc.propagatedSinks) {
        // Skip external taint escape sinks (not real vulnerability sinks)
        if (sink.type === 'external_taint_escape') continue;

        // Find which call edge brought taint to this sink's method
        for (const edge of interProc.callEdges) {
          if (!interProc.taintedMethods.has(edge.calleeMethod)) continue;
          const method = interProc.methodNodes.get(edge.calleeMethod);
          if (!method) continue;
          if (sink.line < method.startLine || sink.line > method.endLine) continue;

          // Skip sinks inside sanitizer methods (@sanitizer annotation)
          if (sanitizerMethodNames.has(method.name)) continue;

          // Find the source connected to this call
          for (const source of taint.sources) {
            // Source should be in the caller's scope, at or before the call line
            if (source.line > edge.callLine) continue;

            // Skip low-confidence interprocedural_param sources
            if (source.type === 'interprocedural_param' && source.confidence < 0.6) continue;

            if (taint.flows.some(f => f.source_line === source.line && f.sink_line === sink.line)) continue;

            taint.flows.push({
              source_line: source.line,
              sink_line: sink.line,
              source_type: source.type,
              sink_type: sink.type,
              path: [
                { variable: source.location, line: source.line, type: 'source' },
                { variable: `call to ${method.name}()`, line: edge.callLine, type: 'use' },
                { variable: sink.location, line: sink.line, type: 'sink' },
              ],
              confidence: sink.confidence * source.confidence * 0.85,
              sanitized: false,
            });
            break; // One source per sink is enough
          }
          break; // One call edge per sink is enough
        }
      }
    }

    // Build inter-procedural info
    const taintBridges = findTaintBridges(interProc);
    taint.interprocedural = {
      tainted_methods: Array.from(interProc.taintedMethods),
      taint_bridges: taintBridges,
      method_flows: interProc.callEdges
        .filter(edge => interProc.taintedMethods.has(edge.calleeMethod))
        .map(edge => ({
          caller: edge.callerMethod,
          callee: edge.calleeMethod,
          call_line: edge.callLine,
          tainted_args: edge.taintedArgs,
          returns_taint: interProc.taintedReturns.has(edge.calleeMethod),
        })),
    };
  }

  // Perform inter-procedural analysis even when no initial sinks (can detect external taint escapes)
  if (taint.sources.length > 0 && taint.sinks.length === 0) {
    const interProc = analyzeInterprocedural(
      types,
      calls,
      dfg,
      taint.sources,
      [],  // No initial sinks
      taint.sanitizers ?? [],
      {
        taintedVariables: constPropResult.tainted,
      }
    );

    // Add inter-procedural sinks (e.g., external_taint_escape)
    for (const sink of interProc.propagatedSinks) {
      if (!constPropResult.unreachableLines.has(sink.line) &&
          !taint.sinks.some(s => s.line === sink.line)) {
        taint.sinks.push(sink);
      }
    }

    // Build inter-procedural info
    if (interProc.taintedMethods.size > 0 || interProc.propagatedSinks.length > 0) {
      const taintBridges = findTaintBridges(interProc);
      taint.interprocedural = {
        tainted_methods: Array.from(interProc.taintedMethods),
        taint_bridges: taintBridges,
        method_flows: interProc.callEdges
          .filter(edge => interProc.taintedMethods.has(edge.calleeMethod))
          .map(edge => ({
            caller: edge.callerMethod,
            callee: edge.calleeMethod,
            call_line: edge.callLine,
            tainted_args: edge.taintedArgs,
            returns_taint: interProc.taintedReturns.has(edge.calleeMethod),
          })),
      };
    }

    // If we found new sinks, create flows from sources
    if (taint.sinks.length > 0) {
      taint.flows = taint.sinks.map(sink => ({
        source_line: taint.sources[0].line,
        sink_line: sink.line,
        source_type: taint.sources[0].type,
        sink_type: sink.type,
        path: [
          { variable: 'input', line: taint.sources[0].line, type: 'source' as const },
          { variable: 'input', line: sink.line, type: 'sink' as const },
        ],
        confidence: taint.sources[0].confidence * sink.confidence,
        sanitized: false,
      }));
    }
  }

  // Detect unresolved items
  const unresolved = detectUnresolved(calls, types, dfg);

  // Build enriched section
  const enriched = buildEnriched(types, calls, taint.sources, taint.sinks);

  logger.debug('Analysis complete', {
    filePath,
    finalSources: taint.sources.length,
    finalSinks: taint.sinks.length,
    flows: taint.flows?.length ?? 0,
    unresolvedItems: unresolved.length,
  });

  return {
    meta,
    types,
    calls,
    cfg,
    dfg,
    taint,
    imports,
    exports,
    unresolved,
    enriched,
  };
}

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

  // Collect all node types in a single traversal for better performance
  const isJavaScript = language === 'javascript' || language === 'typescript';
  const isRust = language === 'rust';
  const isPython = language === 'python';
  let nodeTypesToCollect: Set<string>;
  if (isRust) {
    nodeTypesToCollect = new Set([
      'call_expression', 'macro_invocation', 'function_item', 'struct_item',
      'impl_item', 'enum_item', 'trait_item', 'mod_item', 'use_declaration',
      'let_declaration', 'field_expression', 'scoped_identifier',
    ]);
  } else if (isPython) {
    nodeTypesToCollect = new Set([
      'call', 'function_definition', 'class_definition', 'import_statement',
      'import_from_statement', 'assignment', 'attribute', 'subscript',
    ]);
  } else if (isJavaScript) {
    nodeTypesToCollect = new Set([
      'call_expression', 'new_expression', 'class_declaration', 'function_declaration',
      'arrow_function', 'method_definition', 'variable_declaration', 'lexical_declaration',
      'import_statement', 'export_statement',
    ]);
  } else {
    nodeTypesToCollect = new Set([
      'method_invocation', 'object_creation_expression', 'class_declaration',
      'method_declaration', 'field_declaration', 'import_declaration',
      'interface_declaration', 'enum_declaration',
    ]);
  }
  const nodeCache = collectAllNodes(tree.rootNode, nodeTypesToCollect);

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

  // Generate vulnerabilities from source-sink pairs
  const vulnerabilities = findVulnerabilities(taint.sources, filteredSinks, calls, constPropResult);

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

function evaluateSimpleExpression(
  expr: string,
  symbols: Map<string, { value: string | number | boolean | null; type: string; sourceLine: number }>
): string {
  let evaluated = expr;
  for (const [name, val] of symbols) {
    if (val.type === 'int' || val.type === 'float') {
      const regex = new RegExp(`\\b${name}\\b`, 'g');
      evaluated = evaluated.replace(regex, String(val.value));
    }
  }

  try {
    if (/^[\d\s+\-*/().]+$/.test(evaluated)) {
      const result = Function('"use strict"; return (' + evaluated + ')')();
      if (typeof result === 'number' && !isNaN(result)) {
        return String(Math.floor(result));
      }
    }
  } catch {
    // Evaluation failed
  }

  return expr;
}

function filterCleanArraySinks(
  sinks: CircleIR['taint']['sinks'],
  calls: CircleIR['calls'],
  taintedArrayElements: Map<string, Set<string>>,
  symbols: Map<string, { value: string | number | boolean | null; type: string; sourceLine: number }>
): CircleIR['taint']['sinks'] {
  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  return sinks.filter(sink => {
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        const arrayAccessMatch = arg.expression?.match(/^(\w+)\[(\d+|[^[\]]+)\]$/);
        if (arrayAccessMatch) {
          const arrayName = arrayAccessMatch[1];
          let indexStr = arrayAccessMatch[2];
          indexStr = evaluateSimpleExpression(indexStr, symbols);

          const taintedIndices = taintedArrayElements.get(arrayName);
          if (taintedIndices !== undefined) {
            const isTainted = taintedIndices.has(indexStr) || taintedIndices.has('*');
            if (!isTainted) {
              return false;
            }
          }
        }
      }
    }

    return true;
  });
}

function filterCleanVariableSinks(
  sinks: CircleIR['taint']['sinks'],
  calls: CircleIR['calls'],
  taintedVars: Set<string>,
  symbols: Map<string, { value: string | number | boolean | null; type: string; sourceLine: number }>,
  dfg?: CircleIR['dfg'],
  sanitizedVars?: Set<string>,
  synchronizedLines?: Set<number>
): CircleIR['taint']['sinks'] {
  const fieldNames = new Set<string>();
  if (dfg) {
    for (const def of dfg.defs) {
      if (def.kind === 'field') {
        fieldNames.add(def.variable);
      }
    }
  }

  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  return sinks.filter(sink => {
    const callsAtSink = callsByLine.get(sink.line) ?? [];
    const isInSynchronizedBlock = synchronizedLines?.has(sink.line) ?? false;

    for (const call of callsAtSink) {
      let allArgsAreClean = true;
      const methodName = call.in_method;

      for (const arg of call.arguments) {
        if (arg.variable && !arg.expression?.includes('[')) {
          const varName = arg.variable;
          const scopedName = methodName ? `${methodName}:${varName}` : varName;

          if (fieldNames.has(varName) && !isInSynchronizedBlock) {
            allArgsAreClean = false;
            continue;
          }

          if (sanitizedVars?.has(scopedName) || sanitizedVars?.has(varName)) {
            continue;
          }

          if (taintedVars.has(scopedName) || taintedVars.has(varName)) {
            allArgsAreClean = false;
            continue;
          }

          const symbolValue = symbols.get(scopedName) ?? symbols.get(varName);
          if (symbolValue && symbolValue.type !== 'unknown') {
            continue;
          }

          allArgsAreClean = false;
        } else {
          // Check if the argument is a pure literal (string, number, boolean, etc.)
          // Literals are inherently clean — they can't carry tainted data.
          if (arg.literal != null) {
            continue;
          }
          // Also check if the expression is a quoted string literal without variable interpolation
          if (arg.expression && !arg.variable && isStringLiteralExpression(arg.expression)) {
            continue;
          }
          allArgsAreClean = false;
        }
      }

      if (allArgsAreClean && call.arguments.length > 0) {
        return false;
      }
    }

    return true;
  });
}

function isStringLiteralExpression(expr: string): boolean {
  const trimmed = expr.trim();
  return (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
         (trimmed.startsWith("'") && trimmed.endsWith("'"));
}

function filterSanitizedSinks(
  sinks: CircleIR['taint']['sinks'],
  sanitizers: CircleIR['taint']['sanitizers'],
  calls: CircleIR['calls']
): CircleIR['taint']['sinks'] {
  if (!sanitizers || sanitizers.length === 0) {
    return sinks;
  }

  const sanitizersByLine = new Map<number, typeof sanitizers>();
  for (const san of sanitizers) {
    const existing = sanitizersByLine.get(san.line) ?? [];
    existing.push(san);
    sanitizersByLine.set(san.line, existing);
  }

  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  return sinks.filter(sink => {
    const lineSanitizers = sanitizersByLine.get(sink.line);
    if (!lineSanitizers || lineSanitizers.length === 0) {
      return true;
    }

    for (const san of lineSanitizers) {
      if (san.sanitizes.includes(sink.type as typeof san.sanitizes[number])) {
        const lineCalls = callsByLine.get(sink.line) ?? [];

        for (const call of lineCalls) {
          for (const arg of call.arguments) {
            const expr = arg.expression || '';
            const sanMethodMatch = san.method.match(/(?:(\w+)\.)?(\w+)\(\)/);
            if (sanMethodMatch) {
              const sanMethodName = sanMethodMatch[2];
              const sanClassName = sanMethodMatch[1];
              if (sanClassName) {
                if (expr.includes(`${sanClassName}.${sanMethodName}(`)) {
                  return false;
                }
              } else if (expr.includes(`${sanMethodName}(`)) {
                return false;
              }
            }
          }
        }
      }
    }

    return true;
  });
}

function detectCollectionFlows(
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  taintedVars: Set<string>,
  unreachableLines: Set<number>
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];

  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) {
      continue;
    }

    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        if (arg.variable) {
          const varName = arg.variable;
          const scopedName = call.in_method ? `${call.in_method}:${varName}` : varName;

          if (taintedVars.has(varName) || taintedVars.has(scopedName)) {
            const source = sources[0];
            if (source) {
              flows.push({
                source_line: source.line,
                sink_line: sink.line,
                source_type: source.type,
                sink_type: sink.type,
                path: [
                  { variable: varName, line: source.line, type: 'source' as const },
                  { variable: varName, line: sink.line, type: 'sink' as const },
                ],
                confidence: 0.8,
                sanitized: false,
              });
            }
          }
        }

        if (arg.expression) {
          const expr = arg.expression;
          const collectionMethods = ['getLast', 'getFirst', 'get', 'next', 'poll', 'peek', 'toArray'];
          for (const method of collectionMethods) {
            const methodPattern = new RegExp(`(\\w+)\\.${method}\\(`);
            const match = expr.match(methodPattern);
            if (match) {
              const collectionVar = match[1];
              const scopedCollection = call.in_method ? `${call.in_method}:${collectionVar}` : collectionVar;
              if (taintedVars.has(collectionVar) || taintedVars.has(scopedCollection)) {
                const source = sources[0];
                if (source) {
                  flows.push({
                    source_line: source.line,
                    sink_line: sink.line,
                    source_type: source.type,
                    sink_type: sink.type,
                    path: [
                      { variable: collectionVar, line: source.line, type: 'source' as const },
                      { variable: collectionVar, line: sink.line, type: 'sink' as const },
                    ],
                    confidence: 0.75,
                    sanitized: false,
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  return flows;
}

function detectArrayElementFlows(
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  taintedArrayElements: Map<string, Set<string>>,
  unreachableLines: Set<number>
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];

  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) {
      continue;
    }

    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        const arrayAccessMatch = arg.expression?.match(/^(\w+)\[(\d+|[^[\]]+)\]$/);
        if (arrayAccessMatch) {
          const arrayName = arrayAccessMatch[1];
          const indexStr = arrayAccessMatch[2];

          const taintedIndices = taintedArrayElements.get(arrayName);
          if (taintedIndices) {
            const isTainted = taintedIndices.has(indexStr) || taintedIndices.has('*');

            if (isTainted) {
              const source = sources[0];
              if (source) {
                flows.push({
                  source_line: source.line,
                  sink_line: sink.line,
                  source_type: source.type,
                  sink_type: sink.type,
                  path: [
                    { variable: arrayName, line: source.line, type: 'source' as const },
                    { variable: `${arrayName}[${indexStr}]`, line: sink.line, type: 'sink' as const },
                  ],
                  confidence: 0.85,
                  sanitized: false,
                });
              }
            }
          }
        }
      }
    }
  }

  return flows;
}

/**
 * Detect direct method parameter to sink flows.
 * This handles cases where a tainted method parameter is directly used in a sink
 * without intermediate variable assignments (which DFG chains might miss).
 */
function detectParameterSinkFlows(
  types: CircleIR['types'],
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  unreachableLines: Set<number>
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];

  // Build a map of method name -> parameter sources
  const paramSourcesByMethod = new Map<string, Map<string, CircleIR['taint']['sources'][0]>>();
  for (const source of sources) {
    if (source.type === 'interprocedural_param') {
      // Extract method and param name from location like "String paramName in methodName"
      const match = source.location.match(/(\S+)\s+(\S+)\s+in\s+(\S+)/);
      if (match) {
        const paramName = match[2];
        const methodName = match[3];
        let methodParams = paramSourcesByMethod.get(methodName);
        if (!methodParams) {
          methodParams = new Map();
          paramSourcesByMethod.set(methodName, methodParams);
        }
        methodParams.set(paramName, source);
      }
    }
  }

  if (paramSourcesByMethod.size === 0) {
    return flows;
  }

  // Build map of calls by line
  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  // For each sink, check if it uses a tainted parameter directly
  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) {
      continue;
    }

    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      const methodName = call.in_method;
      if (!methodName) continue;

      const methodParamSources = paramSourcesByMethod.get(methodName);
      if (!methodParamSources) continue;

      // Check if any argument is a tainted parameter
      for (const arg of call.arguments) {
        if (arg.variable) {
          const paramSource = methodParamSources.get(arg.variable);
          if (paramSource) {
            // Found a direct parameter-to-sink flow
            // Check if we already have this flow
            const exists = flows.some(
              f => f.source_line === paramSource.line && f.sink_line === sink.line
            );
            if (!exists) {
              flows.push({
                source_line: paramSource.line,
                sink_line: sink.line,
                source_type: paramSource.type,
                sink_type: sink.type,
                path: [
                  { variable: arg.variable, line: paramSource.line, type: 'source' as const },
                  { variable: arg.variable, line: sink.line, type: 'sink' as const },
                ],
                confidence: 0.75, // Lower confidence for interprocedural
                sanitized: false,
              });
            }
          }
        }
      }
    }
  }

  return flows;
}

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
