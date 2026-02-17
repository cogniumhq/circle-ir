/**
 * Browser entry point for Circle-IR
 *
 * This module provides a browser-compatible API for code analysis.
 */

import {
  initAnalyzer,
  analyze,
  analyzeForAPI,
  isAnalyzerInitialized,
  type AnalyzerOptions,
} from './analyzer.js';
import type { CircleIR, AnalysisResponse } from './types/index.js';
import type { SupportedLanguage } from './core/index.js';

export interface BrowserAnalyzerOptions extends AnalyzerOptions {
  /**
   * URL to the tree-sitter.wasm file.
   * Required for browser usage.
   */
  wasmUrl: string;

  /**
   * URLs to language grammar WASM files.
   */
  languageUrls?: Partial<Record<SupportedLanguage, string>>;
}

/**
 * Initialize the analyzer for browser usage.
 */
export async function init(options: BrowserAnalyzerOptions): Promise<void> {
  await initAnalyzer({
    wasmPath: options.wasmUrl,
    taintConfig: options.taintConfig,
  });
}

/**
 * Analyze source code and return full Circle-IR output.
 */
export async function analyzeCode(
  code: string,
  options: {
    filePath?: string;
    language?: SupportedLanguage;
  } = {}
): Promise<CircleIR> {
  const filePath = options.filePath ?? 'input.java';
  const language = options.language ?? 'java';

  if (!isAnalyzerInitialized()) {
    throw new Error('Analyzer not initialized. Call init() first.');
  }

  return analyze(code, filePath, language);
}

/**
 * Analyze source code and return simplified API response.
 */
export async function analyzeCodeForAPI(
  code: string,
  options: {
    filePath?: string;
    language?: SupportedLanguage;
  } = {}
): Promise<AnalysisResponse> {
  const filePath = options.filePath ?? 'input.java';
  const language = options.language ?? 'java';

  if (!isAnalyzerInitialized()) {
    throw new Error('Analyzer not initialized. Call init() first.');
  }

  return analyzeForAPI(code, filePath, language);
}

// Re-export types for convenience
export type {
  CircleIR,
  AnalysisResponse,
  Vulnerability,
  TaintSource,
  TaintSink,
  SupportedLanguage,
} from './index.js';
