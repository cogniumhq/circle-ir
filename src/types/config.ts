/**
 * Types for YAML configuration files (configs/sources/, configs/sinks/)
 */

import type { Severity, SinkType, SourceType } from './index.js';

// =============================================================================
// Source Configuration (configs/sources/*.yaml)
// =============================================================================

export interface SourceConfig {
  sources: SourcePattern[];
}

export interface SourcePattern {
  // Method-based source (Java style: request.getParameter())
  method?: string;
  class?: string;

  // Property-based source (JS style: req.params, req.query)
  property?: string;         // Property name (e.g., 'params', 'query', 'body')
  object?: string;           // Object name (e.g., 'req', 'request')

  // Annotation-based source
  annotation?: string;

  type: SourceType;
  severity: Severity;

  // Which part is tainted
  return_tainted?: boolean;  // Return value is tainted
  param_tainted?: boolean;   // Annotated parameter is tainted
  property_tainted?: boolean; // Property access is tainted (for JS)

  note?: string;
}

// =============================================================================
// Sink Configuration (configs/sinks/*.yaml)
// =============================================================================

export interface SinkConfig {
  sinks: SinkPattern[];
  sanitizers?: SanitizerPattern[];
}

export interface SinkPattern {
  method: string;
  class?: string;
  type: SinkType;
  cwe: string;
  severity: Severity;
  arg_positions: number[];  // Which arguments are dangerous (0-indexed)
  note?: string;
}

export interface SanitizerPattern {
  method?: string;
  class?: string;
  annotation?: string;
  removes: SinkType[];  // Which sink types this sanitizes
  note?: string;
}

// =============================================================================
// Combined Config (loaded at runtime)
// =============================================================================

export interface TaintConfig {
  sources: SourcePattern[];
  sinks: SinkPattern[];
  sanitizers: SanitizerPattern[];
}
