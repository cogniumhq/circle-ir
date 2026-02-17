/**
 * RustSec Advisory Database Integration
 *
 * Provides vulnerability data from the RustSec advisory database.
 * Advisory data is bundled at build time for offline/deterministic usage.
 */

import type { Severity } from '../types/index.js';

export interface AdvisoryVulnerability {
  /** Unique advisory ID (RUSTSEC-YYYY-NNNN) */
  id: string;
  /** Crate name */
  package: string;
  /** Advisory date (RFC 3339) */
  date: string;
  /** Advisory URL */
  url: string;
  /** CVSS score string */
  cvss?: string;
  /** Vulnerability categories */
  categories: string[];
  /** Search keywords */
  keywords: string[];
  /** Related identifiers (CVE, etc.) */
  aliases: string[];
  /** Affected functions with version constraints */
  affectedFunctions?: {
    name: string;
    versions: string[];
  }[];
  /** Version constraints */
  versions: {
    patched?: string[];
    unaffected?: string[];
  };
  /** Affected architectures */
  affectedArch?: string[];
  /** Affected operating systems */
  affectedOs?: string[];
  /** Human-readable description */
  description: string;
  /** Title/summary of the vulnerability */
  title?: string;
}

export interface AdvisoryDatabase {
  /** Map of crate name to list of advisories */
  advisories: Map<string, AdvisoryVulnerability[]>;
  /** When the database was last updated */
  lastUpdated: string;
  /** Source of the database */
  source: 'bundled' | 'fetched';
  /** Database format version */
  version: string;
  /** Statistics */
  stats?: {
    totalAdvisories: number;
    uniqueCrates: number;
  };
}

/**
 * Bundled advisory database (loaded lazily)
 */
let bundledDb: AdvisoryDatabase | null = null;

/**
 * Load the bundled advisory database
 */
export function loadBundledAdvisories(): AdvisoryDatabase {
  if (bundledDb) {
    return bundledDb;
  }

  // Try to load bundled advisories
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const json = require('../../advisory-db.json');
    bundledDb = parseAdvisoryJson(json);
    return bundledDb;
  } catch {
    // Return empty database if bundled data not available
    return {
      advisories: new Map(),
      lastUpdated: new Date().toISOString(),
      source: 'bundled',
      version: '1.0',
      stats: { totalAdvisories: 0, uniqueCrates: 0 },
    };
  }
}

/**
 * Parse advisory JSON into database structure
 */
export function parseAdvisoryJson(json: {
  version: string;
  lastUpdated: string;
  advisories: AdvisoryVulnerability[];
}): AdvisoryDatabase {
  const advisories = new Map<string, AdvisoryVulnerability[]>();

  for (const advisory of json.advisories) {
    const existing = advisories.get(advisory.package) || [];
    existing.push(advisory);
    advisories.set(advisory.package, existing);
  }

  return {
    advisories,
    lastUpdated: json.lastUpdated,
    source: 'bundled',
    version: json.version,
    stats: {
      totalAdvisories: json.advisories.length,
      uniqueCrates: advisories.size,
    },
  };
}

/**
 * Map RustSec categories to severity levels
 */
export function categoryToSeverity(categories: string[]): Severity {
  const categorySet = new Set(categories);

  // Critical: code execution, privilege escalation
  if (
    categorySet.has('code-execution') ||
    categorySet.has('privilege-escalation')
  ) {
    return 'critical';
  }

  // High: memory safety, denial of service
  if (categorySet.has('memory-safety') || categorySet.has('denial-of-service')) {
    return 'high';
  }

  // Medium: crypto issues, information disclosure
  if (
    categorySet.has('crypto-failure') ||
    categorySet.has('information-disclosure')
  ) {
    return 'medium';
  }

  // Default to medium for unknown categories
  return 'medium';
}

/**
 * Get advisories for a specific crate
 */
export function getAdvisoriesForCrate(
  db: AdvisoryDatabase,
  crateName: string
): AdvisoryVulnerability[] {
  return db.advisories.get(crateName) || [];
}

/**
 * Search advisories by CVE ID
 */
export function findAdvisoryByCve(
  db: AdvisoryDatabase,
  cveId: string
): AdvisoryVulnerability | undefined {
  for (const advisories of db.advisories.values()) {
    for (const advisory of advisories) {
      if (advisory.aliases.includes(cveId)) {
        return advisory;
      }
    }
  }
  return undefined;
}

/**
 * Get all unique crate names with advisories
 */
export function getVulnerableCrates(db: AdvisoryDatabase): string[] {
  return Array.from(db.advisories.keys());
}
