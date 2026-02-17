/**
 * Dependency vulnerability scanner for Rust projects
 *
 * Scans Cargo.lock files for known vulnerable crate versions
 * using the RustSec Advisory Database.
 */

import type { Severity } from '../types/index.js';
import type { AdvisoryVulnerability, AdvisoryDatabase } from './advisory-db.js';
import {
  loadBundledAdvisories,
  getAdvisoriesForCrate,
  categoryToSeverity,
} from './advisory-db.js';
import { parseCargoLock, filterRegistryDeps, type CargoLockDependency } from './cargo-parser.js';
import { isVersionVulnerable } from './semver.js';

/**
 * A finding for a vulnerable dependency
 */
export interface DependencyFinding {
  type: 'vulnerable_dependency';
  /** Crate name */
  crate: string;
  /** Installed version */
  version: string;
  /** Matching advisories */
  vulnerabilities: AdvisoryVulnerability[];
  /** Source file (Cargo.lock) */
  source: string;
  /** Location information */
  location: {
    file: string;
    line?: number;
  };
  /** Severity level */
  severity: Severity;
  /** CWE IDs from advisories */
  cwes: string[];
  /** CVE IDs from advisories */
  cves: string[];
}

/**
 * Options for dependency scanning
 */
export interface ScanOptions {
  /** Path to Cargo.lock file */
  cargoLockPath?: string;
  /** Cargo.lock content (if already loaded) */
  cargoLockContent?: string;
  /** Custom advisory database (defaults to bundled) */
  advisoryDb?: AdvisoryDatabase;
  /** Include dev dependencies */
  includeDevDeps?: boolean;
}

/**
 * Scan result
 */
export interface ScanResult {
  /** List of vulnerable dependencies */
  findings: DependencyFinding[];
  /** Total dependencies scanned */
  totalDependencies: number;
  /** Number of vulnerable dependencies */
  vulnerableCount: number;
  /** Advisory database info */
  advisoryDbInfo: {
    source: string;
    lastUpdated: string;
    totalAdvisories: number;
  };
}

/**
 * Check if a specific crate version is vulnerable
 */
export function checkCrateVulnerability(
  crateName: string,
  version: string,
  db: AdvisoryDatabase
): AdvisoryVulnerability[] {
  const advisories = getAdvisoriesForCrate(db, crateName);

  return advisories.filter((advisory) => {
    return isVersionVulnerable(
      version,
      advisory.versions.patched,
      advisory.versions.unaffected
    );
  });
}

/**
 * Scan Cargo.lock content for vulnerable dependencies
 */
export function scanCargoLock(
  content: string,
  options: ScanOptions = {}
): ScanResult {
  const db = options.advisoryDb || loadBundledAdvisories();
  const cargoLock = parseCargoLock(content);
  const deps = filterRegistryDeps(cargoLock.dependencies);

  const findings: DependencyFinding[] = [];

  for (const dep of deps) {
    const vulnerableAdvisories = checkCrateVulnerability(dep.name, dep.version, db);

    if (vulnerableAdvisories.length > 0) {
      // Extract CWEs and CVEs from advisories
      const cwes: string[] = [];
      const cves: string[] = [];

      for (const advisory of vulnerableAdvisories) {
        for (const alias of advisory.aliases) {
          if (alias.startsWith('CVE-')) {
            cves.push(alias);
          } else if (alias.startsWith('CWE-')) {
            cwes.push(alias);
          }
        }
      }

      // Calculate severity from all advisories
      const allCategories = vulnerableAdvisories.flatMap((a) => a.categories);
      const severity = categoryToSeverity(allCategories);

      findings.push({
        type: 'vulnerable_dependency',
        crate: dep.name,
        version: dep.version,
        vulnerabilities: vulnerableAdvisories,
        source: 'Cargo.lock',
        location: {
          file: options.cargoLockPath || 'Cargo.lock',
        },
        severity,
        cwes: [...new Set(cwes)],
        cves: [...new Set(cves)],
      });
    }
  }

  // Sort findings by severity
  const severityOrder: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  findings.sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  return {
    findings,
    totalDependencies: deps.length,
    vulnerableCount: findings.length,
    advisoryDbInfo: {
      source: db.source,
      lastUpdated: db.lastUpdated,
      totalAdvisories: db.stats?.totalAdvisories || 0,
    },
  };
}

/**
 * Format a dependency finding as a human-readable string
 */
export function formatFinding(finding: DependencyFinding): string {
  const lines: string[] = [];

  lines.push(`${finding.crate}@${finding.version} [${finding.severity.toUpperCase()}]`);

  for (const vuln of finding.vulnerabilities) {
    lines.push(`  ${vuln.id}: ${vuln.title || vuln.description.slice(0, 80)}`);
    if (vuln.aliases.length > 0) {
      lines.push(`    Aliases: ${vuln.aliases.join(', ')}`);
    }
    if (vuln.versions.patched && vuln.versions.patched.length > 0) {
      lines.push(`    Patched: ${vuln.versions.patched.join(', ')}`);
    }
    lines.push(`    URL: ${vuln.url}`);
  }

  return lines.join('\n');
}

/**
 * Format scan result as a human-readable report
 */
export function formatScanReport(result: ScanResult): string {
  const lines: string[] = [];

  lines.push('=== RUST DEPENDENCY VULNERABILITY SCAN ===');
  lines.push('');
  lines.push(`Dependencies scanned: ${result.totalDependencies}`);
  lines.push(`Vulnerable packages: ${result.vulnerableCount}`);
  lines.push(`Advisory DB: ${result.advisoryDbInfo.source} (${result.advisoryDbInfo.lastUpdated})`);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('No known vulnerabilities found.');
  } else {
    lines.push('VULNERABLE DEPENDENCIES:');
    lines.push('');

    for (const finding of result.findings) {
      lines.push(formatFinding(finding));
      lines.push('');
    }
  }

  return lines.join('\n');
}
