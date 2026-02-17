#!/usr/bin/env tsx
/**
 * Fetch RustSec Advisory Database from OSV
 *
 * Downloads the full RustSec advisory database from the OSV GCS bucket
 * and converts it to our bundled format.
 *
 * Usage:
 *   npx tsx scripts/fetch-rustsec-osv.ts
 *   npx tsx scripts/fetch-rustsec-osv.ts --output advisory-db.json
 */

import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import { createGunzip } from 'zlib';
import { pipeline } from 'stream/promises';
import { Readable } from 'stream';
import { Extract } from 'unzipper';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const OSV_URL = 'https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip';

interface OSVVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  database_specific?: {
    categories?: string[];
    cvss?: string;
    informational?: string;
    url?: string;
  };
  affected?: Array<{
    package: {
      ecosystem: string;
      name: string;
    };
    ecosystem_specific?: {
      affects?: {
        arch?: string[];
        os?: string[];
        functions?: string[];
      };
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
      }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{
    type: string;
    url: string;
  }>;
  severity?: Array<{
    type: string;
    score: string;
  }>;
}

interface BundledAdvisory {
  id: string;
  package: string;
  date: string;
  url: string;
  cvss?: string;
  categories: string[];
  keywords: string[];
  aliases: string[];
  versions: {
    patched?: string[];
    unaffected?: string[];
  };
  description: string;
  title?: string;
}

interface BundledDatabase {
  version: string;
  lastUpdated: string;
  advisories: BundledAdvisory[];
}

/**
 * Download a file from URL
 */
async function downloadFile(url: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];

    const request = https.get(url, (response) => {
      if (response.statusCode === 301 || response.statusCode === 302) {
        // Follow redirect
        const redirectUrl = response.headers.location;
        if (redirectUrl) {
          downloadFile(redirectUrl).then(resolve).catch(reject);
          return;
        }
      }

      if (response.statusCode !== 200) {
        reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
        return;
      }

      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve(Buffer.concat(chunks)));
      response.on('error', reject);
    });

    request.on('error', reject);
    request.setTimeout(60000, () => {
      request.destroy();
      reject(new Error('Download timeout'));
    });
  });
}

/**
 * Convert OSV version ranges to our format
 */
function extractVersions(affected?: OSVVulnerability['affected']): {
  patched?: string[];
  unaffected?: string[];
} {
  const result: { patched?: string[]; unaffected?: string[] } = {};

  if (!affected || affected.length === 0) {
    return result;
  }

  const patched: string[] = [];
  const unaffected: string[] = [];

  for (const a of affected) {
    if (a.ranges) {
      for (const range of a.ranges) {
        for (const event of range.events) {
          if (event.fixed) {
            patched.push(`>= ${event.fixed}`);
          }
          if (event.introduced === '0') {
            // Introduced from beginning, so no unaffected versions before this
          } else if (event.introduced) {
            unaffected.push(`< ${event.introduced}`);
          }
        }
      }
    }
  }

  if (patched.length > 0) {
    result.patched = [...new Set(patched)];
  }
  if (unaffected.length > 0) {
    result.unaffected = [...new Set(unaffected)];
  }

  return result;
}

/**
 * Convert OSV vulnerability to our format
 */
function convertOSVToAdvisory(osv: OSVVulnerability): BundledAdvisory | null {
  // Skip if no affected packages
  if (!osv.affected || osv.affected.length === 0) {
    return null;
  }

  // Get the first affected crate (most advisories have one)
  const affected = osv.affected[0];
  if (!affected.package || affected.package.ecosystem !== 'crates.io') {
    return null;
  }

  // Extract CVSS from severity
  let cvss: string | undefined;
  if (osv.severity) {
    const cvssEntry = osv.severity.find((s) => s.type === 'CVSS_V3');
    if (cvssEntry) {
      cvss = cvssEntry.score;
    }
  }

  // Extract URL
  let url = '';
  if (osv.references) {
    const advisory = osv.references.find((r) => r.type === 'ADVISORY');
    url = advisory?.url || osv.references[0]?.url || '';
  }
  if (!url && osv.database_specific?.url) {
    url = osv.database_specific.url;
  }

  // Get date
  const date = osv.published || osv.modified || new Date().toISOString();

  return {
    id: osv.id,
    package: affected.package.name,
    date,
    url,
    cvss,
    categories: osv.database_specific?.categories || [],
    keywords: [],
    aliases: osv.aliases || [],
    versions: extractVersions(osv.affected),
    description: osv.details || osv.summary || '',
    title: osv.summary,
  };
}

/**
 * Parse all JSON files from ZIP buffer
 */
async function parseZipBuffer(zipBuffer: Buffer): Promise<OSVVulnerability[]> {
  const vulnerabilities: OSVVulnerability[] = [];

  // Create temporary directory
  const tmpDir = fs.mkdtempSync('/tmp/osv-');

  try {
    // Extract ZIP to temp directory
    const readable = Readable.from(zipBuffer);
    await pipeline(
      readable,
      Extract({ path: tmpDir })
    );

    // Read all JSON files
    const files = fs.readdirSync(tmpDir);
    for (const file of files) {
      if (file.endsWith('.json')) {
        const filePath = path.join(tmpDir, file);
        const content = fs.readFileSync(filePath, 'utf-8');
        try {
          const vuln = JSON.parse(content) as OSVVulnerability;
          vulnerabilities.push(vuln);
        } catch (e) {
          console.error(`Failed to parse ${file}:`, e);
        }
      }
    }
  } finally {
    // Cleanup
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return vulnerabilities;
}

async function main() {
  const args = process.argv.slice(2);
  let outputPath = path.join(__dirname, '..', 'advisory-db.json');

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' || args[i] === '-o') {
      outputPath = args[i + 1];
      i++;
    }
  }

  console.log('Fetching RustSec advisories from OSV...');
  console.log(`URL: ${OSV_URL}`);

  try {
    // Download ZIP
    console.log('Downloading...');
    const zipBuffer = await downloadFile(OSV_URL);
    console.log(`Downloaded ${(zipBuffer.length / 1024 / 1024).toFixed(2)} MB`);

    // Parse ZIP
    console.log('Extracting and parsing...');
    const vulnerabilities = await parseZipBuffer(zipBuffer);
    console.log(`Found ${vulnerabilities.length} OSV entries`);

    // Convert to our format
    const advisories: BundledAdvisory[] = [];
    for (const vuln of vulnerabilities) {
      const advisory = convertOSVToAdvisory(vuln);
      if (advisory) {
        advisories.push(advisory);
      }
    }

    console.log(`Converted ${advisories.length} advisories`);

    // Group by crate for stats
    const crateSet = new Set(advisories.map((a) => a.package));
    console.log(`Covering ${crateSet.size} unique crates`);

    // Build output
    const database: BundledDatabase = {
      version: '2.0',
      lastUpdated: new Date().toISOString(),
      advisories,
    };

    // Write output
    fs.writeFileSync(outputPath, JSON.stringify(database, null, 2));
    console.log(`\nWritten to: ${outputPath}`);
    console.log(`File size: ${(fs.statSync(outputPath).size / 1024).toFixed(2)} KB`);

    // Show some stats
    console.log('\nCategory breakdown:');
    const categories: Record<string, number> = {};
    for (const a of advisories) {
      for (const cat of a.categories) {
        categories[cat] = (categories[cat] || 0) + 1;
      }
    }
    Object.entries(categories)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .forEach(([cat, count]) => {
        console.log(`  ${cat}: ${count}`);
      });

  } catch (error) {
    console.error('Failed to fetch advisories:', error);
    process.exit(1);
  }
}

main();
