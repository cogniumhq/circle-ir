#!/usr/bin/env npx tsx
/**
 * Demo server for Circle-IR Playground
 *
 * Run with: npx tsx demo/server.ts
 * Then open: http://localhost:3000
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { initAnalyzer, analyzeForAPI } from '../src/analyzer.js';
import type { SupportedLanguage } from '../src/core/index.js';

const PORT = 3000;
const DEMO_DIR = path.dirname(new URL(import.meta.url).pathname);

// MIME types
const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
};

async function startServer() {
  console.log('Initializing Circle-IR analyzer...');
  await initAnalyzer();
  console.log('Analyzer ready!\n');

  const server = http.createServer(async (req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url || '/', `http://localhost:${PORT}`);

    // API endpoint
    if (url.pathname === '/api/analyze' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const { code, language } = JSON.parse(body);

          if (!code) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Missing code' }));
            return;
          }

          const lang = (language || 'java') as SupportedLanguage;
          const result = await analyzeForAPI(code, `input.${lang}`, lang);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Unknown error';
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: message }));
        }
      });
      return;
    }

    // Static files
    let filePath = url.pathname === '/' ? '/index.html' : url.pathname;
    const fullPath = path.join(DEMO_DIR, filePath);

    try {
      const content = fs.readFileSync(fullPath);
      const ext = path.extname(filePath);
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';

      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  });

  server.listen(PORT, () => {
    console.log('='.repeat(50));
    console.log('  Circle-IR Playground');
    console.log('='.repeat(50));
    console.log(`\n  Open in browser: http://localhost:${PORT}\n`);
    console.log('  Press Ctrl+C to stop\n');
    console.log('='.repeat(50));
  });
}

startServer().catch(console.error);
