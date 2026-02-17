import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.test.ts'],
    setupFiles: ['tests/setup.ts'],
    testTimeout: 30000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: [
        'src/browser.ts',
        'src/worker.ts',
        'src/cli/**',           // CLI is integration-tested
        'src/types/**',         // Type definitions only
        'src/benchmark/runner.ts',  // Uses file system, integration-tested
        'src/benchmark/report.ts',  // Output formatting
        'src/index.ts',         // Re-exports only
        'src/agents/**',        // LLM agents - require API, integration-tested
        'src/llm/enrichment.ts',   // LLM enrichment - requires API
        'src/llm/verification.ts', // LLM verification - requires API
        'src/llm/index.ts',     // Re-exports only
        'src/resolution/**',    // Project-level analysis, tested in circle-ir-ai
        'src/languages/types.ts',  // Type definitions only
        'src/analysis/constant-propagation/types.ts',  // Type definitions only
      ],
      thresholds: {
        statements: 75,
        branches: 75,
        functions: 75,
        lines: 75,
      },
    },
  },
});
