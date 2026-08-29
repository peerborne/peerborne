#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { cpus, totalmem } from 'node:os';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), '../..');
const outputPath = resolve(root, 'site/src/data/benchmark-snapshot.json');
const chartMetricNames = {
  'crdt-sync-latency': ['sign-encrypt', 'decrypt-verify'].flatMap((prefix) =>
    ['1kb', '10kb', '100kb', '1mb'].map((size) => `${prefix}-${size}`),
  ),
  'crypto-overhead': ['plaintext-pipeline', 'encrypted-pipeline'].flatMap(
    (prefix) =>
      ['1kb', '10kb', '100kb', '1mb'].map((size) => `${prefix}-${size}`),
  ),
  'convergence-simulation': ['2', '4', '8', '16', '32'].map(
    (peers) => `convergence-${peers}-peers`,
  ),
  'index-query-scaling': ['exact-match', 'prefix-query', 'compound-query'].flatMap(
    (prefix) => ['100', '1000', '10000'].map((count) => `${prefix}-${count}`),
  ),
  'bloom-filter-scaling': ['insert-1000-into', 'merge'].flatMap((prefix) =>
    ['1k-bits', '8k-bits', '64k-bits', '256k-bits', '1m-bits'].map(
      (size) => `${prefix}-${size}`,
    ),
  ),
  'blind-index-perf': ['1', '2', '4', '8', '16'].map(
    (fields) => `derive-and-tokenize-${fields}-fields`,
  ),
};

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

function positiveInteger(name, fallback) {
  const raw = option(name, String(fallback));
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function readSuites(path) {
  const suites = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(suites) || suites.length === 0) {
    throw new Error(`Expected benchmark suites in ${path}`);
  }
  return suites;
}

function currentCommit() {
  const result = spawnSync('git', ['rev-parse', 'HEAD'], {
    cwd: root,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(`Could not determine source commit: ${result.stderr}`);
  }
  return result.stdout.trim();
}

function selectChartMetrics(suites) {
  return Object.entries(chartMetricNames).map(([benchmark, names]) => {
    const source = suites.find((suite) => suite.benchmark === benchmark);
    if (!source) throw new Error(`Missing benchmark suite: ${benchmark}`);
    return {
      benchmark,
      timestamp: source.timestamp,
      system: source.system,
      results: names.map((name) => {
        const result = source.results.find((candidate) => candidate.name === name);
        if (!result) throw new Error(`Missing benchmark metric: ${benchmark}/${name}`);
        return {
          name: result.name,
          iterations: result.iterations,
          unit: result.unit,
          stats: {
            mean: result.stats.mean,
            p99: result.stats.p99,
          },
        };
      }),
    };
  });
}

function collect() {
  const coreIterations = positiveInteger('--core-iterations', 100);
  const indexIterations = positiveInteger('--index-iterations', 100);
  const maxDocuments = positiveInteger('--max-documents', 100_000);
  const corePath = resolve(
    root,
    'packages/core/src/__benchmarks__/results.json',
  );
  const indexPath = resolve(
    root,
    'packages/index/src/__benchmarks__/results.json',
  );
  const suites = [...readSuites(corePath), ...readSuites(indexPath)];
  const systems = new Set(suites.map((suite) => JSON.stringify(suite.system)));
  if (systems.size !== 1) {
    throw new Error('Core and index benchmark system metadata do not match');
  }

  const snapshot = {
    schemaVersion: 1,
    sourceCommit: currentCommit(),
    collectedAt: suites
      .map((suite) => suite.timestamp)
      .sort()
      .at(-1),
    system: {
      ...suites[0].system,
      cpu: cpus()[0]?.model ?? 'unknown',
      memoryBytes: totalmem(),
    },
    commands: [
      `yarn workspace @peerborne/core benchmark --iterations ${coreIterations}`,
      `yarn workspace @peerborne/index benchmark --iterations ${indexIterations} --max-documents ${maxDocuments}`,
    ],
    parameters: {
      coreIterations,
      convergenceIterations: Math.max(1, Math.floor(coreIterations / 5)),
      indexIterations,
      maxDocuments,
    },
    suites: selectChartMetrics(suites),
  };

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(snapshot, null, 2)}\n`);
  console.log(`Wrote ${outputPath}`);
}

if (resolve(process.argv[1] ?? '') === scriptPath) {
  collect();
}
