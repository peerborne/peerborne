import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  chartDefinitions,
  generateCharts,
} from './generate-benchmark-charts.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const snapshot = JSON.parse(
  readFileSync(resolve(root, 'site/src/data/benchmark-snapshot.json'), 'utf8'),
);

test('all six charts are deterministic and current', () => {
  const first = generateCharts(snapshot);
  const second = generateCharts(snapshot);

  assert.equal(first.size, 6);
  assert.deepEqual(first, second);
  for (const [filename, svg] of first) {
    const output = readFileSync(
      resolve(root, 'site/src/assets/charts', filename),
      'utf8',
    );
    assert.equal(output, svg, filename);
  }
});

test('charts are accessible, self-contained SVG without invalid values', () => {
  for (const [filename, svg] of generateCharts(snapshot)) {
    assert.match(svg, /^<svg[^>]+viewBox="0 0 1120 620"/, filename);
    assert.match(svg, /<title id="title">/, filename);
    assert.match(svg, /<desc id="description">/, filename);
    assert.doesNotMatch(svg, /(?:NaN|Infinity|\[object Object\])/, filename);
    assert.doesNotMatch(svg, /<(?:image|foreignObject|script)\b/i, filename);
    assert.doesNotMatch(svg, /(?:href|src)=["'](?:https?:|data:)/i, filename);
  }
});

test('missing metrics fail generation instead of becoming zero', () => {
  const incomplete = structuredClone(snapshot);
  incomplete.suites.find(
    (suite) => suite.benchmark === 'crdt-sync-latency',
  ).results = [];

  assert.throws(() => chartDefinitions(incomplete), /has no results/);
});
