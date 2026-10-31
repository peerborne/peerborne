import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  chartDefinitions,
  generateCharts,
  renderChart,
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

test('pixel styling preserves every measurement and category position', () => {
  for (const chart of chartDefinitions(snapshot)) {
    const svg = renderChart(chart, snapshot);
    const marks = [...svg.matchAll(/<rect\b[^>]*class="mean-marker"[^>]*>/g)].map(
      (match) => match[0],
    );
    const points = chart.series.flatMap((series) => series.points);
    assert.equal(marks.length, points.length, chart.filename);
    marks.forEach((mark, index) => {
      assert.equal(Number(/data-mean="([^"]+)"/.exec(mark)[1]), points[index].mean);
      assert.equal(Number(/data-p99="([^"]+)"/.exec(mark)[1]), points[index].p99);
      const x =
        Number(/\bx="([^"]+)"/.exec(mark)[1]) +
        Number(/\bwidth="([^"]+)"/.exec(mark)[1]) / 2;
      const expected = {
        3: [92, 581, 1070],
        4: [92, 418, 744, 1070],
        5: [92, 336.5, 581, 825.5, 1070],
      }[chart.xLabels.length];
      assert.equal(x, expected[index % chart.xLabels.length]);
    });
    assert.match(svg, /class="pixel-heading"/);
    assert.match(svg, /Squares show means and capped whiskers show p99/);
    assert.ok(svg.includes(snapshot.sourceCommit.slice(0, 8)));
    assert.ok(svg.includes(snapshot.system.cpu));
    assert.doesNotMatch(svg, /<circle|linearGradient|r[xy]="[1-9]/);
  }
});
