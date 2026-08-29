#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), '../..');
const snapshotPath = resolve(root, 'site/src/data/benchmark-snapshot.json');
const outputDirectory = resolve(root, 'site/src/assets/charts');
const chartWidth = 1120;
const chartHeight = 620;
const plot = { x: 92, y: 135, width: 978, height: 350 };
const palette = ['#2dd4bf', '#818cf8', '#f59e0b', '#f472b6'];

function escapeXml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function readSnapshot() {
  return JSON.parse(readFileSync(snapshotPath, 'utf8'));
}

function validateSnapshot(snapshot) {
  if (snapshot.schemaVersion !== 1) {
    throw new Error(`Unsupported benchmark snapshot schema: ${snapshot.schemaVersion}`);
  }
  if (!/^[0-9a-f]{40}$/.test(snapshot.sourceCommit)) {
    throw new Error('Benchmark snapshot requires a full source commit SHA');
  }
  if (!Array.isArray(snapshot.suites) || snapshot.suites.length !== 6) {
    throw new Error('Benchmark snapshot must contain all six suites');
  }
  for (const suite of snapshot.suites) {
    if (!Array.isArray(suite.results) || suite.results.length === 0) {
      throw new Error(`Benchmark suite ${suite.benchmark} has no results`);
    }
  }
}

function suite(snapshot, name) {
  const match = snapshot.suites.find((candidate) => candidate.benchmark === name);
  if (!match) throw new Error(`Missing benchmark suite: ${name}`);
  return match;
}

function metric(snapshot, suiteName, name) {
  const result = suite(snapshot, suiteName).results.find(
    (candidate) => candidate.name === name,
  );
  if (!result) throw new Error(`Missing benchmark metric: ${suiteName}/${name}`);
  if (result.unit !== 'ms') {
    throw new Error(`Expected millisecond metric: ${suiteName}/${name}`);
  }
  for (const field of ['mean', 'p99']) {
    if (!Number.isFinite(result.stats?.[field]) || result.stats[field] < 0) {
      throw new Error(`Invalid ${field}: ${suiteName}/${name}`);
    }
  }
  if (!Number.isInteger(result.iterations) || result.iterations <= 0) {
    throw new Error(`Invalid iterations: ${suiteName}/${name}`);
  }
  return {
    mean: result.stats.mean,
    p99: result.stats.p99,
    iterations: result.iterations,
  };
}

function series(snapshot, suiteName, label, prefix, labels) {
  return {
    label,
    points: labels.map((name) => metric(snapshot, suiteName, `${prefix}${name}`)),
  };
}

export function chartDefinitions(snapshot) {
  validateSnapshot(snapshot);
  const payloads = ['1kb', '10kb', '100kb', '1mb'];
  const documents = ['100', '1000', '10000'];
  const peers = ['2', '4', '8', '16', '32'];
  const filters = ['1k-bits', '8k-bits', '64k-bits', '256k-bits', '1m-bits'];
  const fields = ['1', '2', '4', '8', '16'];

  return [
    {
      filename: 'crdt-pipeline-latency.svg',
      title: 'Signed and encrypted change pipeline',
      subtitle: 'Mean local operation latency by payload size; whiskers show p99',
      description:
        'Line chart of mean sign-and-encrypt and decrypt-and-verify latency from one kilobyte to one megabyte, with p99 whiskers.',
      xLabel: 'Payload size (log-spaced categories)',
      xLabels: ['1 KB', '10 KB', '100 KB', '1 MB'],
      yLabel: 'Latency (ms)',
      scale: 'linear',
      series: [
        series(snapshot, 'crdt-sync-latency', 'Sign + encrypt', 'sign-encrypt-', payloads),
        series(snapshot, 'crdt-sync-latency', 'Decrypt + verify', 'decrypt-verify-', payloads),
      ],
    },
    {
      filename: 'crypto-pipeline-overhead.svg',
      title: 'Plaintext and encrypted pipeline cost',
      subtitle: 'Local synthetic pipeline comparison; mean with p99 whiskers',
      description:
        'Line chart comparing plaintext and encrypted local synthetic pipeline latency across four payload sizes.',
      xLabel: 'Payload size (log-spaced categories)',
      xLabels: ['1 KB', '10 KB', '100 KB', '1 MB'],
      yLabel: 'Latency (ms)',
      scale: 'linear',
      series: [
        series(snapshot, 'crypto-overhead', 'Plaintext pipeline', 'plaintext-pipeline-', payloads),
        series(snapshot, 'crypto-overhead', 'Encrypted pipeline', 'encrypted-pipeline-', payloads),
      ],
    },
    {
      filename: 'convergence-scaling.svg',
      title: 'Simulated convergence scaling',
      subtitle: 'Full local sign/encrypt/broadcast/decrypt/verify simulation; log latency axis',
      description:
        'Line chart of simulated convergence latency from two to 32 peers on a logarithmic latency axis.',
      xLabel: 'Simulated peers',
      xLabels: peers,
      yLabel: 'Latency (ms, log scale)',
      scale: 'log',
      series: [
        series(snapshot, 'convergence-simulation', 'Convergence', 'convergence-', peers.map((value) => `${value}-peers`)),
      ],
    },
    {
      filename: 'index-query-scaling.svg',
      title: 'In-memory index query scaling',
      subtitle: 'Mean local query latency by indexed document count; p99 whiskers',
      description:
        'Line chart comparing exact-match, prefix, and compound local in-memory index query latency from 100 to 10,000 documents.',
      xLabel: 'Indexed documents (log-spaced categories)',
      xLabels: ['100', '1K', '10K'],
      yLabel: 'Latency (ms)',
      scale: 'linear',
      series: [
        series(snapshot, 'index-query-scaling', 'Exact match', 'exact-match-', documents),
        series(snapshot, 'index-query-scaling', 'Prefix query', 'prefix-query-', documents),
        series(snapshot, 'index-query-scaling', 'Compound query', 'compound-query-', documents),
      ],
    },
    {
      filename: 'bloom-filter-scaling.svg',
      title: 'Bloom filter operation scaling',
      subtitle: 'Insert 1,000 items and merge two filters; mean with p99 whiskers',
      description:
        'Line chart comparing insertion and merge latency across Bloom filter sizes from one kilobit to one megabit.',
      xLabel: 'Filter size (log-spaced categories)',
      xLabels: ['1 Kb', '8 Kb', '64 Kb', '256 Kb', '1 Mb'],
      yLabel: 'Latency (ms)',
      scale: 'linear',
      series: [
        series(snapshot, 'bloom-filter-scaling', 'Insert 1,000', 'insert-1000-into-', filters),
        series(snapshot, 'bloom-filter-scaling', 'Merge filters', 'merge-', filters),
      ],
    },
    {
      filename: 'blind-index-scaling.svg',
      title: 'Blind-index field scaling',
      subtitle: 'Derive field keys and compute tokens locally; mean with p99 whiskers',
      description:
        'Line chart of blind-index key derivation and tokenization latency from one to 16 fields.',
      xLabel: 'Fields tokenized',
      xLabels: fields,
      yLabel: 'Latency (ms)',
      scale: 'linear',
      series: [
        series(snapshot, 'blind-index-perf', 'Derive + tokenize', 'derive-and-tokenize-', fields.map((value) => `${value}-fields`)),
      ],
    },
  ];
}

function niceMaximum(value) {
  const exponent = 10 ** Math.floor(Math.log10(value || 1));
  const normalized = value / exponent;
  const step = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return step * exponent;
}

function formatNumber(value) {
  if (value >= 1000) return `${Number((value / 1000).toPrecision(3))}k`;
  if (value >= 10) return String(Number(value.toPrecision(3)));
  if (value >= 1) return value.toFixed(1).replace(/\.0$/, '');
  if (value >= 0.01) return value.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');
  return value.toFixed(3).replace(/0+$/, '').replace(/\.$/, '');
}

function scaleFor(chart) {
  const values = chart.series.flatMap((item) =>
    item.points.flatMap((point) => [point.mean, point.p99]),
  );
  const maximum = Math.max(...values);
  if (chart.scale === 'log') {
    const positive = values.filter((value) => value > 0);
    const minimumPower = Math.floor(Math.log10(Math.min(...positive)));
    const maximumPower = Math.ceil(Math.log10(maximum));
    const ticks = Array.from(
      { length: maximumPower - minimumPower + 1 },
      (_, index) => 10 ** (minimumPower + index),
    );
    return {
      ticks,
      y(value) {
        const ratio =
          (Math.log10(Math.max(value, ticks[0])) - minimumPower) /
          (maximumPower - minimumPower);
        return plot.y + plot.height - ratio * plot.height;
      },
    };
  }

  const top = niceMaximum(maximum * 1.08);
  const ticks = Array.from({ length: 6 }, (_, index) => (top * index) / 5);
  return {
    ticks,
    y(value) {
      return plot.y + plot.height - (value / top) * plot.height;
    },
  };
}

function xPosition(index, count) {
  if (count === 1) return plot.x + plot.width / 2;
  return plot.x + (plot.width * index) / (count - 1);
}

function iterationSummary(chart) {
  const iterations = [
    ...new Set(chart.series.flatMap((item) => item.points.map((point) => point.iterations))),
  ].sort((a, b) => a - b);
  return iterations.length === 1
    ? `${iterations[0]} timed iterations per point`
    : `${iterations.join('–')} timed iterations per point`;
}

export function renderChart(chart, snapshot) {
  const scale = scaleFor(chart);
  const grid = scale.ticks
    .map((tick) => {
      const y = scale.y(tick);
      return `    <line x1="${plot.x}" y1="${y.toFixed(2)}" x2="${plot.x + plot.width}" y2="${y.toFixed(2)}" stroke="#334155" stroke-width="1"/>
    <text x="${plot.x - 14}" y="${(y + 5).toFixed(2)}" fill="#94a3b8" font-size="13" text-anchor="end">${escapeXml(formatNumber(tick))}</text>`;
    })
    .join('\n');
  const xAxis = chart.xLabels
    .map((label, index) => {
      const x = xPosition(index, chart.xLabels.length);
      return `    <line x1="${x.toFixed(2)}" y1="${plot.y + plot.height}" x2="${x.toFixed(2)}" y2="${plot.y + plot.height + 7}" stroke="#64748b"/>
    <text x="${x.toFixed(2)}" y="${plot.y + plot.height + 27}" fill="#cbd5e1" font-size="14" font-weight="650" text-anchor="middle">${escapeXml(label)}</text>`;
    })
    .join('\n');
  const renderedSeries = chart.series
    .map((item, seriesIndex) => {
      const color = palette[seriesIndex];
      const points = item.points.map((point, index) => ({
        ...point,
        x: xPosition(index, item.points.length),
        meanY: scale.y(point.mean),
        p99Y: scale.y(point.p99),
      }));
      const path = points
        .map((point, index) => `${index === 0 ? 'M' : 'L'}${point.x.toFixed(2)} ${point.meanY.toFixed(2)}`)
        .join(' ');
      const marks = points
        .map((point) => {
          const preferredOffset = seriesIndex === 0 ? -12 : 20 + seriesIndex * 14;
          const labelY =
            point.meanY + preferredOffset > plot.y + plot.height - 5
              ? point.meanY - 12 - seriesIndex * 15
              : point.meanY + preferredOffset;
          return `      <line x1="${point.x.toFixed(2)}" y1="${point.meanY.toFixed(2)}" x2="${point.x.toFixed(2)}" y2="${point.p99Y.toFixed(2)}" stroke="${color}" stroke-width="2" stroke-opacity=".65"/>
      <line x1="${(point.x - 6).toFixed(2)}" y1="${point.p99Y.toFixed(2)}" x2="${(point.x + 6).toFixed(2)}" y2="${point.p99Y.toFixed(2)}" stroke="${color}" stroke-width="2"/>
      <circle cx="${point.x.toFixed(2)}" cy="${point.meanY.toFixed(2)}" r="6" fill="#0f172a" stroke="${color}" stroke-width="3"/>
      <text x="${point.x.toFixed(2)}" y="${labelY.toFixed(2)}" fill="${color}" font-size="11.5" font-weight="750" text-anchor="middle">${escapeXml(formatNumber(point.mean))}</text>`;
        })
        .join('\n');
      return `    <g aria-label="${escapeXml(item.label)}">
      <path d="${path}" fill="none" stroke="${color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
${marks}
    </g>`;
    })
    .join('\n');
  const legend = chart.series
    .map((item, index) => {
      const x = plot.x + index * 245;
      return `    <line x1="${x}" y1="107" x2="${x + 28}" y2="107" stroke="${palette[index]}" stroke-width="4" stroke-linecap="round"/>
    <circle cx="${x + 14}" cy="107" r="5" fill="#0f172a" stroke="${palette[index]}" stroke-width="2"/>
    <text x="${x + 38}" y="112" fill="#e2e8f0" font-size="14" font-weight="650">${escapeXml(item.label)}</text>`;
    })
    .join('\n');
  const commit = snapshot.sourceCommit.slice(0, 8);
  const date = snapshot.collectedAt.slice(0, 10);

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${chartWidth}" height="${chartHeight}" viewBox="0 0 ${chartWidth} ${chartHeight}" role="img" aria-labelledby="title description">
  <title id="title">${escapeXml(chart.title)}</title>
  <desc id="description">${escapeXml(chart.description)} Dots show means and capped whiskers show p99. This is a directional single-machine snapshot, not a performance guarantee.</desc>
  <defs>
    <linearGradient id="background" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0f172a"/>
      <stop offset="1" stop-color="#111827"/>
    </linearGradient>
    <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
      <path d="M40 0H0V40" fill="none" stroke="#94a3b8" stroke-opacity=".035"/>
    </pattern>
    <style>text { font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }</style>
  </defs>
  <rect width="${chartWidth}" height="${chartHeight}" rx="26" fill="url(#background)"/>
  <rect width="${chartWidth}" height="${chartHeight}" rx="26" fill="url(#grid)"/>
  <path d="M0 26A26 26 0 0 1 26 0H1094A26 26 0 0 1 1120 26V32H0Z" fill="#2dd4bf"/>
  <g>
    <text x="42" y="59" fill="#f8fafc" font-size="29" font-weight="780">${escapeXml(chart.title)}</text>
    <text x="42" y="84" fill="#94a3b8" font-size="15">${escapeXml(chart.subtitle)}</text>
${legend}
${grid}
    <line x1="${plot.x}" y1="${plot.y}" x2="${plot.x}" y2="${plot.y + plot.height}" stroke="#64748b" stroke-width="1.5"/>
    <line x1="${plot.x}" y1="${plot.y + plot.height}" x2="${plot.x + plot.width}" y2="${plot.y + plot.height}" stroke="#64748b" stroke-width="1.5"/>
${xAxis}
${renderedSeries}
    <text x="${plot.x + plot.width / 2}" y="538" fill="#cbd5e1" font-size="14" font-weight="650" text-anchor="middle">${escapeXml(chart.xLabel)}</text>
    <text x="24" y="${plot.y + plot.height / 2}" fill="#cbd5e1" font-size="14" font-weight="650" text-anchor="middle" transform="rotate(-90 24 ${plot.y + plot.height / 2})">${escapeXml(chart.yLabel)}</text>
    <rect x="42" y="557" width="1036" height="43" rx="12" fill="#0b1524" stroke="#334155"/>
    <text x="560" y="575" fill="#94a3b8" font-size="11.5" text-anchor="middle">Directional snapshot · ${escapeXml(snapshot.system.cpu)} · ${escapeXml(snapshot.system.node)} · ${escapeXml(snapshot.system.platform)}/${escapeXml(snapshot.system.arch)} · commit ${commit} · ${date}</text>
    <text x="560" y="591" fill="#94a3b8" font-size="11.5" text-anchor="middle">Mean dots + p99 whiskers · ${escapeXml(iterationSummary(chart))} · no pass/fail budget</text>
  </g>
</svg>
`;
}

export function generateCharts(snapshot) {
  return new Map(
    chartDefinitions(snapshot).map((chart) => [
      chart.filename,
      renderChart(chart, snapshot),
    ]),
  );
}

function run() {
  const charts = generateCharts(readSnapshot());
  const checking = process.argv.includes('--check');
  if (!checking) mkdirSync(outputDirectory, { recursive: true });

  for (const [filename, svg] of charts) {
    const path = resolve(outputDirectory, filename);
    if (checking) {
      let current;
      try {
        current = readFileSync(path, 'utf8');
      } catch {
        throw new Error(`Missing generated chart: ${path}`);
      }
      if (current !== svg) {
        throw new Error(`Generated chart is stale: ${path}`);
      }
    } else {
      writeFileSync(path, svg);
    }
  }

  console.log(`${checking ? 'Verified' : 'Generated'} ${charts.size} benchmark charts`);
}

if (resolve(process.argv[1] ?? '') === scriptPath) {
  run();
}
