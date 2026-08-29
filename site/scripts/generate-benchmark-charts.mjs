/**
 * Generates SVG benchmark charts from results.json files produced by
 * the core and index benchmark suites.
 *
 * Usage: node site/scripts/generate-benchmark-charts.mjs
 */
import * as fs from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..');
const OUT_DIR = join(__dirname, '..', 'public', 'benchmarks');

function readJSON(path) {
  return JSON.parse(fs.readFileSync(join(ROOT, path), 'utf-8'));
}

function findResult(suites, name) {
  return suites.flatMap((s) => s.results).find((r) => r.name === name);
}

function meanVal(suites, name) {
  const r = findResult(suites, name);
  return r ? r.meanMs : 0;
}

function width(val, max, available = 560) {
  if (max <= 0) return 0;
  return Math.max(1, (val / max) * available);
}

/* ------------------------------------------------------------------ */
/* SVG helper                                                          */
/* ------------------------------------------------------------------ */

function svgChart({ title, yLabel, data, width: w = 720, height: h = 400 }) {
  const max = Math.max(...data.map((d) => d.value), 1);
  const barAreaLeft = 80;
  const barAreaRight = 120;
  const barAreaTop = 40;
  const barAreaBottom = h - 60;
  const barAreaW = w - barAreaLeft - barAreaRight;
  const barAreaH = barAreaBottom - barAreaTop;
  const labelEvery = Math.max(1, Math.ceil(data.length / 16));

  const bars = data
    .map((d, i) => {
      const bw = barAreaW / data.length;
      const bh = (d.value / max) * barAreaH;
      return {
        x: barAreaLeft + i * bw + 2,
        y: barAreaBottom - bh,
        w: bw - 4,
        h: Math.max(1, bh),
        label: d.label,
        value: d.value,
        showLabel: i % labelEvery === 0 || data.length <= 8,
      };
    })
    .join(
      (d) =>
        `<rect x="${d.x.toFixed(1)}" y="${d.y.toFixed(1)}" width="${d.w.toFixed(1)}" height="${d.h.toFixed(1)}" fill="#6366f1" rx="2"><title>${d.label}: ${d.value.toFixed(3)} ms</title></rect>${d.showLabel ? `<text x="${(d.x + d.w / 2).toFixed(1)}" y="${(barAreaBottom + 14).toFixed(1)}" text-anchor="middle" font-size="9" fill="#6b7280" transform="rotate(-40, ${(d.x + d.w / 2).toFixed(1)}, ${(barAreaBottom + 14).toFixed(1)})">${d.label}</text>` : ''}`,
    );

  const titleLen = title.length * 7;
  const yLines = 5;
  const ySteps = [...Array(yLines + 1)].map((_, i) => ({
    val: (max / yLines) * i,
    y: barAreaBottom - (barAreaH / yLines) * i,
  }));

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #fff; border-radius: 8px;">
  <text x="${w / 2}" y="24" text-anchor="middle" font-size="14" font-weight="600" fill="#111827">${title}</text>
  <line x1="${barAreaLeft}" y1="${barAreaTop}" x2="${barAreaLeft}" y2="${barAreaBottom}" stroke="#e5e7eb" stroke-width="1"/>
  <line x1="${barAreaLeft}" y1="${barAreaBottom}" x2="${barAreaLeft + barAreaW}" y2="${barAreaBottom}" stroke="#e5e7eb" stroke-width="1"/>
  ${ySteps.map((s) => `<line x1="${barAreaLeft}" y1="${s.y.toFixed(1)}" x2="${barAreaLeft + barAreaW}" y2="${s.y.toFixed(1)}" stroke="#f3f4f6" stroke-width="1"/><text x="${barAreaLeft - 6}" y="${(s.y + 4).toFixed(1)}" text-anchor="end" font-size="10" fill="#6b7280">${(s.val < 1 ? s.val.toFixed(2) : s.val.toFixed(1))}</text>`).join('\n  ')}
  <text x="${barAreaLeft + barAreaW / 2}" y="${h - 10}" text-anchor="middle" font-size="11" fill="#4b5563">${yLabel}</text>
  ${bars}
</svg>`;
}

/* ------------------------------------------------------------------ */
/* Chart definitions                                                   */
/* ------------------------------------------------------------------ */

function chartCrdtSyncLatency(coreSuites) {
  const sizes = ['1kb', '10kb', '100kb', '1mb'];
  const ops = [
    { key: 'sign', label: 'Sign (ECDSA P-384)' },
    { key: 'verify', label: 'Verify' },
    { key: 'encrypt', label: 'Encrypt (AES-GCM)' },
    { key: 'decrypt', label: 'Decrypt' },
  ];

  const data = [];
  for (const size of sizes) {
    for (const op of ops) {
      data.push({
        label: `${op.key}-${size}`,
        value: meanVal(coreSuites, `${op.key}-${size}`),
      });
    }
  }
  return svgChart({
    title: 'CRDT Sync Pipeline Latency by Payload Size',
    yLabel: 'Operation × Payload Size',
    data,
    height: 400,
  });
}

function chartCryptoOverhead(coreSuites) {
  const sizes = ['1kb', '10kb', '100kb', '1mb'];
  const data = [];
  for (const size of sizes) {
    data.push({ label: `plaintext-${size}`, value: meanVal(coreSuites, `plaintext-pipeline-${size}`) });
    data.push({ label: `encrypted-${size}`, value: meanVal(coreSuites, `encrypted-pipeline-${size}`) });
  }
  return svgChart({
    title: 'Plaintext vs Encrypted Change Propagation',
    yLabel: 'Pipeline × Size',
    data,
    height: 350,
  });
}

function chartConvergence(coreSuites) {
  const peers = [2, 4, 8, 16, 32];
  const data = peers.map((n) => ({
    label: `${n} peers`,
    value: meanVal(coreSuites, `convergence-${n}-peers`),
  }));
  return svgChart({
    title: 'Convergence Time by Peer Count',
    yLabel: 'Peer Count',
    data,
    height: 350,
  });
}

function chartIndexQueryScaling(indexSuites) {
  const counts = [100, 1000, 10000, 100000];
  const queries = [
    { key: 'exact-match', label: 'Exact Match' },
    { key: 'range-gte', label: 'Range (GTE)' },
    { key: 'compound-query', label: 'Compound (2 filters)' },
  ];

  const data = [];
  for (const count of counts) {
    for (const q of queries) {
      data.push({
        label: `${q.key}-${count}`,
        value: meanVal(indexSuites, `${q.key}-${count}`),
      });
    }
  }
  return svgChart({
    title: 'Index Query Latency by Document Count',
    yLabel: 'Query × Document Count',
    data,
    height: 400,
  });
}

function chartBloomFilter(indexSuites) {
  const sizes = [
    { label: '1K bits', key: '1k-bits' },
    { label: '8K bits', key: '8k-bits' },
    { label: '64K bits', key: '64k-bits' },
    { label: '256K bits', key: '256k-bits' },
    { label: '1M bits', key: '1m-bits' },
  ];

  const data = [];
  for (const s of sizes) {
    data.push({ label: `insert-${s.label}`, value: meanVal(indexSuites, `insert-1000-into-${s.key}`) });
    data.push({ label: `query-${s.label}`, value: meanVal(indexSuites, `query-positive-${s.key}`) });
    data.push({ label: `merge-${s.label}`, value: meanVal(indexSuites, `merge-${s.key}`) });
  }
  return svgChart({
    title: 'Bloom Filter Operations by Filter Size',
    yLabel: 'Operation × Filter Size',
    data,
    height: 400,
  });
}

function chartBlindIndex(indexSuites) {
  const fieldCounts = [1, 2, 4, 8, 16];
  const data = fieldCounts.map((n) => ({
    label: `${n} fields`,
    value: meanVal(indexSuites, `derive-and-tokenize-${n}-fields`),
  }));
  data.unshift({ label: 'batch-100', value: meanVal(indexSuites, 'batch-100-tokens') });
  return svgChart({
    title: 'Blind Index Operations by Field Count',
    yLabel: 'Operation',
    data,
    height: 300,
  });
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const coreSuites = readJSON('packages/core/dist-bench/__benchmarks__/results.json');
  const indexSuites = readJSON('packages/index/dist-bench/__benchmarks__/results.json');

  const charts = [
    { name: 'crdt-sync-latency', fn: () => chartCrdtSyncLatency(coreSuites) },
    { name: 'crypto-overhead', fn: () => chartCryptoOverhead(coreSuites) },
    { name: 'convergence', fn: () => chartConvergence(coreSuites) },
    { name: 'index-query-scaling', fn: () => chartIndexQueryScaling(indexSuites) },
    { name: 'bloom-filter', fn: () => chartBloomFilter(indexSuites) },
    { name: 'blind-index', fn: () => chartBlindIndex(indexSuites) },
  ];

  for (const chart of charts) {
    const svg = chart.fn();
    fs.writeFileSync(join(OUT_DIR, `${chart.name}.svg`), svg);
    console.log(`  ${chart.name}.svg`);
  }

  console.log(`\nCharts written to ${OUT_DIR}`);
}

main();