import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  diagramDefinitions,
  diagramOutputPath,
  generateDiagrams,
} from './generate-doc-diagrams.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

test('all documentation diagrams are deterministic and current', () => {
  const first = generateDiagrams();
  const second = generateDiagrams();

  assert.equal(first.size, diagramDefinitions().length);
  assert.deepEqual([...first.keys()], [
    'package-dependencies.svg',
    'networking-stack.svg',
    'encryption-identity.svg',
    'document-change-lifecycle.svg',
    'shadow-sync-graph.svg',
    'stored-change-payload.svg',
    'local-index-pipeline.svg',
    'distributed-index-flow.svg',
    'relay-data-flow.svg',
    'single-relay-topology.svg',
    'multi-relay-topology.svg',
    'history-compaction.svg',
    'sync-envelope-lifecycle.svg',
    'browser-relay-path.svg',
    'change-pipeline.svg',
    'durability-recovery.svg',
    'initial-load.svg',
    'key-roles.svg',
    'offline-boundary.svg',
    'search-architecture.svg',
    'trust-boundary.svg',
    'runtime.svg',
  ]);
  assert.deepEqual(first, second);
  for (const [filename, svg] of first) {
    const output = readFileSync(
      diagramOutputPath(filename),
      'utf8',
    );
    assert.equal(output, svg, filename);
  }
});

test('diagrams are accessible, legible, self-contained SVG', () => {
  for (const [filename, svg] of generateDiagrams()) {
    assert.match(
      svg,
      /^<svg[^>]+width="\d+" height="\d+" viewBox="0 0 \d+ \d+" role="img" aria-labelledby="[^"]+">/,
      filename,
    );
    assert.match(svg, /<title id="[^"]+">/, filename);
    assert.match(svg, /<desc id="[^"]+">/, filename);
    assert.doesNotMatch(svg, /(?:NaN|Infinity|\[object Object\])/, filename);
    assert.doesNotMatch(svg, /<(?:image|foreignObject|script)\b/i, filename);
    assert.doesNotMatch(svg, /(?:href|src)=["'](?:https?:|data:)/i, filename);

    const sizes = [...svg.matchAll(/font-size(?:="|:\s*)([\d.]+)/g)].map((match) =>
      Number(match[1]),
    );
    assert.ok(sizes.length > 0, `${filename} has declared text sizes`);
    assert.ok(
      sizes.every((size) => size >= 13),
      `${filename} keeps declared text at 13px or larger`,
    );
  }
});

test('every served documentation diagram uses the shared generator', () => {
  const files = readdirSync(resolve(root, 'site/src/assets/diagrams'))
    .filter((name) => name.endsWith('.svg'))
    .sort();
  const generated = [...generateDiagrams().keys()]
    .filter((name) => name !== 'runtime.svg')
    .sort();
  assert.deepEqual(generated, files);
});
