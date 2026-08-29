import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  generatePeerborneHookSvg,
  normalizeNewlines,
} from './render-peerborne-hook.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = resolve(root, '.github/assets/peerborne-hook.svg');

test('the README visual is deterministic and current', () => {
  const first = generatePeerborneHookSvg();
  const second = generatePeerborneHookSvg();

  assert.equal(first, second);
  assert.equal(normalizeNewlines(readFileSync(outputPath, 'utf8')), first);
});

test('the README visual is a self-contained accessible SVG', () => {
  const svg = generatePeerborneHookSvg();

  assert.match(svg, /^<svg[^>]+viewBox="0 0 960 540"/);
  assert.match(svg, /<title id="title">/);
  assert.match(svg, /<desc id="description">/);
  assert.match(svg, /SIGNED EDITOR INVITATION/);
  assert.match(svg, /RECIPIENT-ENCRYPTED WELCOME/);
  assert.match(svg, /DISTINCT IDENTITIES/);
  assert.match(svg, /live bidirectional relay sync/);
  assert.match(svg, /DISTRIBUTED SEARCH · INCOMPLETE \/ NOT DEMONSTRATED/);
  assert.doesNotMatch(svg, /SAME IDENTITY|restored out of band/i);
  assert.match(svg, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(svg, /\.packet \{ opacity:0;/);
  assert.match(svg, /\.packet-return \{ opacity:0;/);
  assert.match(svg, /\.waiting \{ opacity:0;/);
  assert.doesNotMatch(svg, /<image\b/i);
  assert.doesNotMatch(svg, /<foreignObject\b/i);
  assert.doesNotMatch(svg, /<script\b/i);
  assert.doesNotMatch(svg, /(?:href|src)=["'](?:https?:|data:)/i);
  assert.ok(Buffer.byteLength(svg) <= 100 * 1024);
});

test('newline normalization handles Windows and legacy checkouts', () => {
  assert.equal(normalizeNewlines('one\r\ntwo\rthree\n'), 'one\ntwo\nthree\n');
});
