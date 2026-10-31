import assert from 'node:assert/strict';
import test from 'node:test';
import { figurePalette, pixelFigure } from './figure-theme.mjs';
import { generateDiagrams } from './generate-doc-diagrams.mjs';

const colors = new Set(Object.values(figurePalette));

test('every diagram uses pixel headings, the site palette, and square unblurred shapes', () => {
  for (const [name, svg] of generateDiagrams()) {
    if (name !== 'runtime.svg') assert.match(svg, /class="pixel-heading"/, name);
    assert.match(svg, /Liberation Mono/, name);
    assert.doesNotMatch(svg, /<(?:circle|linearGradient)\b|r[xy]="[1-9]|stdDeviation="[1-9]|stroke-line(?:cap|join)="round"/, name);
    for (const color of svg.match(/#[\da-f]{6}\b/gi) ?? []) {
      assert.ok(colors.has(color.toLowerCase()), `${name}: ${color} is in the site palette`);
    }
  }
});

test('label fitting respects translated panels and keeps anchor placement', () => {
  const svg = pixelFigure('<svg width="500" height="200"><g transform="translate(100 50)"><rect width="150" height="100" fill="#0f172a"/><text x="20" y="40" font-size="20">This label is deliberately too wide</text><text x="75" y="80" font-size="20" text-anchor="middle">Centered long label</text></g></svg>');
  assert.match(svg, /x="0" y="0" font-size="20" transform="translate\(20 40\) scale\(0\.\d+ 1\)"/);
  assert.match(svg, /text-anchor="middle" transform="translate\(75 80\) scale\(0\.\d+ 1\)"/);
  assert.doesNotMatch(svg, /NaN|textLength/);
});

test('a circle without explicit center coordinates becomes a centered square', () => {
  const svg = pixelFigure('<svg width="100" height="100"><circle r="25" fill="#818cf8"/></svg>');
  assert.match(svg, /<rect x="-25" y="-25" width="50" height="50"/);
});

test('labels use the visible panel instead of covered icons or chart markers', () => {
  const svg = pixelFigure(`<svg width="500" height="200">
    <rect width="500" height="200" fill="#0f172a"/>
    <circle cx="250" cy="70" r="12"/>
    <rect x="50" y="50" width="400" height="40"/>
    <text x="250" y="75" font-size="14" text-anchor="middle">Encrypted initial document load</text>
    <circle cx="250" cy="125" r="6"/>
    <text x="250" y="125" font-size="14" text-anchor="middle">1.1</text>
  </svg>`);
  assert.doesNotMatch(svg, /scale\(/);
});

test('new colors require an explicit palette decision', () => {
  assert.throws(() => pixelFigure('<svg width="100"><rect fill="#123456"/></svg>'), /palette mapping for #123456/);
});
