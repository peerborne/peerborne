import assert from 'node:assert/strict';
import { test } from 'node:test';
import { transformDocsFigures } from './rehype-docs-figures.mjs';

function paragraph(properties, siblings = []) {
  return {
    type: 'element',
    tagName: 'p',
    properties: {},
    children: [
      { type: 'text', value: '\n' },
      { type: 'element', tagName: 'img', properties, children: [] },
      ...siblings,
    ],
  };
}

test('wraps a captioned standalone SVG in a semantic figure', () => {
  const tree = {
    type: 'root',
    children: [
      paragraph({
        src: '../../../assets/charts/latency.svg',
        alt: 'Latency by payload size',
        title: 'Local latency snapshot.',
      }),
    ],
  };

  transformDocsFigures(tree);

  const figure = tree.children[0];
  assert.equal(figure.tagName, 'div');
  assert.deepEqual(figure.properties.className, [
    'docs-figure',
    'docs-figure--chart',
  ]);
  const semanticFigure = figure.children[0];
  assert.equal(semanticFigure.tagName, 'figure');
  assert.equal(semanticFigure.children[0].tagName, 'div');
  assert.equal(
    semanticFigure.children[0].children[0].properties.title,
    undefined,
  );
  assert.equal(
    semanticFigure.children[0].children[0].properties.alt,
    'Latency by payload size',
  );
  assert.equal(semanticFigure.children.at(-1).tagName, 'figcaption');
  assert.equal(
    semanticFigure.children.at(-1).children[0].value,
    'Local latency snapshot.',
  );
  const details = figure.children[1];
  assert.equal(details.tagName, 'details');
  assert.equal(
    details.children[0].children[0].value,
    'View chart at full size',
  );
  assert.equal(
    details.children[0].properties['aria-label'],
    'View chart at full size: Local latency snapshot.',
  );
  assert.equal(
    details.properties['aria-describedby'],
    semanticFigure.children.at(-1).properties.id,
  );
  const fullSize = details.children[1];
  assert.equal(fullSize.properties.role, 'region');
  assert.equal(fullSize.properties.tabIndex, 0);
  assert.equal(
    fullSize.properties['aria-label'],
    'Full-size chart: Local latency snapshot.',
  );
  assert.equal(fullSize.children[0].properties.alt, '');
});

test('leaves non-SVG and non-standalone images unchanged', () => {
  const bitmap = paragraph({
    src: '/social-card.png',
    alt: 'Social card',
    title: 'Social card.',
  });
  const inline = paragraph(
    {
      src: '../../../assets/diagrams/path.svg',
      alt: 'Path',
      title: 'Path.',
    },
    [{ type: 'text', value: ' trailing prose' }],
  );
  const missingCaption = paragraph({
    src: '../../../assets/diagrams/path.svg',
    alt: 'Path',
  });
  const tree = { type: 'root', children: [bitmap, inline, missingCaption] };

  transformDocsFigures(tree);

  assert.equal(tree.children[0], bitmap);
  assert.equal(tree.children[1], inline);
  assert.equal(tree.children[2], missingCaption);
});

test('assigns unique caption IDs to multiple figures', () => {
  const tree = {
    type: 'root',
    children: [
      paragraph({
        src: '../../../assets/charts/first.svg',
        alt: 'First chart',
        title: 'First chart caption.',
      }),
      paragraph({
        src: '../../../assets/charts/second.svg',
        alt: 'Second chart',
        title: 'Second chart caption.',
      }),
    ],
  };

  transformDocsFigures(tree);

  assert.equal(
    tree.children[0].children[0].children.at(-1).properties.id,
    'docs-figure-caption-1',
  );
  assert.equal(
    tree.children[1].children[0].children.at(-1).properties.id,
    'docs-figure-caption-2',
  );
});
