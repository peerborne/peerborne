function meaningfulChildren(node) {
  return node.children.filter(
    (child) => child.type !== 'text' || child.value.trim() !== '',
  );
}

function svgFigure(node, figureIndex) {
  if (node.type !== 'element' || node.tagName !== 'p') return undefined;

  const children = meaningfulChildren(node);
  if (children.length !== 1) return undefined;

  const image = children[0];
  if (image.type !== 'element' || image.tagName !== 'img') return undefined;

  const source = image.properties?.src;
  const caption = image.properties?.title;
  if (
    typeof source !== 'string' ||
    !source.toLowerCase().endsWith('.svg') ||
    typeof caption !== 'string' ||
    caption.trim() === ''
  ) {
    return undefined;
  }

  delete image.properties.title;
  const kind = source.includes('/charts/') ? 'chart' : 'diagram';
  const captionId = `docs-figure-caption-${figureIndex}`;
  const viewportId = `docs-figure-viewport-${figureIndex}`;

  return {
    type: 'element',
    tagName: 'div',
    properties: {
      className: ['docs-figure', `docs-figure--${kind}`],
    },
    children: [
      {
        type: 'element',
        tagName: 'figure',
        properties: { className: ['docs-figure__body'] },
        children: [
          {
            type: 'element',
            tagName: 'div',
            properties: {
              'aria-labelledby': captionId,
              className: ['docs-figure__viewport'],
              id: viewportId,
              role: 'region',
              tabIndex: 0,
            },
            children: [image],
          },
          {
            type: 'element',
            tagName: 'figcaption',
            properties: {
              className: ['docs-figure__caption'],
              id: captionId,
            },
            children: [{ type: 'text', value: caption.trim() }],
          },
        ],
      },
      {
        type: 'element',
        tagName: 'details',
        properties: {
          'aria-describedby': captionId,
          className: ['docs-figure__details'],
        },
        children: [
          {
            type: 'element',
            tagName: 'summary',
            properties: {
              'aria-controls': viewportId,
              'aria-describedby': captionId,
            },
            children: [
              {
                type: 'element',
                tagName: 'span',
                properties: { className: ['docs-figure__expand-label'] },
                children: [
                  { type: 'text', value: `View ${kind} at full size` },
                ],
              },
              {
                type: 'element',
                tagName: 'span',
                properties: { className: ['docs-figure__fit-label'] },
                children: [{ type: 'text', value: `Fit ${kind} to page` }],
              },
            ],
          },
        ],
      },
    ],
    position: node.position,
  };
}

function visitDocsFigures(tree, state) {
  if (!tree || !Array.isArray(tree.children)) return;

  for (let index = 0; index < tree.children.length; index += 1) {
    const child = tree.children[index];
    const figure = svgFigure(child, state.nextFigureIndex);
    if (figure) {
      tree.children[index] = figure;
      state.nextFigureIndex += 1;
      continue;
    }
    visitDocsFigures(child, state);
  }
}

export function transformDocsFigures(tree) {
  visitDocsFigures(tree, { nextFigureIndex: 1 });
}

export default function rehypeDocsFigures() {
  return transformDocsFigures;
}
