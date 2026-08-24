import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  cleanMdx,
  mapOutsideFences,
  rewriteMarkdownLinks,
} from './generate-llms-full.mjs';

const repository = fileURLToPath(new URL('../..', import.meta.url));

test('rejects an unclosed fenced block', () => {
  assert.throws(
    () =>
      mapOutsideFences(
        ['Before', '```ts', 'const value = true;'].join('\n'),
        (markdown) => markdown,
        'fixture.mdx',
      ),
    /fixture\.mdx:2: unclosed ``` fence/,
  );
});

test('cleans MDX wrappers while preserving fenced content', () => {
  const input = [
    'import {',
    '  Card,',
    '  CardGrid,',
    '  LinkButton,',
    "} from '@astrojs/starlight/components';",
    '',
    '<CardGrid>',
    '  <Card title="Example">',
    '    Before.',
    '',
    '    ```ts',
    "    import value from './value';",
    "    const spacer = \"{' '}\";",
    '    [Relative example](../inside-code/)',
    '    ```',
    '',
    '    After.',
    '  </Card>',
    '</CardGrid>',
    '',
    '<LinkButton',
    '  href="../guide/"',
    '>',
    '  Guide',
    "</LinkButton>{' '}",
  ].join('\n');

  const output = cleanMdx(input, 'fixture.mdx');
  const prose = output.replace(/```[\s\S]*?```/g, '');

  assert.doesNotMatch(prose, /^import \{/m);
  assert.doesNotMatch(prose, /<\/?(?:Card|CardGrid|LinkButton)\b/);
  assert.doesNotMatch(prose, /\{\s*(['"])\s+\1\s*\}/);
  assert.match(output, /\*\*Example\*\*\n\nBefore\./);
  assert.match(
    output,
    /```ts\nimport value from '\.\/value';\nconst spacer = "\{' '\}";\n\[Relative example\]\(\.\.\/inside-code\/\)\n```/,
  );
  assert.match(output, /After\./);
  assert.match(output, /- \[Guide\]\(\.\.\/guide\/\)/);
});

test('names the source containing an unsupported MDX component', () => {
  assert.throws(
    () => cleanMdx('<Unsupported />', 'docs/example.mdx'),
    /docs\/example\.mdx: unsupported MDX component Unsupported/,
  );
  assert.throws(
    () => cleanMdx('<Unsupported>content</Unsupported>', 'docs/example.mdx'),
    /docs\/example\.mdx: unsupported MDX component Unsupported/,
  );
});

test('rewrites site links without changing fenced examples', () => {
  const source = resolve(
    repository,
    'site/src/content/docs/concepts/architecture.md',
  );
  const output = rewriteMarkdownLinks(
    [
      '[Limitations](../limitations/)',
      '[Audit](../../../../../docs/feature-audit.md)',
      '```md',
      '[Example](../kept-relative/)',
      '```',
    ].join('\n'),
    source,
  );

  assert.match(
    output,
    /\[Limitations\]\(https:\/\/peerborne\.io\/concepts\/limitations\/\)/,
  );
  assert.match(
    output,
    /\[Audit\]\(https:\/\/github\.com\/Peerborne\/peerborne\/blob\/main\/docs\/feature-audit\.md\)/,
  );
  assert.match(output, /\[Example\]\(\.\.\/kept-relative\/\)/);
});

test('rewrites repository file, directory, and fragment links', () => {
  const source = resolve(repository, 'docs/feature-audit.md');
  const output = rewriteMarkdownLinks(
    [
      '[README](../README.md)',
      '[Examples](../examples/)',
      '[Section](#evidence)',
    ].join('\n'),
    source,
  );

  assert.match(
    output,
    /\[README\]\(https:\/\/github\.com\/Peerborne\/peerborne\/blob\/main\/README\.md\)/,
  );
  assert.match(
    output,
    /\[Examples\]\(https:\/\/github\.com\/Peerborne\/peerborne\/tree\/main\/examples\)/,
  );
  assert.match(
    output,
    /\[Section\]\(https:\/\/github\.com\/Peerborne\/peerborne\/blob\/main\/docs\/feature-audit\.md#evidence\)/,
  );
});

test('names the source and href for a missing repository link', () => {
  const source = resolve(repository, 'docs/feature-audit.md');

  assert.throws(
    () => rewriteMarkdownLinks('[Missing](../not-here.md)', source),
    /docs\/feature-audit\.md has an invalid repository link \.\.\/not-here\.md:.*not-here\.md/,
  );
});

test('names the source and href for malformed repository encoding', () => {
  const source = resolve(repository, 'docs/feature-audit.md');

  assert.throws(
    () => rewriteMarkdownLinks('[Bad](../bad%ZZ.md)', source),
    /docs\/feature-audit\.md has an invalid repository link \.\.\/bad%ZZ\.md: URI malformed/,
  );
});

test('names the source and href for malformed documentation encoding', () => {
  const source = resolve(
    repository,
    'site/src/content/docs/concepts/architecture.md',
  );

  assert.throws(
    () => rewriteMarkdownLinks('[Bad](../bad%ZZ.md)', source),
    /site\/src\/content\/docs\/concepts\/architecture\.md has an invalid link \.\.\/bad%ZZ\.md: URI malformed/,
  );
});
