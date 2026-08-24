import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const checkerPath = fileURLToPath(
  new URL('./check-links.mjs', import.meta.url),
);
const fixtureDirectories = [];

after(() => {
  for (const directory of fixtureDirectories) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function createFixture({
  indexBody = '',
  llms = '[Home](https://peerborne.io/)',
  llmsFull = '[Home](https://peerborne.io/)',
  pages = {},
  repositoryDirectories = [],
  repositoryFiles = {},
} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'peerborne-site-links-'));
  const directory = join(root, 'dist');
  const repositoryDirectory = join(root, 'repository');
  fixtureDirectories.push(root);
  mkdirSync(directory);
  mkdirSync(repositoryDirectory);
  writeFileSync(
    join(directory, 'index.html'),
    '<!doctype html><link rel="canonical" href="https://peerborne.io/">' +
      indexBody,
  );

  for (const [relativePath, html] of Object.entries(pages)) {
    const path = join(directory, relativePath);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, html);
  }

  for (const relativePath of repositoryDirectories) {
    mkdirSync(join(repositoryDirectory, relativePath), { recursive: true });
  }
  for (const [relativePath, contents] of Object.entries(repositoryFiles)) {
    const path = join(repositoryDirectory, relativePath);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, contents);
  }

  if (llms !== null) writeFileSync(join(directory, 'llms.txt'), llms);
  if (llmsFull !== null) {
    writeFileSync(join(directory, 'llms-full.txt'), llmsFull);
  }
  return { directory, repositoryDirectory, root };
}

function check(fixture) {
  return spawnSync(
    process.execPath,
    [checkerPath, fixture.directory, fixture.repositoryDirectory],
    { encoding: 'utf8' },
  );
}

function outputFor(result) {
  return `${result.stdout}${result.stderr}`;
}

test('accepts valid site and repository links from llms.txt', () => {
  const fixture = createFixture({
    indexBody: '<a href="./guide/#topic">Guide</a>',
    llms: [
      '[Guide][guide]',
      '[guide]: https://peerborne.io/guide/#topic',
      '[Audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md)',
      '[Examples](https://github.com/Peerborne/peerborne/tree/main/examples)',
      '[Issue](https://github.com/Peerborne/peerborne/issues/1)',
      '[Node.js](https://nodejs.org/)',
    ].join('\n'),
    pages: {
      'guide/index.html': '<h2 id="topic">Topic</h2>',
    },
    repositoryDirectories: ['examples'],
    repositoryFiles: { 'docs/feature-audit.md': '# Feature audit' },
  });

  const result = check(fixture);
  assert.equal(result.status, 0, outputFor(result));
  assert.match(
    outputFor(result),
    /5 links in llms\.txt \(1 site, 2 repository, 2 external\)/,
  );
});

test('keeps validating links from generated HTML', () => {
  const result = check(
    createFixture({
      indexBody: '<a href="./guide/#missing">Guide</a>',
      pages: { 'guide/index.html': '<h2 id="topic">Topic</h2>' },
    }),
  );

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /index\.html:.*missing anchor "missing"/);
});

test('rejects a missing site target from llms.txt', () => {
  const result = check(
    createFixture({
      llms: '[Missing](https://peerborne.io/missing/)',
    }),
  );

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /llms\.txt:.*missing target/);
});

test('rejects a missing site anchor from llms.txt', () => {
  const result = check(
    createFixture({
      llms: '[Guide](https://peerborne.io/guide/#missing)',
      pages: { 'guide/index.html': '<h2 id="topic">Topic</h2>' },
    }),
  );

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /llms\.txt:.*missing anchor "missing"/);
});

test('treats a link to another origin as external', () => {
  const result = check(
    createFixture({
      llms: '[Outside](https://example.com/outside/)',
    }),
  );

  assert.equal(result.status, 0, outputFor(result));
});

test('rejects a malformed URL from llms.txt', () => {
  const result = check(createFixture({ llms: '[Bad](https://[invalid)' }));

  assert.equal(result.status, 1, outputFor(result));
  assert.match(
    outputFor(result),
    /llms\.txt: invalid href="https:\/\/\[invalid"/,
  );
});

test('rejects an inline Markdown link without a closing delimiter', () => {
  const result = check(
    createFixture({
      llms: [
        '[Home](https://peerborne.io/)',
        '[Guide](https://peerborne.io/guide/',
      ].join('\n'),
    }),
  );

  assert.equal(result.status, 1, outputFor(result));
  assert.match(
    outputFor(result),
    /llms\.txt:2: malformed inline Markdown link/,
  );
});

test('rejects an undefined Markdown link reference', () => {
  const result = check(
    createFixture({
      llms: [
        '[Home](https://peerborne.io/)',
        '[Guide][missing]',
        '[guide]: https://peerborne.io/guide/',
      ].join('\n'),
    }),
  );

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /undefined link reference "missing"/);
});

test('rejects a missing repository target from llms.txt', () => {
  const result = check(
    createFixture({
      llms: '[Missing](https://github.com/Peerborne/peerborne/blob/main/docs/not-here.md)',
    }),
  );

  assert.equal(result.status, 1, outputFor(result));
  assert.match(
    outputFor(result),
    /missing repository target "docs\/not-here\.md"/,
  );
});

test('rejects unsupported same-repository source routes', () => {
  const result = check(
    createFixture({
      llms: [
        '[Branch](https://github.com/Peerborne/peerborne/blob/dev/docs/file.md)',
        '[Route](https://github.com/Peerborne/peerborne/blbo/main/docs/file.md)',
        '[Short route](https://github.com/Peerborne/peerborne/blbo/main)',
        '[Other branch](https://github.com/Peerborne/peerborne/blbo/dev/docs/file.md)',
      ].join('\n'),
    }),
  );

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /unsupported repository branch "dev"/);
  assert.match(outputFor(result), /unsupported repository route "blbo\/main"/);
  assert.match(outputFor(result), /unsupported repository route "blbo\/dev"/);
});

test('rejects repository paths containing encoded backslashes', () => {
  const result = check(
    createFixture({
      llms: '[Escape](https://github.com/Peerborne/peerborne/blob/main/docs/..%5Coutside.md)',
    }),
  );

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /escapes the repository checkout/);
});

test('rejects repository targets that symlink outside the checkout', () => {
  const fixture = createFixture({
    llms: '[Escape](https://github.com/Peerborne/peerborne/blob/main/docs/link.md)',
    repositoryDirectories: ['docs'],
  });
  writeFileSync(join(fixture.root, 'outside.md'), 'outside');
  symlinkSync(
    join('..', '..', 'outside.md'),
    join(fixture.repositoryDirectory, 'docs/link.md'),
  );

  const result = check(fixture);
  assert.equal(result.status, 1, outputFor(result));
  assert.match(
    outputFor(result),
    /escapes the checkout through a symbolic link/,
  );
});

test('accepts repository targets that symlink within the checkout', () => {
  const fixture = createFixture({
    llms: '[Link](https://github.com/Peerborne/peerborne/blob/main/docs/link.md)',
    repositoryFiles: { 'docs/target.md': 'target' },
  });
  symlinkSync('target.md', join(fixture.repositoryDirectory, 'docs/link.md'));

  const result = check(fixture);
  assert.equal(result.status, 0, outputFor(result));
});

test('rejects an empty llms.txt', () => {
  const result = check(createFixture({ llms: '' }));

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /llms\.txt: contains no Markdown links/);
});

test('requires llms.txt in the built site', () => {
  const result = check(createFixture({ llms: null }));

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /llms\.txt does not exist/);
});

test('resumes llms-full.txt validation after fenced examples', () => {
  const result = check(
    createFixture({
      llmsFull: [
        '[Guide](https://peerborne.io/guide/#topic)',
        '```md',
        '[Example only](https://peerborne.io/ignored/)',
        '```',
        '[Missing](https://peerborne.io/missing/)',
      ].join('\n'),
      pages: { 'guide/index.html': '<h2 id="topic">Topic</h2>' },
    }),
  );

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /llms-full\.txt:.*missing target/);
});

test('rejects an unclosed fence in llms-full.txt', () => {
  const result = check(
    createFixture({
      llmsFull: [
        '[Home](https://peerborne.io/)',
        '```md',
        '[Masked](https://peerborne.io/missing/)',
      ].join('\n'),
    }),
  );

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /llms-full\.txt:2: unclosed ``` fence/);
});

test('requires llms-full.txt in the built site', () => {
  const result = check(createFixture({ llmsFull: null }));

  assert.equal(result.status, 1, outputFor(result));
  assert.match(outputFor(result), /llms-full\.txt does not exist/);
});
