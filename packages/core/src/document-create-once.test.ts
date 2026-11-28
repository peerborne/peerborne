import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('a node creates a document path once, and a fresh instance must open it', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/document-create-once.fixture.mjs`],
    { timeout: 60_000 },
  );
}, 70_000);
