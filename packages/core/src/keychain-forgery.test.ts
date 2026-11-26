import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('a writer cannot add a key to another Yjs or Automerge replica through a Welcome or a load response', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/keychain-forgery.fixture.mjs`],
    { timeout: 60_000 },
  );
}, 70_000);
