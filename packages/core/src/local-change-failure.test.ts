import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('after a local change fails before publication, Automerge, Yjs and Loro writers converge with a replica', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/local-change-failure.fixture.mjs`],
    { timeout: 60_000 },
  );
}, 70_000);
