import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('replicas buffer, checkpoint and recover changes with missing Automerge dependencies', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/missing-dependencies.fixture.mjs`],
    { timeout: 60_000 },
  );
}, 70_000);
