import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('Automerge actors stay bound to the signers that registered them', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/actor-binding.fixture.mjs`],
    { timeout: 60_000 },
  );
}, 70_000);
