import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('direct onboarding, re-sharing after revocation, and founder crash recovery hold across real nodes', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/invitation-reshare.fixture.mjs`],
    { timeout: 90_000 },
  );
}, 100_000);
