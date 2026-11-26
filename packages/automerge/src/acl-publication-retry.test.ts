import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('a writer removal after a rejected publication and retry converges through PeerborneDocument', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/acl-publication-retry.fixture.mjs`],
    { timeout: 60_000 },
  );
}, 70_000);
