import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('re-sharing, catch-up and opening do not wait on blocks only an absent peer stored', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/deferred-cross-links.fixture.mjs`],
    { timeout: 240_000 },
  );
}, 250_000);
