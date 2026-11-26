import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('a change whose frame reaches no peer is kept and reported until a later frame reaches one', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/undelivered-publication.fixture.mjs`],
    { timeout: 60_000 },
  );
}, 70_000);
