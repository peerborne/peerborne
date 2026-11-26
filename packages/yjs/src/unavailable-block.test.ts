import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('a replica missing a block whose author is offline keeps working', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/unavailable-block.fixture.mjs`],
    { timeout: 60_000 },
  );
}, 70_000);
