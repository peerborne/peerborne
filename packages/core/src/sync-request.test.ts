import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('checks native sync-request framing, authentication, replay bounds and writer response confinement', async () => {
  await promisify(execFile)(
    process.execPath,
    [
      '--import',
      'tsx',
      '--test',
      `${__dirname}/sync-request-native.fixture.mjs`,
    ],
    { timeout: 60_000 },
  );
}, 70_000);
