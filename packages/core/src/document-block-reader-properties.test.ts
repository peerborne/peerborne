import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { test } from '@jest/globals';

test('checks the native document block read boundaries', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--import', 'tsx', '--test', `${__dirname}/document-block-reader.fixture.mjs`],
    { timeout: 60_000 },
  );
}, 70_000);
