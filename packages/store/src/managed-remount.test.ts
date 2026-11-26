import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

test('a managed store keeps an undelivered offline edit across a remount of a real document', async () => {
  await promisify(execFile)(
    process.execPath,
    [
      '--test',
      fileURLToPath(new URL('./managed-remount.fixture.mjs', import.meta.url)),
    ],
    { timeout: 60_000 },
  );
}, 70_000);
