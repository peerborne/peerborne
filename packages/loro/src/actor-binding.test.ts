import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

test('Loro peer IDs stay bound to the signers that registered them', async () => {
  await promisify(execFile)(
    process.execPath,
    [
      '--test',
      fileURLToPath(new URL('./actor-binding.fixture.mjs', import.meta.url)),
    ],
    { timeout: 60_000 },
  );
}, 70_000);
