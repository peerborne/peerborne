import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

test('a retired Yjs or Loro document fails its collection, and Automerge rolls the change back', async () => {
  await promisify(execFile)(
    process.execPath,
    [
      '--test',
      fileURLToPath(new URL('./retired-document.fixture.mjs', import.meta.url)),
    ],
    { timeout: 60_000 },
  );
}, 70_000);
