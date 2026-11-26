import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

test('PeerborneDocument replicas reject crafted Loro payloads and stay in sync', async () => {
  await promisify(execFile)(
    process.execPath,
    [
      '--test',
      fileURLToPath(
        new URL('./peerborne-validation.fixture.mjs', import.meta.url),
      ),
    ],
    { timeout: 60_000 },
  );
}, 70_000);
