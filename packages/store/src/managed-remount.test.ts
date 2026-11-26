import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const fixture = (name: string) =>
  promisify(execFile)(
    process.execPath,
    [
      '--test',
      '--test-timeout=100000',
      fileURLToPath(new URL(name, import.meta.url)),
    ],
    { timeout: 110_000 },
  );

test('a managed store keeps an undelivered offline edit across a remount of a real document', async () => {
  await fixture('./managed-remount.fixture.mjs');
}, 120_000);

test('with the default GossipSub options, a managed store keeps an edit that reached no member peer', async () => {
  await fixture('./offline-remount.fixture.mjs');
}, 120_000);

test('over a circuit relay, only evidence from a member clears a delivery failure', async () => {
  await fixture('./relay-delivery.fixture.mjs');
}, 120_000);
