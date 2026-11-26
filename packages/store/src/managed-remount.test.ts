import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const fixture = (name: string) =>
  promisify(execFile)(
    process.execPath,
    ['--test', fileURLToPath(new URL(name, import.meta.url))],
    { timeout: 60_000 },
  );

test('a managed store keeps an undelivered offline edit across a remount of a real document', async () => {
  await fixture('./managed-remount.fixture.mjs');
}, 70_000);

test('with the default GossipSub options, a managed store keeps an edit made with no peers until one receives a later frame', async () => {
  await fixture('./offline-remount.fixture.mjs');
}, 70_000);
