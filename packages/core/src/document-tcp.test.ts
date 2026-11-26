import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { describe, expect, test } from '@jest/globals';

const execFileAsync = promisify(execFile);

describe('documents on real libp2p TCP nodes', () => {
  test('close() during open() or create() and garbage collection during continuous edits', async () => {
    const fixture = `${__dirname}/document-tcp.fixture.mjs`;
    await expect(
      execFileAsync(process.execPath, ['--expose-gc', '--test', fixture], {
        timeout: 60_000,
      }),
    ).resolves.toBeDefined();
  }, 70_000);
});
