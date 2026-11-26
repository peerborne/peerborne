import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { describe, expect, test } from '@jest/globals';

const execFileAsync = promisify(execFile);

describe('inbound connection defaults', () => {
  test('accepts a burst of relayed peers with the native ESM browser and Node builders', async () => {
    const fixture = `${__dirname}/inbound-connection-defaults.fixture.mjs`;
    await expect(
      execFileAsync(process.execPath, ['--import', 'tsx', '--test', fixture], {
        timeout: 60_000,
      }),
    ).resolves.toBeDefined();
  }, 70_000);
});
