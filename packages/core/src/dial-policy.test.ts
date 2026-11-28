import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { describe, expect, test } from '@jest/globals';

const execFileAsync = promisify(execFile);

describe('dial policy', () => {
  test('refuses local-network dials by default with native libp2p', async () => {
    const fixture = `${__dirname}/dial-policy.fixture.mjs`;
    await expect(
      execFileAsync(process.execPath, ['--import', 'tsx', '--test', fixture], {
        timeout: 60_000,
      }),
    ).resolves.toBeDefined();
  }, 70_000);
});
