import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { describe, expect, test } from '@jest/globals';

const execFileAsync = promisify(execFile);

describe('libp2p peer identity', () => {
  test('one default-config instance holds the persisted PeerId and the others get their own', async () => {
    const fixture = `${__dirname}/peer-identity.fixture.mjs`;
    await expect(
      execFileAsync(process.execPath, ['--import', 'tsx', '--test', fixture], {
        timeout: 60_000,
      }),
    ).resolves.toBeDefined();
  }, 70_000);
});
