import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { describe, expect, test } from '@jest/globals';

const execFileAsync = promisify(execFile);

describe('GossipSub IP colocation defaults', () => {
  test('keeps delivering to churned peers that share an IP with the native ESM browser and Node builders', async () => {
    const fixture = `${__dirname}/gossip-colocation-defaults.fixture.mjs`;
    await expect(
      execFileAsync(process.execPath, ['--import', 'tsx', '--test', fixture], {
        timeout: 60_000,
      }),
    ).resolves.toBeDefined();
  }, 70_000);
});
