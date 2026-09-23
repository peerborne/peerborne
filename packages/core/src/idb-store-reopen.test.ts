import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { describe, expect, test } from '@jest/globals';

const execFileAsync = promisify(execFile);

describe('IndexedDB store persistence', () => {
  test('current stores retain blocks and pins across reopen', async () => {
    const fixture = `${__dirname}/idb-store-reopen.fixture.mjs`;
    await expect(
      execFileAsync(process.execPath, ['--test', fixture]),
    ).resolves.toBeDefined();
  });
});
