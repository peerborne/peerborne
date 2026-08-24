import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { describe, expect, test } from '@jest/globals';

const execFileAsync = promisify(execFile);

describe('IndexedDB store migration', () => {
  test('current stores read and extend databases from the previous majors', async () => {
    const fixture = `${__dirname}/idb-store-migration.fixture.mjs`;
    await expect(
      execFileAsync(process.execPath, ['--test', fixture]),
    ).resolves.toBeDefined();
  });
});
