import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('Yjs ACL changes wait outside the live ACL until their history arrives', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/acl-dependencies.fixture.mjs`],
    { timeout: 100_000 },
  );
}, 110_000);
