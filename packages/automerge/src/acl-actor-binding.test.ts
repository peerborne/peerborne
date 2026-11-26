import { test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('Automerge ACL actors stay bound to the signers that registered them', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--test', `${__dirname}/acl-actor-binding.fixture.mjs`],
    { timeout: 100_000 },
  );
}, 110_000);
