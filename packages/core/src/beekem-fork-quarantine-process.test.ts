import { execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { expect, test } from '@jest/globals';

const run = promisify(execFile);
const fixture = join(__dirname, 'beekem-fork-quarantine-process.fixture.mjs');

test.each([
  ['confirm', 'quarantined'],
  ['interrupt', 'active'],
])(
  'blocks a fresh process after a %s quarantine write',
  async (step, expectedPhase) => {
    const directory = await mkdtemp(join(tmpdir(), 'peerborne-fork-process-'));
    const start = (mode: string, phase = '') =>
      run(process.execPath, ['--import', 'tsx', fixture, directory, mode, phase], {
        timeout: 8000,
      });
    try {
      if (step === 'interrupt') {
        await expect(start(step)).rejects.toMatchObject({ code: 41 });
      } else {
        await start(step);
      }
      await start('restart', expectedPhase);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
  20000,
);
