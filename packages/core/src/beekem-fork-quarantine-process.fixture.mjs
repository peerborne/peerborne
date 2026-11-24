import assert from 'node:assert/strict';
import { open, readFile, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { BeeKEMForkQuarantine } from './beekem-fork-quarantine.ts';

const [directory, step, expectedPhase] = process.argv.slice(2);
assert.ok(directory);
assert.ok(['confirm', 'interrupt', 'restart'].includes(step));
const record = join(directory, 'anchor.json');
const staged = join(directory, 'anchor.next');
const lockPath = join(directory, 'anchor.lock');

const store = {
  async load(scope) {
    try {
      const value = JSON.parse(await readFile(record, 'utf8'));
      assert.deepEqual(value.scope, scope);
      return value.anchor;
    } catch (error) {
      if (error.code === 'ENOENT') return undefined;
      throw error;
    }
  },
  async compareAndSwap(scope, expected, next) {
    if (step === 'interrupt' && next.phase === 'quarantined') process.exit(41);
    const lock = await open(lockPath, 'wx');
    try {
      if (!isDeepStrictEqual(await this.load(scope), expected)) return false;
      const file = await open(staged, 'w');
      try {
        await file.writeFile(JSON.stringify({ scope, anchor: next }));
        await file.sync();
      } finally {
        await file.close();
      }
      await rename(staged, record);
      return true;
    } finally {
      await lock.close();
      await unlink(lockPath);
    }
  },
};

const guard = new BeeKEMForkQuarantine(store, '/process-restart', () => 'owner');
if (step === 'restart') {
  const saved = await readFile(record, 'utf8');
  assert.equal(JSON.parse(saved).anchor.phase, expectedPhase);
  await assert.rejects(guard.acquire());
  assert.equal(await readFile(record, 'utf8'), saved);
} else {
  assert.equal(await guard.provision(), true);
  await guard.acquire();
  assert.equal(guard.acceptsWork, true);
  await guard.quarantine(2);
  assert.equal(guard.acceptsWork, false);
  assert.equal(JSON.parse(await readFile(record, 'utf8')).anchor.generation, 2);
}
