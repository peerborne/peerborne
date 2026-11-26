import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  HeldACLChanges,
  MAX_HELD_ACL_BYTES,
  MAX_HELD_ACL_BYTES_PER_SIGNER,
  MAX_HELD_ACL_CHANGES,
  MAX_HELD_ACL_CHANGES_PER_SIGNER,
  type HeldACLChange,
} from './held-acl-changes.js';
import {
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';

const entry = (
  cid: string,
  signer: string,
  byteLength = 1,
  ready?: () => boolean,
): HeldACLChange<string> => ({
  cid,
  kind: crdtWriterChangeNode,
  changes: cid,
  signer,
  byteLength,
  ready,
});

describe('HeldACLChanges', () => {
  test('generated holds and releases keep every bound and lose no change silently', () => {
    const step = fc.record({
      release: fc.boolean(),
      signer: fc.integer({ min: 0, max: 5 }),
      bytes: fc.integer({ min: 0, max: MAX_HELD_ACL_BYTES_PER_SIGNER }),
      pick: fc.nat(),
    });
    fc.assert(
      fc.property(fc.array(step, { maxLength: 400 }), (steps) => {
        const held = new HeldACLChanges<string>();
        const present: string[] = [];
        steps.forEach(({ release, signer, bytes, pick }, index) => {
          if (release && present.length > 0) {
            const [cid] = present.splice(pick % present.length, 1);
            expect(held.release(cid!)?.cid).toBe(cid);
          } else {
            const cid = `c${index}`;
            present.push(cid);
            for (const evicted of held.hold(entry(cid, `s${signer}`, bytes))) {
              expect(present).toContain(evicted);
              present.splice(present.indexOf(evicted), 1);
            }
          }
          const usage = new Map<string, { count: number; bytes: number }>();
          let total = 0;
          for (const cid of present) {
            const kept = held.get(cid)!;
            const signerUsage = usage.get(kept.signer) ?? {
              count: 0,
              bytes: 0,
            };
            signerUsage.count++;
            signerUsage.bytes += kept.byteLength;
            usage.set(kept.signer, signerUsage);
            total += kept.byteLength;
          }
          expect(held.size).toBe(present.length);
          expect(held.size).toBeLessThanOrEqual(MAX_HELD_ACL_CHANGES);
          expect(total).toBeLessThanOrEqual(MAX_HELD_ACL_BYTES);
          for (const { count, bytes: signerBytes } of usage.values()) {
            expect(count).toBeLessThanOrEqual(MAX_HELD_ACL_CHANGES_PER_SIGNER);
            expect(signerBytes).toBeLessThanOrEqual(
              MAX_HELD_ACL_BYTES_PER_SIGNER,
            );
          }
        });
      }),
      { seed: 9436, numRuns: 50 },
    );
  });

  test('a signer past its bound gives up its own oldest change', () => {
    const held = new HeldACLChanges<string>();
    held.hold(entry('honest', 'h'));
    for (let index = 0; index < MAX_HELD_ACL_CHANGES_PER_SIGNER; index++) {
      expect(held.hold(entry(`m${index}`, 'm'))).toEqual([]);
    }

    expect(held.hold(entry('m-last', 'm'))).toEqual(['m0']);

    expect(held.has('honest')).toBe(true);
    expect(held.has('m0')).toBe(false);
    expect(held.has('m-last')).toBe(true);
    expect(held.size).toBe(MAX_HELD_ACL_CHANGES_PER_SIGNER + 1);
  });

  test('a signer past its byte bound gives up its oldest changes', () => {
    const held = new HeldACLChanges<string>();
    const half = MAX_HELD_ACL_BYTES_PER_SIGNER / 2;
    held.hold(entry('a', 'm', half));
    held.hold(entry('b', 'm', half));

    expect(held.hold(entry('c', 'm', 1))).toEqual(['a']);
    expect(
      held.hold(entry('huge', 'm', MAX_HELD_ACL_BYTES_PER_SIGNER + 1)),
    ).toEqual(['huge']);
    expect(held.hold(entry('nan', 'm', Number.NaN))).toEqual(['nan']);
    expect([held.has('b'), held.has('c'), held.has('huge')]).toEqual([
      true,
      true,
      false,
    ]);
  });

  test('past the document bound the signer holding the most gives up first', () => {
    const held = new HeldACLChanges<string>();
    const signers = MAX_HELD_ACL_CHANGES / MAX_HELD_ACL_CHANGES_PER_SIGNER;
    for (let signer = 0; signer < signers; signer++) {
      const count =
        signer === 0
          ? MAX_HELD_ACL_CHANGES_PER_SIGNER
          : MAX_HELD_ACL_CHANGES_PER_SIGNER - 1;
      for (let index = 0; index < count; index++) {
        held.hold(entry(`s${signer}-${index}`, `s${signer}`));
      }
    }
    for (let index = 0; index < signers; index++) {
      held.hold(entry(`late-${index}`, 'late'));
    }

    expect(held.size).toBe(MAX_HELD_ACL_CHANGES);
    expect(held.has('s0-0')).toBe(false);
    expect(held.has('s1-0')).toBe(true);

    const bytes = new HeldACLChanges<string>();
    const share = MAX_HELD_ACL_BYTES_PER_SIGNER;
    for (let signer = 0; signer < MAX_HELD_ACL_BYTES / share; signer++) {
      bytes.hold(entry(`b${signer}`, `b${signer}`, share));
    }
    expect(bytes.hold(entry('small', 'small', 1))).toEqual(['b0']);
  });

  test('re-holding a change refreshes its guard without counting it twice', () => {
    const held = new HeldACLChanges<string>();
    held.hold(entry('a', 'm', 1, () => false));
    expect(held.ready(crdtWriterChangeNode)).toEqual([]);

    held.hold(entry('a', 'm', 1, () => true));

    expect(held.size).toBe(1);
    expect(held.ready(crdtWriterChangeNode).map(({ cid }) => cid)).toEqual([
      'a',
    ]);
    expect(held.ready(crdtReaderChangeNode)).toEqual([]);
    held.release('a');
    expect(held.size).toBe(0);
    for (let index = 0; index < MAX_HELD_ACL_CHANGES_PER_SIGNER; index++) {
      expect(held.hold(entry(`n${index}`, 'm'))).toEqual([]);
    }
  });
});
