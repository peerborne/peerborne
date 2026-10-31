import { describe, expect, test } from '@jest/globals';
import { LoroProvider } from './index.js';

describe('experimental Loro provider', () => {
  test('merges concurrent offline changes after snapshot onboarding', () => {
    const provider = new LoroProvider();
    const alice = provider.newDocument();
    provider.localChange(alice, 'initial', (doc) => {
      doc.getText('body').insert(0, 'Hello');
    });
    const bob = provider.newDocument();
    provider.applySnapshot(bob, provider.getSnapshot(alice));
    const [, a] = provider.localChange(alice, 'alice', (doc) => {
      doc.getText('body').insert(5, ' Alice');
    });
    const [, b] = provider.localChange(bob, 'bob', (doc) => {
      doc.getText('body').insert(0, 'Bob ');
    });
    provider.remoteChange(alice, b);
    provider.remoteChange(bob, a);
    expect(alice.toJSON()).toEqual(bob.toJSON());
    expect(alice.getText('body').toString()).toContain('Alice');
    expect(alice.getText('body').toString()).toContain('Bob');
    const restored = provider.newDocument();
    provider.applySnapshot(restored, provider.getHistory(alice));
    expect(restored.toJSON()).toEqual(alice.toJSON());
  });

  test('buffers out-of-order dependencies and tolerates replayed updates', () => {
    const provider = new LoroProvider();
    const source = provider.newDocument();
    const [, first] = provider.localChange(source, 'first', (doc) => {
      doc.getText('body').insert(0, 'one');
    });
    const [, second] = provider.localChange(source, 'second', (doc) => {
      doc.getText('body').insert(3, 'two');
    });
    const target = provider.newDocument();
    provider.remoteChange(target, second);
    provider.remoteChange(target, first);
    provider.remoteChange(target, second);
    expect(target.toJSON()).toEqual(source.toJSON());
  });

  test('rejects truncated and corrupt payloads without changing accepted state', () => {
    const provider = new LoroProvider();
    const source = provider.newDocument();
    const [, update] = provider.localChange(source, 'write', (doc) => {
      doc.getMap('data').set('title', 'Private');
    });
    const target = provider.newDocument();
    const before = target.toJSON();
    expect(() => provider.remoteChange(target, update.slice(0, 5))).toThrow();
    const corrupt = new Uint8Array(update);
    corrupt[corrupt.length - 1] ^= 255;
    expect(() => provider.remoteChange(target, corrupt)).toThrow();
    expect(target.toJSON()).toEqual(before);
  });

  test('emits incremental updates and retains state across duplicate snapshots', () => {
    const provider = new LoroProvider();
    const source = provider.newDocument();
    provider.localChange(source, 'large', (doc) => {
      doc.getText('body').insert(0, 'content'.repeat(1000));
    });
    const snapshot = provider.getSnapshot(source);
    const [, delta] = provider.localChange(source, 'small', (doc) => {
      doc.getMap('data').set('done', true);
    });
    expect(delta.byteLength).toBeLessThan(
      provider.getSnapshot(source).byteLength,
    );
    const target = provider.newDocument();
    provider.applySnapshot(target, snapshot);
    provider.remoteChange(target, delta);
    provider.applySnapshot(target, snapshot);
    expect(target.toJSON()).toEqual(source.toJSON());
  });
});
