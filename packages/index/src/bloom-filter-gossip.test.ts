import { afterEach, beforeEach, describe, expect, test, jest as jestFn } from '@jest/globals';
import { BloomFilterGossip } from './bloom-filter-gossip.js';
import { bloomFilterUpdateV1 } from '@peerborne/core';

type MockFn = ReturnType<typeof jestFn.fn>;

describe('BloomFilterGossip', () => {
  let gossip: BloomFilterGossip;
  let publishFn: MockFn;
  let subscribeFn: MockFn;
  let unsubscribeFn: MockFn;

  beforeEach(() => {
    gossip = new BloomFilterGossip({
      filterSizeInBits: 1024,
      numHashFunctions: 3,
      republishIntervalMs: 60000,
    });
    publishFn = jestFn.fn(() => Promise.resolve());
    subscribeFn = jestFn.fn();
    unsubscribeFn = jestFn.fn();
    gossip.setPubSub(
      publishFn as unknown as (topic: string, data: Uint8Array) => Promise<void>,
      subscribeFn as unknown as (topic: string, handler: (peerId: string, data: Uint8Array) => void) => void,
      unsubscribeFn as unknown as (topic: string) => void,
    );
  });

  afterEach(() => {
    gossip.stop();
  });

  describe('addTerm and local filter', () => {
    test('should add terms to local filter', () => {
      gossip.addTerm('hello');
      gossip.addTerm('world');
      expect(gossip.localFilter.has('hello')).toBe(true);
      expect(gossip.localFilter.has('world')).toBe(true);
    });
  });

  describe('publishFilter', () => {
    test('should publish serialized local filter', async () => {
      gossip.addTerm('test');
      await gossip.publishFilter();
      expect(publishFn).toHaveBeenCalledTimes(1);
      expect(publishFn).toHaveBeenCalledWith(
        bloomFilterUpdateV1,
        expect.any(Uint8Array),
      );
    });
  });

  describe('onReceiveFilter', () => {
    test('should track received peer filters', () => {
      const peerGossip = new BloomFilterGossip({
        filterSizeInBits: 1024,
        numHashFunctions: 3,
      });
      peerGossip.addTerm('peer-data');
      const data = peerGossip.localFilter.serialize();

      gossip.onReceiveFilter('peer-1', data);

      expect(gossip.peerFilters.size).toBe(1);
      const peerState = gossip.peerFilters.get('peer-1');
      expect(peerState).toBeDefined();
      expect(peerState!.filter.has('peer-data')).toBe(true);
    });

    test('should merge updates from same peer', () => {
      const peer1 = new BloomFilterGossip({
        filterSizeInBits: 1024,
        numHashFunctions: 3,
      });
      peer1.addTerm('data-1');
      gossip.onReceiveFilter('peer-1', peer1.localFilter.serialize());

      const peer2 = new BloomFilterGossip({
        filterSizeInBits: 1024,
        numHashFunctions: 3,
      });
      peer2.addTerm('data-2');
      gossip.onReceiveFilter('peer-1', peer2.localFilter.serialize());

      const peerState = gossip.peerFilters.get('peer-1');
      expect(peerState!.filter.has('data-1')).toBe(true);
      expect(peerState!.filter.has('data-2')).toBe(true);
    });
  });

  describe('queryPeers', () => {
    test('should return peers matching all terms', () => {
      const peer1 = new BloomFilterGossip({ filterSizeInBits: 1024, numHashFunctions: 3 });
      peer1.addTerm('a');
      peer1.addTerm('b');
      gossip.onReceiveFilter('peer-1', peer1.localFilter.serialize());

      const peer2 = new BloomFilterGossip({ filterSizeInBits: 1024, numHashFunctions: 3 });
      peer2.addTerm('a');
      gossip.onReceiveFilter('peer-2', peer2.localFilter.serialize());

      const result = gossip.queryPeers(['a', 'b']);
      expect(result).toEqual(['peer-1']);
    });

    test('should return empty when no peers match', () => {
      const result = gossip.queryPeers(['nonexistent']);
      expect(result).toEqual([]);
    });
  });

  describe('getMergedFilter', () => {
    test('should combine local and all peer filters', () => {
      gossip.addTerm('local');

      const peer = new BloomFilterGossip({ filterSizeInBits: 1024, numHashFunctions: 3 });
      peer.addTerm('remote');
      gossip.onReceiveFilter('peer-1', peer.localFilter.serialize());

      const merged = gossip.getMergedFilter();
      expect(merged.has('local')).toBe(true);
      expect(merged.has('remote')).toBe(true);
    });
  });

  describe('start without setPubSub', () => {
    test('should throw if setPubSub() was not called', () => {
      const fresh = new BloomFilterGossip({
        filterSizeInBits: 1024,
        numHashFunctions: 3,
      });
      expect(() => fresh.start()).toThrow('setPubSub() must be called before start()');
    });
  });

  describe('onReceiveFilter with malformed data', () => {
    test('should not crash on data with wrong length', () => {
      expect(() => {
        gossip.onReceiveFilter('bad-peer', new Uint8Array(10));
      }).not.toThrow();
      expect(gossip.peerFilters.size).toBe(0);
    });
  });

  describe('start/stop', () => {
    test('should subscribe on start', () => {
      gossip.start();
      expect(subscribeFn).toHaveBeenCalledTimes(1);
    });

    test('should unsubscribe on stop', () => {
      gossip.start();
      gossip.stop();
      expect(unsubscribeFn).toHaveBeenCalledTimes(1);
    });

    test('should be idempotent', () => {
      gossip.start();
      gossip.start();
      expect(subscribeFn).toHaveBeenCalledTimes(1);
      gossip.stop();
      gossip.stop();
      expect(unsubscribeFn).toHaveBeenCalledTimes(1);
    });
  });
});
