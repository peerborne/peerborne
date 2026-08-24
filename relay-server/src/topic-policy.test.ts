import { DEFAULT_MAX_AUTO_TOPICS, PUBSUB_PEER_DISCOVERY_TOPIC } from './config.js'
import { shouldAutoSubscribe } from './topic-policy.js'

const neverTracked = () => false
const trackedSet = (...topics: string[]) => {
  const set = new Set(topics)
  return (topic: string) => set.has(topic)
}

describe('shouldAutoSubscribe', () => {
  describe('open mode (allowlist === null)', () => {
    it('subscribes to a fresh topic when below the cap', () => {
      const decision = shouldAutoSubscribe('/document/my-doc', {
        allowlist: null,
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'subscribe' })
    })

    it('subscribes to arbitrary user-namespace topics', () => {
      const decision = shouldAutoSubscribe('chat-room-42', {
        allowlist: null,
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 5,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'subscribe' })
    })
  })

  describe('allowlist filtering', () => {
    it('subscribes when a topic matches an allowlist prefix', () => {
      const decision = shouldAutoSubscribe('/document/abc', {
        allowlist: ['/document/', '/peerborne/'],
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'subscribe' })
    })

    it('subscribes when topic matches the second prefix', () => {
      const decision = shouldAutoSubscribe('/peerborne/xyz', {
        allowlist: ['/document/', '/peerborne/'],
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'subscribe' })
    })

    it('rejects topics that do not match any prefix', () => {
      const decision = shouldAutoSubscribe('/other/abc', {
        allowlist: ['/document/', '/peerborne/'],
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'skip', reason: 'NotInAllowlist' })
    })

    it('rejects when the allowlist is empty (effectively closed mode)', () => {
      // Note: loadConfig collapses an empty allowlist to null, but the
      // policy fn must still handle an explicit empty list as "closed".
      const decision = shouldAutoSubscribe('/document/abc', {
        allowlist: [],
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'skip', reason: 'NotInAllowlist' })
    })

    it('uses prefix match, not equality', () => {
      const decision = shouldAutoSubscribe('/document/abc/sub', {
        allowlist: ['/document/'],
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'subscribe' })
    })
  })

  describe('cap enforcement', () => {
    it('subscribes when one slot remains', () => {
      const decision = shouldAutoSubscribe('/document/abc', {
        allowlist: null,
        maxAutoTopics: 10,
        autoTopicCount: 9,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'subscribe' })
    })

    it('rejects when at the cap', () => {
      const decision = shouldAutoSubscribe('/document/abc', {
        allowlist: null,
        maxAutoTopics: 10,
        autoTopicCount: 10,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'skip', reason: 'CapReached' })
    })

    it('rejects when above the cap', () => {
      const decision = shouldAutoSubscribe('/document/abc', {
        allowlist: null,
        maxAutoTopics: 10,
        autoTopicCount: 99,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'skip', reason: 'CapReached' })
    })
  })

  describe('tracked-topic short-circuit', () => {
    it('reports AlreadyTracked when topic is in the tracked set', () => {
      const decision = shouldAutoSubscribe(PUBSUB_PEER_DISCOVERY_TOPIC, {
        allowlist: null,
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: trackedSet(PUBSUB_PEER_DISCOVERY_TOPIC),
      })
      expect(decision).toEqual({ action: 'skip', reason: 'AlreadyTracked' })
    })

    it('skips tracked topics even if the cap is at zero', () => {
      // No-op subscription should still be a no-op regardless of cap.
      const decision = shouldAutoSubscribe('/documents', {
        allowlist: null,
        maxAutoTopics: 0,
        autoTopicCount: 0,
        isTracked: trackedSet('/documents'),
      })
      expect(decision).toEqual({ action: 'skip', reason: 'AlreadyTracked' })
    })
  })

  describe('system-topic rejection', () => {
    it('rejects topics with the "_" prefix', () => {
      const decision = shouldAutoSubscribe('_internal', {
        allowlist: null,
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'skip', reason: 'SystemTopic' })
    })

    it('rejects topics with the "floodsub:" prefix', () => {
      const decision = shouldAutoSubscribe('floodsub:something', {
        allowlist: null,
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'skip', reason: 'SystemTopic' })
    })

    it('rejects system topics even when explicitly allowlisted', () => {
      // System-topic check runs before allowlist; this prevents an
      // operator from accidentally allowing internal topics with a wide
      // prefix like "".
      const decision = shouldAutoSubscribe('_internal', {
        allowlist: ['_'],
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'skip', reason: 'SystemTopic' })
    })

    it('respects a caller-overridden system prefix list', () => {
      const decision = shouldAutoSubscribe('zz:custom', {
        allowlist: null,
        maxAutoTopics: DEFAULT_MAX_AUTO_TOPICS,
        autoTopicCount: 0,
        isTracked: neverTracked,
        systemTopicPrefixes: ['zz:'],
      })
      expect(decision).toEqual({ action: 'skip', reason: 'SystemTopic' })
    })
  })

  describe('rejection precedence', () => {
    // The decision returns the *first* matching reason. Pin the order so
    // future refactors can't silently shuffle the gates.
    it('AlreadyTracked beats every other reason', () => {
      const decision = shouldAutoSubscribe('_already-tracked', {
        allowlist: [], // closed
        maxAutoTopics: 0, // capped
        autoTopicCount: 0,
        isTracked: trackedSet('_already-tracked'),
      })
      expect(decision).toEqual({ action: 'skip', reason: 'AlreadyTracked' })
    })

    it('SystemTopic beats NotInAllowlist and CapReached', () => {
      const decision = shouldAutoSubscribe('_internal', {
        allowlist: [],
        maxAutoTopics: 0,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'skip', reason: 'SystemTopic' })
    })

    it('NotInAllowlist beats CapReached', () => {
      const decision = shouldAutoSubscribe('/other/abc', {
        allowlist: ['/document/'],
        maxAutoTopics: 0,
        autoTopicCount: 0,
        isTracked: neverTracked,
      })
      expect(decision).toEqual({ action: 'skip', reason: 'NotInAllowlist' })
    })
  })

  describe('counter validation', () => {
    // These are programming-error guards: the production caller wires
    // autoTopics.size and the loaded config, so these inputs only show up
    // when a caller has a bug. Throwing surfaces the bug instead of
    // letting the cap arithmetic produce silently-wrong decisions.
    const baseInput = {
      allowlist: null,
      isTracked: neverTracked,
    } as const

    it('throws when maxAutoTopics is negative', () => {
      expect(() =>
        shouldAutoSubscribe('/document/abc', {
          ...baseInput,
          maxAutoTopics: -1,
          autoTopicCount: 0,
        }),
      ).toThrow(/finite, non-negative/)
    })

    it('throws when autoTopicCount is negative', () => {
      expect(() =>
        shouldAutoSubscribe('/document/abc', {
          ...baseInput,
          maxAutoTopics: 10,
          autoTopicCount: -1,
        }),
      ).toThrow(/finite, non-negative/)
    })

    it('throws when maxAutoTopics is NaN', () => {
      expect(() =>
        shouldAutoSubscribe('/document/abc', {
          ...baseInput,
          maxAutoTopics: Number.NaN,
          autoTopicCount: 0,
        }),
      ).toThrow(/finite, non-negative/)
    })

    it('throws when autoTopicCount is Infinity', () => {
      expect(() =>
        shouldAutoSubscribe('/document/abc', {
          ...baseInput,
          maxAutoTopics: 10,
          autoTopicCount: Number.POSITIVE_INFINITY,
        }),
      ).toThrow(/finite, non-negative/)
    })

    it('accepts zero counters (cap-of-zero is a valid closed-mode config)', () => {
      const decision = shouldAutoSubscribe('/document/abc', {
        ...baseInput,
        maxAutoTopics: 0,
        autoTopicCount: 0,
      })
      expect(decision).toEqual({ action: 'skip', reason: 'CapReached' })
    })
  })
})
