import { AutoTopicRegistry } from './auto-topic-registry.js'
import { DEFAULT_TOPIC_ALLOWLIST } from './config.js'

function registry(maxAutoTopics = 2) {
  return new AutoTopicRegistry({
    permanentTopics: ['/announcements'],
    allowlist: ['/custom/'],
    maxAutoTopics,
    maxAutoTopicsPerPeer: 2,
  })
}

describe('AutoTopicRegistry', () => {
  it('admits only the current default document namespace', () => {
    const topics = new AutoTopicRegistry({
      permanentTopics: [],
      allowlist: DEFAULT_TOPIC_ALLOWLIST,
      maxAutoTopics: 2,
      maxAutoTopicsPerPeer: 2,
    })
    for (const topic of ['/peerborne/document/v3/shared', '/peerborne/document/v3/other']) {
      expect(topics.subscriptionChanged('peer-a', topic, true)).toEqual({
        action: 'subscribe', topic,
      })
    }
    for (const topic of ['/document/shared', '/documents', '/peerborne/documents/v30']) {
      expect(topics.subscriptionChanged('peer-b', topic, true)).toEqual({
        action: 'skip', topic, reason: 'NotInAllowlist',
      })
    }
    expect(topics.size).toBe(2)
  })

  it('reclaims the last topics held by a disconnected peer', () => {
    const topics = registry()
    expect(topics.subscriptionChanged('peer-a', '/custom/a', true)).toEqual({
      action: 'subscribe',
      topic: '/custom/a',
    })
    expect(topics.subscriptionChanged('peer-a', '/custom/b', true)).toEqual({
      action: 'subscribe',
      topic: '/custom/b',
    })

    expect(topics.peerDisconnected('peer-a')).toEqual([
      { action: 'unsubscribe', topic: '/custom/a' },
      { action: 'unsubscribe', topic: '/custom/b' },
    ])
    expect(topics.size).toBe(0)
  })

  it('keeps a topic while another peer still subscribes', () => {
    const topics = registry()
    topics.subscriptionChanged('peer-a', '/custom/shared', true)
    topics.subscriptionChanged('peer-b', '/custom/shared', true)

    expect(topics.peerDisconnected('peer-a')).toEqual([])
    expect(topics.size).toBe(1)
    expect(topics.peerDisconnected('peer-b')).toEqual([
      { action: 'unsubscribe', topic: '/custom/shared' },
    ])
  })

  it('reclaims a topic on an explicit last unsubscribe', () => {
    const topics = registry()
    topics.subscriptionChanged('peer-a', '/custom/a', true)

    expect(topics.subscriptionChanged('peer-a', '/custom/a', false)).toEqual({
      action: 'unsubscribe',
      topic: '/custom/a',
    })
    expect(topics.size).toBe(0)
  })

  it('returns capacity after disconnect instead of permanently exhausting it', () => {
    const topics = registry(1)
    topics.subscriptionChanged('attacker', '/custom/one', true)
    expect(topics.subscriptionChanged('peer-b', '/custom/two', true)).toMatchObject({
      action: 'skip',
      reason: 'CapReached',
    })

    topics.peerDisconnected('attacker')
    expect(topics.subscriptionChanged('peer-b', '/custom/two', true)).toEqual({
      action: 'subscribe',
      topic: '/custom/two',
    })
  })

  it('prevents one peer from consuming more than its topic allowance', () => {
    const topics = registry(10)
    topics.subscriptionChanged('attacker', '/custom/one', true)
    topics.subscriptionChanged('attacker', '/custom/two', true)

    expect(
      topics.subscriptionChanged('attacker', '/custom/three', true),
    ).toEqual({
      action: 'skip',
      topic: '/custom/three',
      reason: 'PeerCapReached',
    })
    expect(topics.size).toBe(2)
  })

  it('applies the per-peer cap when joining an existing dynamic topic', () => {
    const topics = registry(10)
    topics.subscriptionChanged('peer-a', '/custom/one', true)
    topics.subscriptionChanged('peer-a', '/custom/two', true)
    topics.subscriptionChanged('peer-b', '/custom/shared', true)

    expect(
      topics.subscriptionChanged('peer-a', '/custom/shared', true),
    ).toEqual({
      action: 'skip',
      topic: '/custom/shared',
      reason: 'PeerCapReached',
    })
    expect(topics.peerDisconnected('peer-b')).toEqual([
      { action: 'unsubscribe', topic: '/custom/shared' },
    ])
  })

  it('returns per-peer capacity after an unsubscribe', () => {
    const topics = registry(10)
    topics.subscriptionChanged('peer-a', '/custom/one', true)
    topics.subscriptionChanged('peer-a', '/custom/two', true)
    topics.subscriptionChanged('peer-a', '/custom/one', false)

    expect(
      topics.subscriptionChanged('peer-a', '/custom/three', true),
    ).toEqual({
      action: 'subscribe',
      topic: '/custom/three',
    })
  })

  it('does not bypass the per-peer cap during reconciliation', () => {
    const topics = registry(10)
    topics.subscriptionChanged('peer-a', '/custom/one', true)
    topics.subscriptionChanged('peer-a', '/custom/two', true)
    topics.subscriptionChanged('peer-b', '/custom/shared', true)

    expect(
      topics.reconcileTopic('/custom/shared', ['peer-a']),
    ).toEqual({
      action: 'unsubscribe',
      topic: '/custom/shared',
    })
  })

  it('reconciles missed unsubscribe events against GossipSub subscribers', () => {
    const topics = registry()
    topics.subscriptionChanged('peer-a', '/custom/a', true)

    expect(topics.reconcileTopic('/custom/a', [])).toEqual({
      action: 'unsubscribe',
      topic: '/custom/a',
    })
    expect(topics.size).toBe(0)
  })

  it('rebuilds peer membership during reconciliation', () => {
    const topics = registry()
    topics.subscriptionChanged('peer-a', '/custom/a', true)
    expect(topics.reconcileTopic('/custom/a', ['peer-b'])).toMatchObject({
      action: 'skip',
    })

    expect(topics.peerDisconnected('peer-a')).toEqual([])
    expect(topics.peerDisconnected('peer-b')).toEqual([
      { action: 'unsubscribe', topic: '/custom/a' },
    ])
  })

  it('never auto-subscribes permanent or disallowed topics', () => {
    const topics = registry()
    expect(topics.subscriptionChanged('peer-a', '/announcements', true)).toMatchObject({
      action: 'skip',
      reason: 'AlreadyTracked',
    })
    expect(topics.subscriptionChanged('peer-a', '/other', true)).toMatchObject({
      action: 'skip',
      reason: 'NotInAllowlist',
    })
    expect(topics.size).toBe(0)
  })
})
