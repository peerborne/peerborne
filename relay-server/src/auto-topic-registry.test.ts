import { AutoTopicRegistry } from './auto-topic-registry.js'

function registry(maxAutoTopics = 2) {
  return new AutoTopicRegistry({
    permanentTopics: ['/documents'],
    allowlist: ['/document/'],
    maxAutoTopics,
    maxAutoTopicsPerPeer: 2,
  })
}

describe('AutoTopicRegistry', () => {
  it('reclaims the last topics held by a disconnected peer', () => {
    const topics = registry()
    expect(topics.subscriptionChanged('peer-a', '/document/a', true)).toEqual({
      action: 'subscribe',
      topic: '/document/a',
    })
    expect(topics.subscriptionChanged('peer-a', '/document/b', true)).toEqual({
      action: 'subscribe',
      topic: '/document/b',
    })

    expect(topics.peerDisconnected('peer-a')).toEqual([
      { action: 'unsubscribe', topic: '/document/a' },
      { action: 'unsubscribe', topic: '/document/b' },
    ])
    expect(topics.size).toBe(0)
  })

  it('keeps a topic while another peer still subscribes', () => {
    const topics = registry()
    topics.subscriptionChanged('peer-a', '/document/shared', true)
    topics.subscriptionChanged('peer-b', '/document/shared', true)

    expect(topics.peerDisconnected('peer-a')).toEqual([])
    expect(topics.size).toBe(1)
    expect(topics.peerDisconnected('peer-b')).toEqual([
      { action: 'unsubscribe', topic: '/document/shared' },
    ])
  })

  it('reclaims a topic on an explicit last unsubscribe', () => {
    const topics = registry()
    topics.subscriptionChanged('peer-a', '/document/a', true)

    expect(topics.subscriptionChanged('peer-a', '/document/a', false)).toEqual({
      action: 'unsubscribe',
      topic: '/document/a',
    })
    expect(topics.size).toBe(0)
  })

  it('returns capacity after disconnect instead of permanently exhausting it', () => {
    const topics = registry(1)
    topics.subscriptionChanged('attacker', '/document/one', true)
    expect(topics.subscriptionChanged('peer-b', '/document/two', true)).toMatchObject({
      action: 'skip',
      reason: 'CapReached',
    })

    topics.peerDisconnected('attacker')
    expect(topics.subscriptionChanged('peer-b', '/document/two', true)).toEqual({
      action: 'subscribe',
      topic: '/document/two',
    })
  })

  it('prevents one peer from consuming more than its topic allowance', () => {
    const topics = registry(10)
    topics.subscriptionChanged('attacker', '/document/one', true)
    topics.subscriptionChanged('attacker', '/document/two', true)

    expect(
      topics.subscriptionChanged('attacker', '/document/three', true),
    ).toEqual({
      action: 'skip',
      topic: '/document/three',
      reason: 'PeerCapReached',
    })
    expect(topics.size).toBe(2)
  })

  it('applies the per-peer cap when joining an existing dynamic topic', () => {
    const topics = registry(10)
    topics.subscriptionChanged('peer-a', '/document/one', true)
    topics.subscriptionChanged('peer-a', '/document/two', true)
    topics.subscriptionChanged('peer-b', '/document/shared', true)

    expect(
      topics.subscriptionChanged('peer-a', '/document/shared', true),
    ).toEqual({
      action: 'skip',
      topic: '/document/shared',
      reason: 'PeerCapReached',
    })
    expect(topics.peerDisconnected('peer-b')).toEqual([
      { action: 'unsubscribe', topic: '/document/shared' },
    ])
  })

  it('returns per-peer capacity after an unsubscribe', () => {
    const topics = registry(10)
    topics.subscriptionChanged('peer-a', '/document/one', true)
    topics.subscriptionChanged('peer-a', '/document/two', true)
    topics.subscriptionChanged('peer-a', '/document/one', false)

    expect(
      topics.subscriptionChanged('peer-a', '/document/three', true),
    ).toEqual({
      action: 'subscribe',
      topic: '/document/three',
    })
  })

  it('does not bypass the per-peer cap during reconciliation', () => {
    const topics = registry(10)
    topics.subscriptionChanged('peer-a', '/document/one', true)
    topics.subscriptionChanged('peer-a', '/document/two', true)
    topics.subscriptionChanged('peer-b', '/document/shared', true)

    expect(
      topics.reconcileTopic('/document/shared', ['peer-a']),
    ).toEqual({
      action: 'unsubscribe',
      topic: '/document/shared',
    })
  })

  it('reconciles missed unsubscribe events against GossipSub subscribers', () => {
    const topics = registry()
    topics.subscriptionChanged('peer-a', '/document/a', true)

    expect(topics.reconcileTopic('/document/a', [])).toEqual({
      action: 'unsubscribe',
      topic: '/document/a',
    })
    expect(topics.size).toBe(0)
  })

  it('rebuilds peer membership during reconciliation', () => {
    const topics = registry()
    topics.subscriptionChanged('peer-a', '/document/a', true)
    expect(topics.reconcileTopic('/document/a', ['peer-b'])).toMatchObject({
      action: 'skip',
    })

    expect(topics.peerDisconnected('peer-a')).toEqual([])
    expect(topics.peerDisconnected('peer-b')).toEqual([
      { action: 'unsubscribe', topic: '/document/a' },
    ])
  })

  it('never auto-subscribes permanent or disallowed topics', () => {
    const topics = registry()
    expect(topics.subscriptionChanged('peer-a', '/documents', true)).toMatchObject({
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
