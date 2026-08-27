/**
 * Pure topic auto-subscribe policy.
 *
 * The relay watches GossipSub `subscription-change` events: when a browser
 * peer subscribes to a new topic, the relay decides whether to also
 * subscribe so it can forward messages between peers that haven't yet
 * formed a direct WebRTC mesh.
 *
 * This module exposes the decision as a pure function so it can be unit-
 * tested without spinning up libp2p. The caller (index.ts) holds the live
 * state (the tracked-topics Set) and invokes this on each event.
 */

import { SYSTEM_TOPIC_PREFIXES } from './config.js'

/**
 * Input to the auto-subscribe decision.
 *
 * - `allowlist`: list of allowed topic prefixes, or null for open mode.
 *   When set, a topic must start with at least one prefix to be eligible.
 * - `maxAutoTopics`: hard cap on auto-subscribed topics. Once reached,
 *   further subscriptions are rejected.
 * - `autoTopicCount`: number of topics currently auto-subscribed (used
 *   against the cap). Tracked topics that are already subscribed return
 *   `AlreadyTracked` and don't increment the count.
 * - `isTracked`: predicate that returns true if the relay already tracks
 *   the topic (seed, EXTRA_TOPICS, or previously auto-subscribed).
 * - `systemTopicPrefixes`: prefixes that mark a topic as internal /
 *   system. Defaults to `SYSTEM_TOPIC_PREFIXES` from `config.ts`. Override
 *   for testing or stricter deployments.
 */
export interface AutoSubscribePolicy {
  readonly allowlist: readonly string[] | null
  readonly maxAutoTopics: number
  readonly autoTopicCount: number
  readonly isTracked: (topic: string) => boolean
  readonly systemTopicPrefixes?: readonly string[]
}

/**
 * Outcome of the decision. The relay caller uses this both to gate the
 * libp2p `subscribe` call and to surface human-readable rationale in logs.
 */
export type AutoSubscribeDecision =
  | { readonly action: 'subscribe' }
  | { readonly action: 'skip'; readonly reason: AutoSubscribeSkipReason }

/**
 * Why a topic was skipped. `AlreadyTracked` is benign (no-op), but
 * `CapReached` indicates the relay is at its configured limit and is a
 * signal worth logging.
 */
export type AutoSubscribeSkipReason =
  | 'AlreadyTracked'
  | 'SystemTopic'
  | 'NotInAllowlist'
  | 'CapReached'
  | 'PeerCapReached'

/**
 * Decide whether the relay should auto-subscribe to `topic`.
 *
 * Order of checks (each rejection is reported as a distinct reason):
 *   1. AlreadyTracked  — topic is in the tracked set; nothing to do.
 *   2. SystemTopic     — topic starts with a system prefix (e.g. `_`).
 *   3. NotInAllowlist  — allowlist is configured and topic doesn't match.
 *   4. CapReached      — auto-subscribe cap would be exceeded.
 *
 * If all four checks pass, the decision is `subscribe`.
 */
export function shouldAutoSubscribe(
  topic: string,
  policy: AutoSubscribePolicy,
): AutoSubscribeDecision {
  // Programming-error guard: negative / non-finite counters indicate a
  // caller bug (the cap-arithmetic in index.ts would silently misbehave).
  // Throw rather than return a misleading decision — these never happen
  // at runtime from a correctly-wired relay.
  if (
    !Number.isFinite(policy.maxAutoTopics) ||
    !Number.isFinite(policy.autoTopicCount) ||
    policy.maxAutoTopics < 0 ||
    policy.autoTopicCount < 0
  ) {
    throw new Error(
      `AutoSubscribePolicy counters must be finite, non-negative numbers ` +
        `(got maxAutoTopics=${policy.maxAutoTopics}, ` +
        `autoTopicCount=${policy.autoTopicCount})`,
    )
  }

  if (policy.isTracked(topic)) {
    return { action: 'skip', reason: 'AlreadyTracked' }
  }

  const systemPrefixes = policy.systemTopicPrefixes ?? SYSTEM_TOPIC_PREFIXES
  if (systemPrefixes.some((prefix) => topic.startsWith(prefix))) {
    return { action: 'skip', reason: 'SystemTopic' }
  }

  if (
    policy.allowlist !== null &&
    !policy.allowlist.some((prefix) => topic.startsWith(prefix))
  ) {
    return { action: 'skip', reason: 'NotInAllowlist' }
  }

  if (policy.autoTopicCount >= policy.maxAutoTopics) {
    return { action: 'skip', reason: 'CapReached' }
  }

  return { action: 'subscribe' }
}
