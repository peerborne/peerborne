/** Default topic prefix for version-isolated document pubsub messages. */
export const DEFAULT_DOCUMENT_TOPIC_PREFIX = '/peerborne/document/v3/';

/** Shared GossipSub peer-discovery topic for browser, Node, and relay peers. */
export const DEFAULT_PEER_DISCOVERY_TOPIC =
  'peerborne._peer-discovery._p2p._pubsub';

export interface DocumentPubsubConfig {
  readonly pubsubDocumentPrefix: string;
}

/** Return a detached document-topic configuration without replacing overrides. */
export function copyDocumentPubsubConfig(
  config: DocumentPubsubConfig,
): DocumentPubsubConfig {
  return {
    pubsubDocumentPrefix: config.pubsubDocumentPrefix,
  };
}

/** Returns a fresh copy of the shared browser and Node document-topic defaults. */
export function defaultDocumentPubsubConfig(): DocumentPubsubConfig {
  return copyDocumentPubsubConfig({
    pubsubDocumentPrefix: DEFAULT_DOCUMENT_TOPIC_PREFIX,
  });
}

/**
 * Builds a pubsub topic string for a given document path by prepending
 * the configured topic prefix. This separates document pubsub traffic
 * from other topics on the same network.
 *
 * The default prefix is `'/peerborne/document/v3/'`. Topic names are routing
 * labels, not authenticated version negotiation. Every peer on a custom
 * namespace must use the current protocol. Pass an empty string to use the
 * bare document path.
 *
 * @param documentPath - The path identifying the document.
 * @param topicPrefix - Prefix to prepend (defaults to
 *   `'/peerborne/document/v3/'`).
 * @returns The full pubsub topic string.
 */
export function documentTopic(
  documentPath: string,
  topicPrefix: string = DEFAULT_DOCUMENT_TOPIC_PREFIX,
): string {
  if (topicPrefix === '') {
    return documentPath;
  }
  // Avoid double slashes when both prefix ends with '/' and path starts with '/'.
  if (topicPrefix.endsWith('/') && documentPath.startsWith('/')) {
    return `${topicPrefix}${documentPath.slice(1)}`;
  }
  // Insert a separator when neither side provides one.
  if (!topicPrefix.endsWith('/') && !documentPath.startsWith('/')) {
    return `${topicPrefix}/${documentPath}`;
  }
  return `${topicPrefix}${documentPath}`;
}
