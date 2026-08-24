/** Default topic prefix for document pubsub topics. */
export const DEFAULT_DOCUMENT_TOPIC_PREFIX = '/document/';

/**
 * Builds a pubsub topic string for a given document path by prepending
 * the configured topic prefix. This separates document pubsub traffic
 * from other topics on the same network.
 *
 * The default prefix is `'/document/'`, which namespaces document traffic
 * on the pubsub mesh. Pass an empty string to disable prefixing (the topic
 * will be the bare document path).
 *
 * @param documentPath - The path identifying the document.
 * @param topicPrefix - Prefix to prepend (defaults to `'/document/'`).
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
