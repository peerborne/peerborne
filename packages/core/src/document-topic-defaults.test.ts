import { describe, expect, test } from '@jest/globals';
import {
  DEFAULT_DOCUMENT_PUBLISH_PATH,
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  defaultDocumentPubsubConfig,
} from './document-topic.js';

describe('document topic defaults', () => {
  test('provides the shared v3 defaults used by browser and Node builders', () => {
    expect(defaultDocumentPubsubConfig()).toEqual({
      pubsubDocumentPrefix: DEFAULT_DOCUMENT_TOPIC_PREFIX,
      pubsubDocumentPublishPath: DEFAULT_DOCUMENT_PUBLISH_PATH,
    });
    expect(DEFAULT_DOCUMENT_PUBLISH_PATH).not.toBe('/documents');
  });

  test('returns a fresh bundle so caller mutation cannot change later defaults', () => {
    const first = defaultDocumentPubsubConfig() as {
      pubsubDocumentPrefix: string;
    };
    first.pubsubDocumentPrefix = '/legacy/';

    expect(defaultDocumentPubsubConfig().pubsubDocumentPrefix).toBe(
      DEFAULT_DOCUMENT_TOPIC_PREFIX,
    );
  });
});
