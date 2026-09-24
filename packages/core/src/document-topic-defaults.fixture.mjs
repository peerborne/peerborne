import assert from 'node:assert/strict';
import test from 'node:test';
import 'fake-indexeddb/auto';
import {
  DEFAULT_DOCUMENT_PUBLISH_PATH,
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  defaultDocumentPubsubConfig,
} from './document-topic.ts';
import {
  defaultBootstrapConfig,
  defaultConfig,
} from './peerborne-config.ts';
import { defaultNodeConfig } from './peerborne-node.ts';

function topicDefaults(config) {
  return {
    pubsubDocumentPrefix: config.pubsubDocumentPrefix,
    pubsubDocumentPublishPath: config.pubsubDocumentPublishPath,
  };
}

test('browser and Node builders use the shared document-topic defaults', () => {
  const expected = defaultDocumentPubsubConfig();
  const browser = defaultConfig(defaultBootstrapConfig([]));
  const node = defaultNodeConfig(defaultBootstrapConfig([]));

  assert.deepEqual(topicDefaults(browser), expected);
  assert.deepEqual(topicDefaults(node), expected);
  assert.equal(expected.pubsubDocumentPrefix, DEFAULT_DOCUMENT_TOPIC_PREFIX);
  assert.equal(
    expected.pubsubDocumentPublishPath,
    DEFAULT_DOCUMENT_PUBLISH_PATH,
  );
});
