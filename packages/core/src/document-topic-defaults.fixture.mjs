import assert from 'node:assert/strict';
import test from 'node:test';
import 'fake-indexeddb/auto';
import {
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  DEFAULT_PEER_DISCOVERY_TOPIC,
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
  };
}

test('browser and Node builders use the shared document-topic defaults', () => {
  const expected = defaultDocumentPubsubConfig();
  const browser = defaultConfig(defaultBootstrapConfig([]));
  const node = defaultNodeConfig(defaultBootstrapConfig([]));

  assert.deepEqual(topicDefaults(browser), expected);
  assert.deepEqual(topicDefaults(node), expected);
  assert.equal(expected.pubsubDocumentPrefix, DEFAULT_DOCUMENT_TOPIC_PREFIX);
  assert.equal('pubsubDocumentPublishPath' in browser, false);
  assert.equal('pubsubDocumentPublishPath' in node, false);
});

function pubsubDiscoveryTopics(config) {
  const components = {
    logger: { forComponent: () => Object.assign(() => {}, { error() {}, trace() {} }) },
  };
  const topics = [];
  for (const factory of config.helia.libp2p.peerDiscovery) {
    let service;
    try {
      service = factory(components);
    } catch {
      continue;
    }
    if (service?.[Symbol.toStringTag] === '@libp2p/pubsub-peer-discovery') {
      topics.push(...service.topics);
    }
  }
  return topics;
}

test('browser and Node builders announce on the shared discovery topic', () => {
  const browser = defaultConfig(defaultBootstrapConfig([]));
  const node = defaultNodeConfig(defaultBootstrapConfig([]));

  assert.deepEqual(pubsubDiscoveryTopics(browser), [DEFAULT_PEER_DISCOVERY_TOPIC]);
  assert.deepEqual(pubsubDiscoveryTopics(node), [DEFAULT_PEER_DISCOVERY_TOPIC]);
});
