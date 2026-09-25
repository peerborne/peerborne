import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { describe, expect, test } from '@jest/globals';
import {
  DEFAULT_DOCUMENT_TOPIC_PREFIX,
  defaultDocumentPubsubConfig,
} from './document-topic.js';

const execFileAsync = promisify(execFile);

describe('document topic defaults', () => {
  test('provides the shared v3 defaults', () => {
    expect(defaultDocumentPubsubConfig()).toEqual({
      pubsubDocumentPrefix: DEFAULT_DOCUMENT_TOPIC_PREFIX,
    });
  });

  test('imports native ESM browser and Node builders with the same document topics', async () => {
    const fixture = `${__dirname}/document-topic-defaults.fixture.mjs`;
    await expect(
      execFileAsync(
        process.execPath,
        ['--import', 'tsx', '--test', fixture],
        { timeout: 20_000 },
      ),
    ).resolves.toBeDefined();
  }, 30_000);

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
