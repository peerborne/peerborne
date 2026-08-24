import { describe, expect, test } from '@jest/globals';
import { documentTopic, DEFAULT_DOCUMENT_TOPIC_PREFIX } from './document-topic.js';

describe('documentTopic', () => {
  test('uses /document/ prefix by default', () => {
    expect(documentTopic('my-doc')).toBe('/document/my-doc');
  });

  test('default prefix matches DEFAULT_DOCUMENT_TOPIC_PREFIX', () => {
    expect(DEFAULT_DOCUMENT_TOPIC_PREFIX).toBe('/document/');
  });

  test('avoids double slash with default prefix and leading-slash path', () => {
    expect(documentTopic('/my-doc')).toBe('/document/my-doc');
  });

  test('returns bare path when using explicit empty prefix', () => {
    expect(documentTopic('my-doc', '')).toBe('my-doc');
  });

  test('preserves leading slash with explicit empty prefix', () => {
    expect(documentTopic('/my-doc', '')).toBe('/my-doc');
  });

  test('preserves nested paths with explicit empty prefix', () => {
    expect(documentTopic('/org/team/doc', '')).toBe('/org/team/doc');
  });

  test('preserves nested paths without leading slash with explicit empty prefix', () => {
    expect(documentTopic('org/team/doc', '')).toBe('org/team/doc');
  });

  test('returns empty string for empty path with explicit empty prefix', () => {
    expect(documentTopic('', '')).toBe('');
  });

  test('uses a custom prefix', () => {
    expect(documentTopic('my-doc', '/docs/')).toBe('/docs/my-doc');
  });

  test('avoids double slash with custom prefix ending in / and path starting with /', () => {
    expect(documentTopic('/my-doc', '/docs/')).toBe('/docs/my-doc');
  });

  test('inserts slash when prefix does not end with / and path does not start with /', () => {
    expect(documentTopic('my-doc', '/docs')).toBe('/docs/my-doc');
  });

  test('works when prefix does not end with / but path starts with /', () => {
    expect(documentTopic('/my-doc', '/docs')).toBe('/docs/my-doc');
  });

  test('applies /document/ prefix when explicitly provided', () => {
    expect(documentTopic('my-doc', '/document/')).toBe('/document/my-doc');
  });

  test('applies /document/ prefix and avoids double slash', () => {
    expect(documentTopic('/my-doc', '/document/')).toBe('/document/my-doc');
  });

  // Edge case: '/' prefix produces '/path'
  test('applies bare / prefix correctly', () => {
    expect(documentTopic('my-doc', '/')).toBe('/my-doc');
  });

  test('applies bare / prefix and avoids double slash with leading-slash path', () => {
    expect(documentTopic('/my-doc', '/')).toBe('/my-doc');
  });
});
