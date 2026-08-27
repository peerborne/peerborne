import { IndexDefinition, IndexFieldType, IndexScalar, QueryAst, SortClause } from './types.js';
import { compareCodeUnits, compareIndexScalars, normalizeIndexScalar } from './query-ast.js';
import { extractField } from './field-extractor.js';

const MAX_CURSOR_BYTES = 16_384;
const MAX_CURSOR_ENCODED_LENGTH = Math.ceil(MAX_CURSOR_BYTES * 4 / 3);
const MAX_DOCUMENT_PATH_LENGTH = 4096;

export interface QueryCursorPosition {
  sort: Array<IndexScalar | null>;
  documentPath: string;
}

interface CursorPayload extends QueryCursorPosition {
  version: 1;
  queryHash: string;
  schemaHash: string;
  generation: string;
}

export function createQueryCursor(
  queryHash: string,
  schemaHash: string,
  generation: string,
  documentPath: string,
  fields: Record<string, unknown>,
  query: QueryAst,
  definition: IndexDefinition,
): string {
  const sort = (query.orderBy ?? []).map((clause) => {
    const field = definition.fields.find((candidate) => candidate.path === clause.path)!;
    return normalizeIndexScalar(extractField(fields, clause.path), field) ?? null;
  });
  const json = JSON.stringify({
    version: 1,
    queryHash,
    schemaHash,
    generation,
    sort,
    documentPath,
  });
  return encodeBase64Url(new TextEncoder().encode(json));
}

export function parseQueryCursor(
  cursor: string,
  expectedQueryHash: string,
  expectedSchemaHash: string,
  expectedGeneration: string,
  expectedSortLength?: number,
  expectedSortTypes?: IndexFieldType[],
): QueryCursorPosition {
  let bytes: Uint8Array;
  let parsed: unknown;
  try {
    if (cursor.length > MAX_CURSOR_ENCODED_LENGTH) throw new Error('cursor too large');
    bytes = decodeBase64Url(cursor);
    if (bytes.byteLength > MAX_CURSOR_BYTES) throw new Error('cursor too large');
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new TypeError('invalid query cursor');
  }
  if (!isRecord(parsed)) throw new TypeError('invalid query cursor');
  const keys = Object.keys(parsed).sort().join(',');
  if (keys !== 'documentPath,generation,queryHash,schemaHash,sort,version' || parsed.version !== 1 ||
      parsed.queryHash !== expectedQueryHash || parsed.schemaHash !== expectedSchemaHash ||
      parsed.generation !== expectedGeneration ||
      !Array.isArray(parsed.sort) || parsed.sort.length > 8 ||
      (expectedSortLength !== undefined && parsed.sort.length !== expectedSortLength) ||
      typeof parsed.documentPath !== 'string' || parsed.documentPath.length === 0 ||
      parsed.documentPath.length > MAX_DOCUMENT_PATH_LENGTH || /[\u0000-\u001f]/.test(parsed.documentPath)) {
    throw new TypeError('query cursor does not match this query or generation');
  }
  if (expectedSortTypes !== undefined && expectedSortTypes.length !== parsed.sort.length) {
    throw new TypeError('query cursor does not match this query');
  }
  for (let index = 0; index < parsed.sort.length; index++) {
    const value = parsed.sort[index];
    if (value !== null && typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') {
      throw new TypeError('invalid query cursor sort value');
    }
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new TypeError('invalid query cursor sort value');
    }
    const expectedType = expectedSortTypes?.[index];
    const actualType = expectedType === 'date' ? 'number' : expectedType;
    if (value !== null && actualType !== undefined && typeof value !== actualType) {
      throw new TypeError('query cursor sort value has the wrong type');
    }
  }
  return { sort: parsed.sort as Array<IndexScalar | null>, documentPath: parsed.documentPath };
}

export function compareEntriesForQuery(
  a: { documentPath: string; fields: Record<string, unknown> },
  b: { documentPath: string; fields: Record<string, unknown> },
  orderBy: SortClause[],
  definition: IndexDefinition,
): number {
  for (const clause of orderBy) {
    const field = definition.fields.find((candidate) => candidate.path === clause.path)!;
    const left = normalizeIndexScalar(extractField(a.fields, clause.path), field);
    const right = normalizeIndexScalar(extractField(b.fields, clause.path), field);
    const compared = compareIndexScalars(left, right);
    if (compared !== 0) return clause.direction === 'desc' ? -compared : compared;
  }
  return compareCodeUnits(a.documentPath, b.documentPath);
}

export function isAfterQueryCursor(
  entry: { documentPath: string; fields: Record<string, unknown> },
  position: QueryCursorPosition,
  orderBy: SortClause[],
  definition: IndexDefinition,
): boolean {
  for (let i = 0; i < orderBy.length; i++) {
    const clause = orderBy[i];
    const field = definition.fields.find((candidate) => candidate.path === clause.path)!;
    const value = normalizeIndexScalar(extractField(entry.fields, clause.path), field);
    const rawCursorValue = position.sort[i];
    const cursorValue = rawCursorValue === null ? undefined : rawCursorValue;
    const compared = compareIndexScalars(value, cursorValue);
    if (compared !== 0) return clause.direction === 'desc' ? compared < 0 : compared > 0;
  }
  return compareCodeUnits(entry.documentPath, position.documentPath) > 0;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid base64url');
  const padding = '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/') + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
