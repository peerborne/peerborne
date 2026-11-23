import { StorageQueryRequest, StorageQueryResult, IndexEntry } from './index-storage.js';
import { compareCodeUnits, evaluateQueryExpression } from './query-ast.js';
import { compareEntriesForQuery } from './query-cursor.js';
import type { QueryIndexLookup } from './query-planner.js';
import type { IndexScalar } from './types.js';

export function matchIndexLookup<Key>(
  key: readonly Key[],
  { equals, range }: QueryIndexLookup,
  compare: (value: Key | undefined, bound: IndexScalar) => number,
): 'before' | 'match' | 'past' {
  for (let i = 0; i < equals.length; i++) {
    const compared = compare(key[i], equals[i]);
    if (compared < 0) return 'before';
    if (compared > 0) return 'past';
  }
  if (!range) return 'match';
  const value = key[range.position];
  if (range.prefix !== undefined) {
    if (typeof value !== 'string') return 'past';
    if (value.startsWith(range.prefix)) return 'match';
    return compareCodeUnits(value, range.prefix) < 0 ? 'before' : 'past';
  }
  if (range.lower !== undefined) {
    const compared = compare(value, range.lower);
    if (compared < 0 || (compared === 0 && !range.lowerInclusive)) return 'before';
  }
  if (range.upper !== undefined) {
    const compared = compare(value, range.upper);
    if (compared > 0 || (compared === 0 && !range.upperInclusive)) return 'past';
  }
  return 'match';
}

export function finalizeQueryCandidates(
  request: StorageQueryRequest,
  candidates: IndexEntry[],
  rowsVisited: number,
  indexOrderPreserved: boolean,
): StorageQueryResult {
  const deduplicated = new Map<string, IndexEntry>();
  for (const candidate of candidates) {
    if (!deduplicated.has(candidate.documentPath) &&
        evaluateQueryExpression(candidate.fields, request.query.where, request.definition)) {
      deduplicated.set(candidate.documentPath, {
        documentPath: candidate.documentPath,
        fields: structuredClone(candidate.fields),
      });
    }
  }
  const entries = Array.from(deduplicated.values());
  const orderBy = request.query.orderBy ?? [];
  if (orderBy.length > 0 && !indexOrderPreserved) {
    entries.sort((a, b) => compareEntriesForQuery(a, b, orderBy, request.definition));
  } else if (orderBy.length === 0) {
    entries.sort((a, b) => compareCodeUnits(a.documentPath, b.documentPath));
  }
  return {
    entries,
    totalCount: entries.length,
    rowsVisited,
    rowsMatched: entries.length,
    sort: orderBy.length === 0 ? 'none' : indexOrderPreserved ? 'index' : 'memory',
  };
}
