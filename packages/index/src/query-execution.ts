import { StorageQueryRequest, StorageQueryResult, IndexEntry } from './index-storage.js';
import { compareCodeUnits, evaluateQueryExpression } from './query-ast.js';
import { compareEntriesForQuery } from './query-cursor.js';

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
