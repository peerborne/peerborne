import { useEffect, useMemo, useState } from 'react';
import { IndexManager } from './index-manager.js';
import { IndexDefinition, QueryOptions, QueryResult } from './types.js';

/**
 * React hook that subscribes to live index query results.
 * Re-runs the query when the result set changes and when options change.
 *
 * @param manager The IndexManager to query against.
 * @param options Query options (filters, sort, limit, offset, etc.).
 * @returns The current query result, updated reactively.
 */
export function useIndexQuery(
  manager: IndexManager<unknown>,
  options: QueryOptions,
): QueryResult<Record<string, unknown>> {
  const [result, setResult] = useState<QueryResult<Record<string, unknown>>>({
    documents: [],
    totalCount: 0,
  });

  const serializedOptions = useMemo(() => JSON.stringify(options), [options]);

  useEffect(() => {
    const unsub = manager.subscribe(options, (newResult) => {
      setResult(newResult);
    });

    return unsub;
    // Re-subscribe when serialized options change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [manager, serializedOptions]);

  return result;
}

/**
 * React hook that defines indexes on mount and removes them on unmount.
 * Returns `true` once all index definitions have been registered.
 *
 * @param manager The IndexManager to define indexes on.
 * @param definitions Array of index definitions to register.
 * @returns Whether all indexes have been defined.
 */
export function useDefineIndexes(
  manager: IndexManager<unknown>,
  definitions: IndexDefinition[],
): boolean {
  const [ready, setReady] = useState(false);
  const serializedDefs = useMemo(() => JSON.stringify(definitions), [definitions]);

  useEffect(() => {
    const names: string[] = [];
    let cancelled = false;
    setReady(false);

    (async () => {
      let allSucceeded = true;
      for (const def of definitions) {
        if (cancelled) return;
        try {
          await manager.defineIndex(def);
          names.push(def.name);
        } catch (err) {
          allSucceeded = false;
          console.warn(`useDefineIndexes: failed to define index "${def.name}"`, err);
        }
      }
      if (!cancelled && allSucceeded) {
        setReady(true);
      }
    })();

    return () => {
      cancelled = true;
      for (const name of names) {
        manager.removeIndex(name).catch((err) => {
          console.warn(`useDefineIndexes: failed to remove index "${name}"`, err);
        });
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [manager, serializedDefs]);

  return ready;
}
