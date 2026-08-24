import { BlindIndexProvider } from './blind-index-provider.js';

/**
 * Entry with blind index tokens attached to a change block.
 */
export interface BlindIndexEntry {
  documentPath: string;
  blindIndexTokens: Record<string, string>;
}

/**
 * Provides query methods for searching over blind-indexed change blocks.
 */
export class BlindIndexQuery {
  constructor(private _provider: BlindIndexProvider) {}

  /**
   * Filter entries by exact match on a blind-indexed field.
   * Computes the token for the query value, then matches against stored tokens.
   */
  async exactMatch(
    fieldKey: CryptoKey,
    fieldPath: string,
    value: string | number,
    entries: BlindIndexEntry[],
  ): Promise<BlindIndexEntry[]> {
    const queryToken = await this._provider.computeToken(fieldKey, value);
    return entries.filter(entry => entry.blindIndexTokens[fieldPath] === queryToken);
  }

  /**
   * Filter entries by compound exact match on multiple blind-indexed fields.
   */
  async compoundMatch(
    fieldKey: CryptoKey,
    tokenKey: string,
    values: (string | number)[],
    entries: BlindIndexEntry[],
  ): Promise<BlindIndexEntry[]> {
    const queryToken = await this._provider.computeCompoundToken(fieldKey, values);
    return entries.filter(entry => entry.blindIndexTokens[tokenKey] === queryToken);
  }
}
