/** Encryptions under one key after which a warning is logged once. */
export const ENCRYPTION_WARNING_THRESHOLD = 2 ** 31;

/**
 * Encryptions allowed under one key: NIST SP 800-38D's limit for AES-GCM with
 * random 96-bit IVs.
 */
export const ENCRYPTION_LIMIT = 2 ** 32;

/**
 * Counts encryptions per key object. The count is local to this process and
 * this key object: it is lost on restart, a re-imported copy of the same key
 * starts at zero, and other devices encrypting under the key are not counted.
 */
export class EncryptionUsageCounter<Key extends object> {
  private readonly counts = new WeakMap<Key, number>();

  constructor(
    private readonly warningThreshold = ENCRYPTION_WARNING_THRESHOLD,
    private readonly limit = ENCRYPTION_LIMIT,
  ) {
    if (
      !Number.isSafeInteger(warningThreshold) ||
      !Number.isSafeInteger(limit) ||
      warningThreshold < 0 ||
      limit < warningThreshold
    )
      throw new RangeError('Invalid encryption usage thresholds');
  }

  /** Reserve one encryption under `key`, refusing once the limit is reached. */
  record(key: Key): void {
    const count = this.counts.get(key) ?? 0;
    if (count >= this.limit)
      throw new Error(
        'Encryption key reached its usage limit; rotate the document key',
      );
    this.counts.set(key, count + 1);
    if (count === this.warningThreshold)
      console.warn(
        'Encryption key passed its usage warning threshold; rotate the document key',
      );
  }
}
