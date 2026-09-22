/** @internal Preserve per-key ordering while reclaiming settled queue tails. */
export function trackQueuedOperation<T>(
  tails: Map<string, Promise<void>>,
  encodedKey: string,
  run: Promise<T>,
): Promise<T> {
  let settledTail!: Promise<void>;
  const result = run.then(
    (value) => {
      if (tails.get(encodedKey) === settledTail) tails.delete(encodedKey);
      return value;
    },
    (error: unknown) => {
      if (tails.get(encodedKey) === settledTail) tails.delete(encodedKey);
      throw error;
    },
  );
  settledTail = result.then(
    () => undefined,
    () => undefined,
  );
  tails.set(encodedKey, settledTail);
  return result;
}
