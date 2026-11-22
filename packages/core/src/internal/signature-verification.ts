export const SIGNATURE_VERIFICATION_CONCURRENCY = 4;

/** Wait for every started verification before moving to another batch. */
export async function verifyMemberSignature<Key>(
  keys: readonly Key[],
  verify: (key: Key) => Promise<boolean>,
): Promise<boolean> {
  for (
    let offset = 0;
    offset < keys.length;
    offset += SIGNATURE_VERIFICATION_CONCURRENCY
  ) {
    const batch = keys.slice(
      offset,
      offset + SIGNATURE_VERIFICATION_CONCURRENCY,
    );
    const results = await Promise.allSettled(
      batch.map(async (key) => verify(key)),
    );
    if (
      results.some(
        (result) => result.status === 'fulfilled' && result.value === true,
      )
    )
      return true;
    const failure = results.find((result) => result.status === 'rejected');
    if (failure) throw failure.reason;
  }
  return false;
}
