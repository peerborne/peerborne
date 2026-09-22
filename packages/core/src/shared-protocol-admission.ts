export type SharedProtocolMutationResult<T> =
  | { readonly admitted: true; readonly value: T }
  | { readonly admitted: false };

/** Cooperative deadline token passed only to shared-protocol document work. */
export interface SharedProtocolHandlerAdmission {
  isActive(): boolean;
  runMutation<T>(
    operation: () => T | Promise<T>,
  ): Promise<SharedProtocolMutationResult<T>>;
}

/** Preserve direct-call compatibility, but fail closed for an expired token. */
export function isSharedProtocolHandlerActive(
  admission: SharedProtocolHandlerAdmission | undefined,
): boolean {
  if (admission === undefined) return true;
  try {
    return admission.isActive() === true;
  } catch {
    return false;
  }
}

/** Run one state commit, or decline it after the handler deadline expires. */
export async function runSharedProtocolMutation<T>(
  admission: SharedProtocolHandlerAdmission | undefined,
  operation: () => T | Promise<T>,
): Promise<SharedProtocolMutationResult<T>> {
  if (admission === undefined) {
    return { admitted: true, value: await operation() };
  }
  if (!isSharedProtocolHandlerActive(admission)) {
    return { admitted: false };
  }
  const result = await admission.runMutation(operation);
  return result?.admitted === true
    ? { admitted: true, value: result.value }
    : { admitted: false };
}
