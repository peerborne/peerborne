export type DistributedSearchPermission = 'manage' | 'advertise' | 'query';

/** Application identity used for authorization and signing; it is not a libp2p PeerId. */
export interface DistributedSearchSigner {
  applicationId: string;
  sign(payload: Uint8Array): Promise<Uint8Array>;
}

export interface DistributedSearchAuthorizer {
  authorize(
    applicationId: string,
    permission: DistributedSearchPermission,
    collectionId: string,
  ): Promise<boolean>;
  verify(
    applicationId: string,
    payload: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean>;
}

export function validateApplicationId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 ||
      /[\u0000-\u001f]/.test(value)) {
    throw new TypeError('application identity is invalid');
  }
}
