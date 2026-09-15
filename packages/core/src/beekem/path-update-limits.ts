/** Maximum internal nodes on a v1 leaf-to-root direct path. */
export const MAX_V1_PATH_NODES = 13;

/** Minimum non-empty ECIES ciphertext size for a v1 private path key. */
export const MIN_V1_ENCRYPTED_PRIVATE_KEY_BYTES = 125;

/** Maximum ECIES ciphertext size for a v1 private path key. */
export const MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES = 4096;

/** Maximum detached binary data admitted for one v1 PathUpdate. */
export const MAX_V1_PATH_UPDATE_BYTES =
  65 +
  MAX_V1_PATH_NODES * (65 + MAX_V1_ENCRYPTED_PRIVATE_KEY_BYTES);
