/**
 * Validation + eager raw-export for the recipient-side BeeKEM Welcome
 * key pair installed via `PeerborneDocument.setKemKeyPair`.
 *
 * Extracted into a standalone module so the validation logic can be
 * unit-tested without dragging in the full `PeerborneDocument`
 * dependency graph (libp2p, Helia, providers). The receive path
 * (`_evaluateAndApplyBeeKEMWelcome`) requires (a) an ECDH P-256 key
 * pair and (b) a private key with `deriveBits` usage, and it consumes
 * the raw SEC1-uncompressed public key bytes on every incoming
 * Welcome. Without eager validation a misconfigured key pair (wrong
 * algorithm, wrong curve, missing usage, non-exportable public key)
 * would surface as a generic WebCrypto exception deep inside the
 * Welcome handler on the first invite. This helper validates the
 * key pair up-front and eagerly exports the raw public key so the
 * receive path never has to await an `exportKey` call.
 */

/**
 * Validate that `keyPair` is a usable BeeKEM Welcome KEM key pair and
 * return the raw SEC1-uncompressed bytes of the public key.
 *
 * Throws a clear, install-time error if:
 *   - either key is not ECDH
 *   - either key is not on the P-256 curve
 *   - the private key usages do not include `'deriveBits'`
 *   - the public key cannot be raw-exported (e.g. was created with
 *     `extractable=false`)
 */
export async function validateAndExportKemKeyPair(
  keyPair: CryptoKeyPair,
): Promise<Uint8Array> {
  const pubAlgo = keyPair.publicKey.algorithm as {
    name?: string;
    namedCurve?: string;
  };
  const privAlgo = keyPair.privateKey.algorithm as {
    name?: string;
    namedCurve?: string;
  };
  if (pubAlgo.name !== 'ECDH' || privAlgo.name !== 'ECDH') {
    throw new Error(
      `setKemKeyPair: key pair must be ECDH (got publicKey=${
        pubAlgo.name ?? 'unknown'
      }, privateKey=${privAlgo.name ?? 'unknown'})`,
    );
  }
  if (pubAlgo.namedCurve !== 'P-256' || privAlgo.namedCurve !== 'P-256') {
    throw new Error(
      `setKemKeyPair: key pair must use curve P-256 (got publicKey=${
        pubAlgo.namedCurve ?? 'unknown'
      }, privateKey=${privAlgo.namedCurve ?? 'unknown'})`,
    );
  }
  if (!keyPair.privateKey.usages.includes('deriveBits')) {
    throw new Error(
      `setKemKeyPair: private key usages must include 'deriveBits' (got [${keyPair.privateKey.usages.join(
        ', ',
      )}])`,
    );
  }

  try {
    return new Uint8Array(
      await crypto.subtle.exportKey('raw', keyPair.publicKey),
    );
  } catch (err) {
    // Normalize the inner error: `${err}` on a non-Error throwable
    // (DOMException, plain object, etc.) can produce
    // "[object Object]". Pulling `.message` when available keeps the
    // text actionable; the original is preserved via `cause` for
    // structured introspection.
    const msg = err instanceof Error ? err.message : String(err);
    // The KEM PUBLIC key must be raw-exportable so it can be advertised
    // out-of-band to inviters. The PRIVATE key should remain
    // non-extractable; the recommended pattern is to call
    // `generateKey({ ..., extractable: true })`, then re-import the
    // private key with `extractable: false` (see `generateEciesKeyPair`
    // in `ecies.ts` for the canonical approach).
    throw new Error(
      `setKemKeyPair: failed to export public key as raw bytes ` +
        `(the public key must be raw-exportable; the private key can ` +
        `still be non-extractable): ${msg}`,
      { cause: err },
    );
  }
}
