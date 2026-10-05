import { LastWriterRemovalError } from '@peerborne/core';
import { PeerborneContext, usePeerborneDocumentState } from '@peerborne/react';
import { deserializeKey, serializeKey } from '@peerborne/yjs';
import { useContext, useEffect, useState } from 'react';
import { Button, Form, Table } from 'react-bootstrap';
import { YjsPeerborne } from './utils';

type DisplayPermission = {
  key: CryptoKey;
  publicKey: string; // id
  permissions: 'r' | 'rw';
};

const lastEditorMessage =
  'The last editor cannot be demoted or removed. Add another editor first.';
const missingKemMessage = "Enter the new member's KEM public key.";
const keepAnotherEditor = { requireRemainingWriter: true } as const;

async function isLastWriter(
  target: CryptoKey,
  writers: readonly CryptoKey[] | undefined,
): Promise<boolean> {
  const [serializedTarget, ...serializedWriters] = await Promise.all(
    [target, ...(writers ?? [])].map((key) => serializeKey(key)),
  );
  const writerKeys = new Set(serializedWriters);
  return writerKeys.size === 1 && writerKeys.has(serializedTarget);
}

class KemPublicKeyInputError extends Error {}

function decodeKemPublicKey(value: string): Uint8Array | undefined {
  const encoded = value.trim();
  if (!encoded) return undefined;
  let decoded: string;
  try {
    decoded = atob(encoded);
  } catch {
    throw new KemPublicKeyInputError(
      'The member KEM public key is not valid base64.',
    );
  }
  const raw = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new KemPublicKeyInputError(
      'The member KEM public key must be a 65-byte uncompressed P-256 ' +
        'public key starting with 0x04.',
    );
  }
  return raw;
}

export function PermissionsTable({
  passwordId,
  peerborne,
  kemKeyPair,
}: {
  passwordId?: string;
  peerborne: YjsPeerborne;
  kemKeyPair: CryptoKeyPair;
}) {
  const documentPath = `/passwords/${passwordId}`;
  const [
    ,
    ,
    { readers, addReader, removeReader, writers, addWriter, removeWriter },
  ] = usePeerborneDocumentState(peerborne, documentPath);
  const { docCache } = useContext(PeerborneContext);
  const docRef = Object.values(docCache).find(
    (candidate) =>
      candidate.swarm === peerborne && candidate.documentPath === documentPath,
  );
  const [kemReadyDocRef, setKemReadyDocRef] = useState<typeof docRef>();
  const [permissions, setPermissions] = useState<DisplayPermission[]>([]);
  const [draftUserKey, setDraftUserKey] = useState('');
  const [draftKemKey, setDraftKemKey] = useState('');
  const [draftPermission, setDraftPermission] = useState<'r' | 'rw'>('r');

  // addReader seeds BeeKEM leaf 0 from the founder's KEM key pair, so install
  // it once per document before any membership change.
  useEffect(() => {
    if (!docRef) return;
    let active = true;
    (async () => {
      if (!docRef.getKemPublicKeyRaw()) {
        await docRef.setKemKeyPair(kemKeyPair);
      }
      if (active) setKemReadyDocRef(docRef);
    })().catch(() => {
      console.error(`Failed to install a KEM key pair for ${documentPath}`);
    });
    return () => {
      active = false;
    };
  }, [docRef, documentPath, kemKeyPair]);

  // Update `permissions` whenever document `readers` and/or `writers` changes.
  useEffect(() => {
    (async () => {
      const keys = new Set<string>();
      const newPermissions: DisplayPermission[] = [];
      if (!writers) {
        return;
      }
      for (const writer of writers) {
        const serializedKey: string = await serializeKey(writer);
        keys.add(serializedKey);
        newPermissions.push({
          key: writer,
          publicKey: serializedKey,
          permissions: 'rw',
        });
      }
      if (!readers) {
        return;
      }
      for (const reader of readers) {
        const serializedKey: string = await serializeKey(reader);
        if (!keys.has(serializedKey)) {
          newPermissions.push({
            key: reader,
            publicKey: serializedKey,
            permissions: 'r',
          });
        }
      }
      setPermissions(newPermissions);
    })();
  }, [readers, writers]);

  return (
    <>
      <p>
        Enter the member's signing public key and raw P-256 ECDH KEM public key,
        both base64. The KEM key gives the member a BeeKEM leaf and seals the
        document key in a Welcome sent to connected peers. A new member requires
        a KEM key; an existing member's role can change without one.
      </p>
      <Table striped bordered hover>
        <thead>
          <tr>
            <th>User</th>
            <th colSpan={2}>Authorization role</th>
          </tr>
        </thead>
        <tbody>
          {permissions &&
            permissions.map((permission, i) => (
              <tr key={permission.publicKey}>
                <td
                  style={{
                    wordBreak: 'break-all',
                  }}
                >
                  {permission.publicKey}
                </td>
                <td>
                  {permission.permissions === 'rw' ? 'Editor' : 'Reader'}
                </td>
                <td>
                  <Button
                    variant="danger"
                    onClick={() => {
                      (async () => {
                        try {
                          switch (permission.permissions) {
                            case 'r': {
                              await removeReader(permission.key);
                              console.log('Removed reader: ', permission);
                              break;
                            }
                            case 'rw': {
                              // Writers keep an explicit reader row, so demote
                              // before revoking read access.
                              await removeWriter(
                                permission.key,
                                keepAnotherEditor,
                              );
                              await removeReader(permission.key);
                              console.log('Removed editor: ', permission);
                              break;
                            }
                            default: {
                              console.warn(
                                'Found unrecognized permission type: ',
                                permission,
                              );
                            }
                          }
                        } catch (error) {
                          alert(
                            error instanceof LastWriterRemovalError
                              ? lastEditorMessage
                              : 'Unable to remove this member. The document ' +
                                  'founder cannot be removed, and an editor ' +
                                  'must also hold reader access before ' +
                                  'demotion.',
                          );
                        }
                      })();
                    }}
                  >
                    Remove
                  </Button>
                </td>
              </tr>
            ))}
          {(!permissions || permissions.length === 0) && (
            <tr>
              <td colSpan={3}>No permissions defined!</td>
            </tr>
          )}
          <tr>
            <td>
              <Form.Control
                placeholder="Public Key to add"
                value={draftUserKey}
                onChange={(e) => setDraftUserKey(e.target.value)}
              />
              <Form.Control
                className="mt-2"
                placeholder="Member KEM public key"
                value={draftKemKey}
                onChange={(e) => setDraftKemKey(e.target.value)}
              />
            </td>
            <td>
              <Form.Control
                as="select"
                value={draftPermission}
                onChange={(e) =>
                  setDraftPermission(e.target.value as 'r' | 'rw')
                }
              >
                <option value="r">Reader</option>
                <option value="rw">Editor</option>
              </Form.Control>
            </td>
            <td>
              <Button
                variant="success"
                disabled={!docRef || kemReadyDocRef !== docRef}
                onClick={() => {
                  (async () => {
                    try {
                      const key = await deserializeKey(
                        {
                          name: 'ECDSA',
                          namedCurve: 'P-384',
                        },
                        ['verify'],
                      )(draftUserKey);
                      const kemPublicKey = decodeKemPublicKey(draftKemKey);
                      const serializedKey = await serializeKey(key);
                      const isMember = permissions.some(
                        (permission) => permission.publicKey === serializedKey,
                      );
                      if (!isMember && !kemPublicKey) {
                        alert(missingKemMessage);
                        return;
                      }

                      switch (draftPermission) {
                        case 'r': {
                          if (await isLastWriter(key, writers)) {
                            alert(lastEditorMessage);
                            return;
                          }
                          await addReader(key, kemPublicKey);
                          await removeWriter(key, keepAnotherEditor);
                          console.log('Added reader');
                          break;
                        }
                        case 'rw': {
                          await addReader(key, kemPublicKey);
                          await addWriter(key);
                          console.log('Added writer');
                          break;
                        }
                        default: {
                          console.warn(
                            'Found unrecognized permission type: ',
                            draftPermission,
                          );
                        }
                      }
                    } catch (error) {
                      if (error instanceof KemPublicKeyInputError) {
                        alert(error.message);
                        return;
                      }
                      alert(
                        error instanceof LastWriterRemovalError
                          ? lastEditorMessage
                          : 'Unable to update document permissions. Verify ' +
                              'both public keys and the membership ' +
                              'configuration. Promotion to editor requires ' +
                              "the member's KEM public key.",
                      );
                      return;
                    }
                  })();
                }}
              >
                Set role
              </Button>
            </td>
          </tr>
        </tbody>
      </Table>
    </>
  );
}
