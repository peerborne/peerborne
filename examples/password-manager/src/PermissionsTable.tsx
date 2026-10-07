import { LastWriterRemovalError } from '@peerborne/core';
import { PeerborneContext, usePeerborneDocumentState } from '@peerborne/react';
import { deserializeKey, serializeKey } from '@peerborne/yjs';
import { useContext, useEffect, useState } from 'react';
import { Button, Form, Table } from 'react-bootstrap';
import {
  decodeKemPublicKey,
  KemPublicKeyInputError,
  YjsPeerborne,
} from './utils';

type DisplayPermission = {
  key: CryptoKey;
  publicKey: string; // id
  permissions: 'r' | 'rw';
};

const lastEditorMessage =
  'The last editor cannot be demoted or removed. Add another editor first.';
const missingKemMessage =
  "Enter the new member's KEM public key from their Settings page.";
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
        Enter the new member's signing public key and the raw P-256 ECDH KEM
        public key from their Settings page, both base64. Adding a member gives
        them a BeeKEM leaf and sends a Welcome sealed to their KEM public key.
        An existing member's role can change without a KEM key. This example
        has no flow for the new member to open a shared secret; use the
        invitation API for that.
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
                aria-label="Member signing public key"
                placeholder="Public Key to add"
                value={draftUserKey}
                onChange={(e) => setDraftUserKey(e.target.value)}
              />
              <Form.Control
                className="mt-2"
                aria-label="Member KEM public key"
                placeholder="Member KEM public key"
                value={draftKemKey}
                onChange={(e) => setDraftKemKey(e.target.value)}
              />
            </td>
            <td>
              <Form.Control
                as="select"
                aria-label="Member role"
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
                      const kemKey = draftKemKey.trim();
                      const kemPublicKey = kemKey
                        ? decodeKemPublicKey(kemKey)
                        : undefined;
                      const serializedKey = await serializeKey(key);
                      const current = permissions.find(
                        (permission) => permission.publicKey === serializedKey,
                      );
                      // Writers keep their reader row, so only a new member
                      // requires a KEM public key. Entering it for an existing
                      // member retries their onboarding, which resends the
                      // Welcome sealed to that key.
                      if (!current && !kemPublicKey) {
                        alert(missingKemMessage);
                        return;
                      }
                      const onboardReader = async () => {
                        if (kemPublicKey) await addReader(key, kemPublicKey);
                      };

                      switch (draftPermission) {
                        case 'r': {
                          if (current?.permissions === 'rw') {
                            if (await isLastWriter(key, writers)) {
                              alert(lastEditorMessage);
                              return;
                            }
                            await removeWriter(key, keepAnotherEditor);
                          } else {
                            await onboardReader();
                          }
                          console.log('Added reader');
                          break;
                        }
                        case 'rw': {
                          await onboardReader();
                          if (current?.permissions !== 'rw') {
                            await addWriter(key);
                          }
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
                              'configuration.',
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
