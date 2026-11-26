import { LastWriterRemovalError } from '@peerborne/core';
import { useVaultDocumentState as usePeerborneDocumentState } from './vault-session';
import { deserializeKey, serializeKey } from '@peerborne/yjs';
import { useEffect, useState } from 'react';
import { Button, Form, Table } from 'react-bootstrap';
import { YjsPeerborne } from './utils';

type DisplayPermission = {
  key: CryptoKey;
  publicKey: string; // id
  permissions: 'r' | 'rw';
};

const lastEditorMessage =
  'The last editor cannot be demoted or removed. Add another editor first.';
const newMemberMessage =
  'This example cannot add a new member: a member added directly could ' +
  'never open the secret. Sharing needs an invitation, which this Yjs ' +
  'example does not support.';
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
    { readers, removeReader, writers, addWriter, removeWriter, docRef },
  ] = usePeerborneDocumentState(peerborne, documentPath);
  const [kemReadyDocRef, setKemReadyDocRef] = useState<typeof docRef>();
  const [permissions, setPermissions] = useState<DisplayPermission[]>([]);
  const [draftUserKey, setDraftUserKey] = useState('');
  const [draftPermission, setDraftPermission] = useState<'r' | 'rw'>('r');

  // Role changes run against BeeKEM membership state, so install the
  // identity's KEM key pair once per document before any change.
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
        Enter an existing member's signing public key, base64, to change their
        role. This example cannot add members: a member added directly with
        addReader could never open the secret, and sharing needs the invitation
        API, which requires the Automerge provider profile that this Yjs example
        does not use.
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
                <td>{permission.permissions === 'rw' ? 'Editor' : 'Reader'}</td>
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
                placeholder="Existing member's public key"
                value={draftUserKey}
                onChange={(e) => setDraftUserKey(e.target.value)}
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
                      const serializedKey = await serializeKey(key);
                      const current = permissions.find(
                        (permission) => permission.publicKey === serializedKey,
                      );
                      if (!current) {
                        alert(newMemberMessage);
                        return;
                      }

                      switch (draftPermission) {
                        case 'r': {
                          if (current.permissions === 'rw') {
                            if (await isLastWriter(key, writers)) {
                              alert(lastEditorMessage);
                              return;
                            }
                            await removeWriter(key, keepAnotherEditor);
                          }
                          console.log('Set reader');
                          break;
                        }
                        case 'rw': {
                          if (current.permissions !== 'rw') {
                            await addWriter(key);
                          }
                          console.log('Set editor');
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
                      alert(
                        error instanceof LastWriterRemovalError
                          ? lastEditorMessage
                          : 'Unable to update document permissions. Verify ' +
                              'the public key and the membership ' +
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
