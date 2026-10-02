import { LastWriterRemovalError } from '@peerborne/core';
import { usePeerborneDocumentState } from '@peerborne/react';
import { deserializeKey, serializeKey } from '@peerborne/yjs';
import { useContext, useEffect, useState } from 'react';
import { Button, Form, Table } from 'react-bootstrap';
import { decodeKemPublicKey, KemKeyPairContext, YjsPeerborne } from './utils';

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
}: {
  passwordId?: string;
  peerborne: YjsPeerborne;
}) {
  const [
    ,
    ,
    {
      readers,
      addReader,
      removeReader,
      writers,
      addWriter,
      removeWriter,
      setKemKeyPair,
    },
  ] = usePeerborneDocumentState(peerborne, `/passwords/${passwordId}`);
  const kemKeyPair = useContext(KemKeyPairContext);
  const [permissions, setPermissions] = useState<DisplayPermission[]>([]);
  const [draftUserKey, setDraftUserKey] = useState('');
  const [draftKemKey, setDraftKemKey] = useState('');
  const [draftPermission, setDraftPermission] = useState<'r' | 'rw'>('r');

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
        Adding a member sends a BeeKEM Welcome sealed to their KEM public key.
        This example has no flow for the new member to open a shared secret;
        use the invitation API for that.
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
                placeholder="KEM Public Key of a new member"
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
                      // Writers keep their reader row, so only a new member
                      // needs reader onboarding with a KEM public key.
                      const onboardReader = async () => {
                        if (current) return true;
                        if (!draftKemKey.trim() || !kemKeyPair) {
                          alert(missingKemMessage);
                          return false;
                        }
                        await setKemKeyPair(kemKeyPair);
                        await addReader(key, decodeKemPublicKey(draftKemKey));
                        return true;
                      };

                      switch (draftPermission) {
                        case 'r': {
                          if (current?.permissions === 'rw') {
                            if (await isLastWriter(key, writers)) {
                              alert(lastEditorMessage);
                              return;
                            }
                            await removeWriter(key, keepAnotherEditor);
                          } else if (!(await onboardReader())) {
                            return;
                          }
                          console.log('Added reader');
                          break;
                        }
                        case 'rw': {
                          if (!(await onboardReader())) return;
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
                      alert(
                        error instanceof LastWriterRemovalError
                          ? lastEditorMessage
                          : 'Unable to update document permissions. Verify ' +
                              'the public key and membership configuration.',
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
