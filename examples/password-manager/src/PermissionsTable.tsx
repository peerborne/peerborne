import { usePeerborneDocumentState } from '@peerborne/react';
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
    { readers, addReader, removeReader, writers, addWriter, removeWriter },
  ] = usePeerborneDocumentState(peerborne, `/passwords/${passwordId}`);
  const [permissions, setPermissions] = useState<DisplayPermission[]>([]);
  const [draftUserKey, setDraftUserKey] = useState('');
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
        These controls change authorization roles only. This example does not
        deliver the encryption keys a new member needs to open the document.
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
                              if (await isLastWriter(permission.key, writers)) {
                                alert(lastEditorMessage);
                                return;
                              }
                              // Writers keep an explicit reader row, so demote
                              // before revoking read access.
                              await removeWriter(permission.key);
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
                        } catch {
                          alert(
                            'Unable to remove this member. The document ' +
                              'founder cannot be removed, and an editor must ' +
                              'also hold reader access before demotion.',
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

                      switch (draftPermission) {
                        case 'r': {
                          if (await isLastWriter(key, writers)) {
                            alert(lastEditorMessage);
                            return;
                          }
                          await addReader(key);
                          await removeWriter(key);
                          console.log('Added reader');
                          break;
                        }
                        case 'rw': {
                          await addReader(key);
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
                    } catch {
                      alert(
                        'Unable to update document permissions. Verify the ' +
                          'public key and membership configuration.',
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
