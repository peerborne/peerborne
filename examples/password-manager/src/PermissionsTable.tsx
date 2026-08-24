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
      <Table striped bordered hover>
        <thead>
          <tr>
            <th>User</th>
            <th colSpan={2}>Permisssions</th>
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
                  {permission.permissions === 'rw' ? 'Read/Write' : 'Read'}
                </td>
                <td>
                  <Button
                    variant="danger"
                    onClick={() => {
                      switch (permission.permissions) {
                        case 'r': {
                          removeReader(permission.key).then(() =>
                            console.log('Removed reader: ', permission),
                          );
                          break;
                        }
                        case 'rw': {
                          removeWriter(permission.key).then(() =>
                            console.log('Removed writer: ', permission),
                          );
                          break;
                        }
                        default: {
                          console.warn(
                            'Found unrecognized permission type: ',
                            permission,
                          );
                        }
                      }
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
                <option value="r">Read</option>
                <option value="rw">Read/Write</option>
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
                          addReader(key).then(() =>
                            console.log('Added reader: ', draftUserKey),
                          );
                          break;
                        }
                        case 'rw': {
                          addWriter(key).then(() =>
                            console.log('Added writer: ', draftUserKey),
                          );
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
                        `The entered key: "${draftUserKey}" is not a valid User public key!`,
                      );
                      return;
                    }
                  })();
                }}
              >
                Add
              </Button>
            </td>
          </tr>
        </tbody>
      </Table>
    </>
  );
}
