import React from 'react';
import {
  Alert,
  Button,
  ListGroup,
  Container,
  Col,
  Row,
  Form,
} from 'react-bootstrap';
import {
  useVaultDocumentState as usePeerborneDocumentState,
  type VaultSession,
} from './vault-session';
import * as uuid from 'uuid';
import { YjsPeerborne } from './utils';
import * as Y from 'yjs';
import { PasswordEditor } from './PasswordEditor';
import { useLocation } from 'react-router-dom';

export function PasswordVault({
  userId,
  peerborne,
  kemKeyPair,
  session,
}: {
  userId: string;
  peerborne: YjsPeerborne;
  kemKeyPair: CryptoKeyPair;
  session: VaultSession;
}) {
  const { pathname } = useLocation();
  const [selection, setSelection] = React.useState<{
    path: string;
    mode: 'open' | 'create';
  }>();
  return (
    <div hidden={pathname !== '/secrets'}>
      {selection ? (
        <PasswordList
          peerborne={peerborne}
          indexPath={selection.path}
          initialization={selection.mode}
          kemKeyPair={kemKeyPair}
          onLeave={() => setSelection(undefined)}
        />
      ) : (
        <div className="mt-3">
          <Button
            onClick={() =>
              setSelection({
                path: `/${encodeURIComponent(userId)}/vaults/${uuid.v4()}`,
                mode: 'create',
              })
            }
          >
            Create a vault
          </Button>
          <p className="mt-2 text-muted">
            Vaults are saved in this browser. Clearing site data removes access
            to them.
          </p>
          <ListGroup>
            {session.vaults.map((path, index) => (
              <ListGroup.Item key={path}>
                <Button
                  variant="outline-primary"
                  onClick={() => setSelection({ path, mode: 'open' })}
                >
                  Open vault {index + 1}
                </Button>
              </ListGroup.Item>
            ))}
          </ListGroup>
        </div>
      )}
    </div>
  );
}

export function PasswordList({
  indexPath,
  peerborne,
  kemKeyPair,
  onLeave,
  initialization,
}: {
  indexPath: string;
  peerborne: YjsPeerborne;
  kemKeyPair: CryptoKeyPair;
  onLeave: () => void;
  initialization: 'open' | 'create';
}) {
  const [currentPasswordId, setCurrentPasswordId] = React.useState<string>();
  const [viewedIds, setViewedIds] = React.useState<string[]>([]);
  const [createdIds, setCreatedIds] = React.useState<Set<string>>(new Set());
  const selectPassword = (id: string) => {
    setViewedIds((ids) => (ids.includes(id) ? ids : [...ids, id]));
    setCurrentPasswordId(id);
  };
  const [passwords, changePasswords, , activationError] =
    usePeerborneDocumentState(peerborne, indexPath, 'all', initialization);
  const [importingPassword, setImportingPassword] = React.useState(false);
  const [importPasswordId, setImportPasswordId] = React.useState('');
  const [importPasswordName, setImportPasswordName] = React.useState('');

  let importButtonDisabled: boolean = true;
  if (importPasswordId) {
    importButtonDisabled = false;
  }

  if (activationError) {
    return (
      <Alert variant="danger">
        Could not {initialization === 'create' ? 'create' : 'open'} this vault.
        Your saved data was left unchanged.{' '}
        <Button size="sm" variant="outline-danger" onClick={onLeave}>
          Choose another vault
        </Button>
      </Alert>
    );
  }

  return (
    <Container>
      <Button className="mt-3" variant="outline-secondary" onClick={onLeave}>
        Choose another vault
      </Button>
      <Row>
        <Col xs={6}>
          <Row className="mt-4" />
          <ListGroup defaultActiveKey="#link1">
            {passwords &&
              passwords.getArray<Y.Map<Y.Text>>('passwords').map((password) => {
                const idRef = password.get('id');
                const nameRef = password.get('name');
                const id = idRef && idRef.toString();
                const name = nameRef && nameRef.toString();
                return (
                  <ListGroup.Item
                    key={id}
                    action
                    onClick={() => {
                      if (id) selectPassword(id);
                    }}
                  >
                    {name || `Unnamed Secret (id: ${id})`}
                  </ListGroup.Item>
                );
              })}
          </ListGroup>
          <ListGroup variant="flush">
            <ListGroup.Item>
              <Button
                variant="primary"
                disabled={!passwords}
                onClick={() => {
                  const id = uuid.v4();
                  setCreatedIds((ids) => new Set([...ids, id]));
                  selectPassword(id);
                  changePasswords((current) => {
                    current.getArray<Y.Map<Y.Text>>('passwords').push([
                      new Y.Map<Y.Text>(
                        Object.entries({
                          id: new Y.Text(id),
                        }),
                      ),
                    ]);
                  });
                }}
              >
                New Secret
              </Button>{' '}
              {!importingPassword && (
                <Button
                  variant="success"
                  onClick={() => {
                    setImportingPassword(true);
                  }}
                >
                  Add Existing Secret
                </Button>
              )}
              {importingPassword && (
                <>
                  <Form.Control
                    aria-label="Secret ID"
                    placeholder="Enter a secret ID"
                    value={importPasswordId}
                    onChange={(e) => setImportPasswordId(e.target.value)}
                  ></Form.Control>
                  <Form.Control
                    aria-label="Secret name (optional)"
                    placeholder="Enter a name (optional)"
                    value={importPasswordName}
                    onChange={(e) => setImportPasswordName(e.target.value)}
                  ></Form.Control>
                  <Button
                    variant="success"
                    disabled={importButtonDisabled}
                    onClick={() => {
                      changePasswords((current) => {
                        current.getArray<Y.Map<Y.Text>>('passwords').push([
                          new Y.Map<Y.Text>(
                            Object.entries({
                              id: new Y.Text(importPasswordId),
                              name: new Y.Text(
                                importPasswordName || importPasswordId,
                              ),
                            }),
                          ),
                        ]);
                      });
                      setImportingPassword(false);
                      setImportPasswordId('');
                      setImportPasswordName('');
                    }}
                  >
                    Import
                  </Button>
                </>
              )}
            </ListGroup.Item>
          </ListGroup>
        </Col>
        <Col xs={6}>
          <Row className="mt-4" />

          {viewedIds.map((id) => (
            <div key={id} hidden={id !== currentPasswordId}>
              <PasswordEditor
                indexPath={indexPath}
                peerborne={peerborne}
                passwordId={id}
                initialization={createdIds.has(id) ? 'create' : 'open'}
                kemKeyPair={kemKeyPair}
              />
            </div>
          ))}
        </Col>
      </Row>
    </Container>
  );
}
