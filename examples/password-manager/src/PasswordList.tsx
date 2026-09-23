import React from 'react';
import { Button, ListGroup, Container, Col, Row, Form } from 'react-bootstrap';
import { usePeerborneDocumentState } from '@peerborne/react';
import * as uuid from 'uuid';
import { YjsPeerborne } from './utils';
import * as Y from 'yjs';
import { PasswordEditor } from './PasswordEditor';
import { useLocation } from 'react-router-dom';

export function PasswordVault({
  userId,
  peerborne,
}: {
  userId: string;
  peerborne: YjsPeerborne;
}) {
  const { pathname } = useLocation();
  const [indexPath, setIndexPath] = React.useState<string>();
  return (
    <div hidden={pathname !== '/secrets'}>
      {indexPath ? (
        <PasswordList peerborne={peerborne} indexPath={indexPath} />
      ) : (
        <Button onClick={() => setIndexPath(`/${userId}/vaults/${uuid.v4()}`)}>
          Create a vault
        </Button>
      )}
    </div>
  );
}

export function PasswordList({
  indexPath,
  peerborne,
}: {
  indexPath: string;
  peerborne: YjsPeerborne;
}) {
  const [currentPasswordId, setCurrentPasswordId] = React.useState<string>();
  const [viewedIds, setViewedIds] = React.useState<string[]>([]);
  const [createdIds, setCreatedIds] = React.useState<Set<string>>(new Set());
  const selectPassword = (id: string) => {
    setViewedIds((ids) => (ids.includes(id) ? ids : [...ids, id]));
    setCurrentPasswordId(id);
  };
  const [passwords, changePasswords] = usePeerborneDocumentState(
    peerborne,
    indexPath,
    'all',
    'create',
  );
  const [importingPassword, setImportingPassword] = React.useState(false);
  const [importPasswordId, setImportPasswordId] = React.useState('');
  const [importPasswordName, setImportPasswordName] = React.useState('');

  let importButtonDisabled: boolean = true;
  if (importPasswordId) {
    importButtonDisabled = false;
  }

  return (
    <Container>
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
              />
            </div>
          ))}
        </Col>
      </Row>
    </Container>
  );
}
