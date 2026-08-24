import React from 'react';
import { Button, ListGroup, Container, Col, Row, Form } from 'react-bootstrap';
import { usePeerborneDocumentState } from '@peerborne/react';
import * as uuid from 'uuid';
import { YjsPeerborne } from './utils';
import * as Y from 'yjs';
import { PasswordEditor } from './PasswordEditor';

export function PasswordList({
  userId,
  peerborne,
}: {
  userId: string;
  peerborne: YjsPeerborne;
}) {
  const [currentPassword, setCurrentPassword] = React.useState<
    Y.Map<Y.Text> | undefined
  >();
  const [passwords, changePasswords] = usePeerborneDocumentState(
    peerborne,
    `/${userId}/passwords-index`,
  );
  const [importingPassword, setImportingPassword] = React.useState(false);
  const [importPasswordId, setImportPasswordId] = React.useState('');
  const [importPasswordName, setImportPasswordName] = React.useState('');

  const currentPasswordIdRef = currentPassword && currentPassword.get('id');
  const currentPasswordId =
    currentPasswordIdRef && currentPasswordIdRef.toString();
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
              passwords
                .getArray<Y.Map<Y.Text>>('passwords')
                .map((password) => {
                  const idRef = password.get('id');
                  const nameRef = password.get('name');
                  const id = idRef && idRef.toString();
                  const name = nameRef && nameRef.toString();
                  return (
                    <ListGroup.Item
                      key={id}
                      action
                      onClick={() => setCurrentPassword(password)}
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
                onClick={() => {
                  changePasswords((current) => {
                    current.getArray<Y.Map<Y.Text>>('passwords').push([
                      new Y.Map<Y.Text>(
                        Object.entries({
                          id: new Y.Text(uuid.v4()),
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

          {currentPassword && (
            <PasswordEditor
              userId={userId}
              peerborne={peerborne}
              passwordId={currentPasswordId}
            />
          )}
        </Col>
      </Row>
    </Container>
  );
}
