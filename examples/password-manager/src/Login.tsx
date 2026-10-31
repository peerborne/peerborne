import React from 'react';
import { Alert, Button, Container, Form } from 'react-bootstrap';
import { serializeKey } from '@peerborne/yjs';
import { getBrowserIdentity, type BrowserIdentity } from './vault-store';

export function Login({
  onLogin,
}: {
  onLogin: (identity: BrowserIdentity, peers: string[]) => Promise<void>;
}) {
  const [identity, setIdentity] = React.useState<BrowserIdentity>();
  const [publicKey, setPublicKey] = React.useState('');
  const [peers, setPeers] = React.useState('');
  const [error, setError] = React.useState<string>();
  const [busy, setBusy] = React.useState(false);
  React.useEffect(() => {
    let active = true;
    void getBrowserIdentity()
      .then(async (value) => {
        const key = await serializeKey(value.signing.publicKey);
        if (active) {
          setIdentity(value);
          setPublicKey(key);
        }
      })
      .catch(() => {
        if (active)
          setError(
            'Could not restore the browser identity. Existing vaults were left unchanged.',
          );
      });
    return () => {
      active = false;
    };
  }, []);
  return (
    <Container className="mt-5">
      <p>
        Your identity and encrypted vaults are saved in this browser. Clearing
        site data removes access to them. Login uses the browser identity; it
        does not provide a password lock or a backup.
      </p>
      {error && <Alert variant="danger">{error}</Alert>}
      <Form
        onSubmit={(event) => {
          event.preventDefault();
          if (!identity || busy) return;
          setBusy(true);
          void onLogin(
            identity,
            peers
              .split('\n')
              .map((value) => value.trim())
              .filter(Boolean),
          )
            .catch((error) =>
              setError(
                error instanceof Error
                  ? error.message
                  : 'Could not start the vault session. Your saved data was left unchanged.',
              ),
            )
            .finally(() => setBusy(false));
        }}
      >
        <Form.Group className="mb-3" controlId="browser-public-key">
          <Form.Label>Public Key</Form.Label>
          <Form.Control as="textarea" rows={3} value={publicKey} readOnly />
        </Form.Group>
        <Form.Group className="mb-3" controlId="bootstrap-peers">
          <Form.Label>Bootstrap Peers</Form.Label>
          <Form.Control
            as="textarea"
            value={peers}
            onChange={(event) => setPeers(event.target.value)}
            placeholder="Optional peer addresses, one per line"
          />
        </Form.Group>
        <Button type="submit" disabled={!identity || busy}>
          {busy ? 'Opening…' : 'Login'}
        </Button>
      </Form>
    </Container>
  );
}
