import { generateEciesKeyPair } from '@peerborne/core';
import React from 'react';
import { Button, Container, Row, Form } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import { exportKey, importKey } from './utils';

export const passwordManagerNamespace = '/password-manager';

export function Login({
  setUserId,
  setPublicKey,
  setPrivateKey,
  setKemKeyPair,
  setBootstrapPeers,
}: {
  userId?: string;
  setUserId?: (userId: string) => void;
  publicKey?: CryptoKey;
  setPublicKey?: (publicKey: CryptoKey) => void;
  privateKey?: CryptoKey;
  setPrivateKey?: (privateKey: CryptoKey) => void;
  setKemKeyPair: (kemKeyPair: CryptoKeyPair) => void;
  bootstrapPeers?: string[];
  setBootstrapPeers?: (peers: string[]) => void;
}) {
  const navigate = useNavigate();
  const [generatedPrivateKey, setGeneratedPrivateKey] = React.useState<
    string | undefined
  >();
  const [generatedPublicKey, setGeneratedPublicKey] = React.useState<
    string | undefined
  >();
  const [generatedKemKeyPair, setGeneratedKemKeyPair] = React.useState<
    CryptoKeyPair | undefined
  >();
  const [draftBootstrapPeers, setDraftBootstrapPeers] = React.useState('');
  // Generate a keypair.
  React.useEffect(() => {
    console.log(`Calling <Login /> init effect`);
    (async () => {
      const keypair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-384',
        },
        true,
        ['sign', 'verify'],
      );
      // Secret documents seed BeeKEM leaf 0 with this P-256 ECDH key pair
      // before their first membership change.
      setGeneratedKemKeyPair(await generateEciesKeyPair());

      // Save these new generated keypairs.
      const exportedPrivateKey = await exportKey(keypair.privateKey);
      const exportedPublicKey = await exportKey(keypair.publicKey);
      setGeneratedPublicKey(exportedPublicKey);
      setGeneratedPrivateKey(exportedPrivateKey);
    })();

    return () => {
      // Nothing to cleanup.
    };
  }, []);

  const keysReady =
    !!generatedKemKeyPair && !!generatedPublicKey && !!generatedPrivateKey;

  return (
    <Container className="ml-auto mr-auto mt-5">
      <Row className="mt-5">
        {/* Allow user to enter a keypair */}
        <Form>
          <Form.Group className="mb-3" controlId="formBasicPrivateKey">
            <Form.Label>Private Key</Form.Label>
            <Form.Control
              type="password"
              placeholder="Enter private key"
              value={generatedPrivateKey || ''}
              onChange={(e) => setGeneratedPrivateKey(e.target.value)}
            />
            <Form.Text className="text-muted">
              We've auto-generated a key for you. Feel free to provide your own
              key (must be in JWK format).
            </Form.Text>
          </Form.Group>

          <Form.Group className="mb-3" controlId="formBasicPublicKey">
            <Form.Label>Public Key</Form.Label>
            <Form.Control
              as="textarea"
              rows={6}
              placeholder="Enter public key"
              value={generatedPublicKey || ''}
              onChange={(e) => setGeneratedPublicKey(e.target.value)}
            />
            <Form.Text className="text-muted">
              We've auto-generated a key for you. Feel free to provide your own
              key (must be in JWK format).
            </Form.Text>
          </Form.Group>

          <Form.Group className="mb-3" controlId="formBootstrapPeers">
            <Form.Label>Bootstrap Peers</Form.Label>
            <Form.Control
              as="textarea"
              rows={6}
              placeholder="Enter a list of (line separated) Peer IDs"
              value={draftBootstrapPeers || ''}
              onChange={(e) => setDraftBootstrapPeers(e.target.value)}
            />
          </Form.Group>

          <Button
            variant="primary"
            disabled={!keysReady}
            onClick={async () => {
              if (!keysReady) {
                return;
              }
              setKemKeyPair(generatedKemKeyPair);
              setPublicKey &&
                setPublicKey(await importKey(generatedPublicKey, ['verify']));
              setPrivateKey &&
                setPrivateKey(await importKey(generatedPrivateKey, ['sign']));
              setBootstrapPeers &&
                draftBootstrapPeers &&
                setBootstrapPeers(draftBootstrapPeers.split('\n'));
              setUserId && setUserId(btoa(generatedPublicKey));
              // Redirect to the /secrets page.
              navigate('/secrets');
            }}
          >
            Login
          </Button>
        </Form>
      </Row>
    </Container>
  );
}
