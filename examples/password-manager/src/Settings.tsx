import { useEffect, useState } from 'react';
import { Button, Table, Row, Container } from 'react-bootstrap';
import { encodeKemPublicKey, YjsPeerborne } from './utils';
import { serializeKey } from '@peerborne/yjs';

function KeyCell({children}: {children?: React.ReactNode}) {
  return <td>
    {children}
  </td>;
}

function ValueCell({children}: {children?: React.ReactNode}) {
  return <td style={{ wordBreak: 'break-all' }}>
    {children}
  </td>;
}

function ActionCell({value}: {value: string}) {
  return <td>
    <Button
      variant="secondary"
      onClick={async () => {
        await navigator.clipboard.writeText(
          String(value),
        );
      }}
    >
      Copy
    </Button>
  </td>;
}

export function Settings({
  peerborne,
  publicKey,
  kemKeyPair,
}: {
  peerborne: YjsPeerborne;
  publicKey?: CryptoKey;
  kemKeyPair?: CryptoKeyPair;
}) {
  const [serializedKey, setSerializedKey] = useState<string | undefined>();
  const [kemPublicKey, setKemPublicKey] = useState<string | undefined>();

  useEffect(() => {
    (async () => {
      if (!publicKey) {
        return;
      }
      setSerializedKey(await serializeKey(publicKey));
    })();
  }, [publicKey]);

  useEffect(() => {
    let active = true;
    setKemPublicKey(undefined);
    if (kemKeyPair) {
      void crypto.subtle
        .exportKey('raw', kemKeyPair.publicKey)
        .then((raw) => {
          if (active) setKemPublicKey(encodeKemPublicKey(new Uint8Array(raw)));
        });
    }
    return () => {
      active = false;
    };
  }, [kemKeyPair]);

  return (
    <Container className="ml-auto mr-auto mt-5">
      <Row className="mt-5">
        <Table striped bordered hover responsive>
          <thead>
            <tr>
              <th>Item</th>
              <th colSpan={2}>Value</th>
            </tr>
          </thead>
          <tbody>
            {peerborne.libp2p.getMultiaddrs().map((addr, i) => <tr key={addr.toString()}>
              <KeyCell>Address {i+1}</KeyCell>
              <ValueCell>{addr.toString()}</ValueCell>
              <ActionCell value={addr.toString()}></ActionCell>
            </tr>)}
            {serializedKey && <tr>
              <KeyCell>Public Key</KeyCell>
              <ValueCell>{serializedKey}</ValueCell>
              <ActionCell value={serializedKey}></ActionCell>
            </tr>}
            {kemPublicKey && <tr>
              <KeyCell>KEM Public Key</KeyCell>
              <ValueCell>{kemPublicKey}</ValueCell>
              <ActionCell value={kemPublicKey}></ActionCell>
            </tr>}

            {!serializedKey && (peerborne.libp2p.getMultiaddrs().length === 0) && (
              <tr>
                <td colSpan={3}>No settings found!</td>
              </tr>
            )}
          </tbody>
        </Table>
      </Row>
    </Container>
  );
}
