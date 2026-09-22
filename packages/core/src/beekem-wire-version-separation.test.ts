import { describe, expect, test } from '@jest/globals';
import * as protocols from './wire-protocols.js';
import { welcomeFixture, pathUpdateFixture } from './__mocks__/beekem-v2.js';
import { serializeBeeKEMWelcomeV2ForWire, deserializeBeeKEMWelcomeV2FromWire } from './beekem-welcome-wire.js';
import { serializePathUpdateV2ForWire, deserializePathUpdateV2FromWire } from './path-update-wire.js';

describe('BeeKEM current wire version', () => {
  test('exports only the current Welcome and PathUpdate protocols', () => {
    expect(Object.keys(protocols).filter((key) => key.startsWith('beekem')).sort())
      .toEqual(['beekemPathUpdateV2', 'beekemWelcomeV2']);
  });

  test.each([undefined, 1, 3])('rejects unsupported version %s before encoding or decoding', (version) => {
    const welcome = welcomeFixture();
    const update = pathUpdateFixture();
    const welcomeWire = serializeBeeKEMWelcomeV2ForWire(welcome);
    const updateWire = serializePathUpdateV2ForWire(update);
    expect(() => serializeBeeKEMWelcomeV2ForWire({ ...welcome, version } as never)).toThrow(/version/);
    expect(() => deserializeBeeKEMWelcomeV2FromWire({ ...welcomeWire, version })).toThrow(/version/);
    expect(() => serializePathUpdateV2ForWire({ ...update, version } as never)).toThrow(/version/);
    expect(() => deserializePathUpdateV2FromWire({ ...updateWire, version })).toThrow(/version/);
  });

  test('rejects the obsolete path ciphertext field', () => {
    const wire = serializePathUpdateV2ForWire(pathUpdateFixture());
    const obsolete = { ...wire, nodes: [{ ...wire.nodes[0], encryptedPrivateKey: 'AQ==' }] };
    expect(() => deserializePathUpdateV2FromWire(obsolete)).toThrow(/unexpected field/);
  });
});
