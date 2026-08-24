import { describe, expect, test, jest, beforeEach } from '@jest/globals';

const ucanAcl = require('./ucan-acl');
const UCANACLImpl = ucanAcl.UCANACL;
const UCANACLProviderImpl = ucanAcl.UCANACLProvider;

jest.mock('./ucan', () => ({ createUCAN: jest.fn() }));
const mockCreateUCAN = require('./ucan').createUCAN;

interface UCAN {
  version: '0.1.0';
  issuer: string;
  audience: string;
  capabilities: Array<{ resource: string; ability: string }>;
  expiration: number | null;
  notBefore: number | null;
  nonce: string;
  proofs: string[];
  signature: string;
}

function makeFakeUcan(overrides: Partial<UCAN> = {}): UCAN {
  return {
    version: '0.1.0',
    issuer: 'issuer-b64',
    audience: 'audience-b64',
    capabilities: [],
    expiration: null,
    notBefore: null,
    nonce: 'nonce-1',
    proofs: [],
    signature: 'base64sig',
    ...overrides,
  };
}

function makeMockAcl() {
  return {
    add: jest.fn(),
    remove: jest.fn(),
    current: jest.fn(),
    merge: jest.fn(),
    check: jest.fn(),
    users: jest.fn(),
  };
}

describe('UCANACL', () => {
  let backing: any;
  let acl: any;

  beforeEach(() => {
    backing = makeMockAcl();
    acl = new UCANACLImpl(backing, jest.fn(async (key: string) => `serialized:${key}`));
    mockCreateUCAN.mockReset();
  });

  test('add delegates to backing ACL', async () => {
    backing.add.mockResolvedValue('changes');
    const result = await acl.add('key1');
    expect(backing.add).toHaveBeenCalledWith('key1');
    expect(result).toBe('changes');
  });

  test('remove revokes access', async () => {
    backing.remove.mockResolvedValue('changes');
    await acl.remove('key1');
    const hasAccess = await acl.check('key1', '/doc/write');
    expect(hasAccess).toBe(false);
  });

  test('current delegates to backing ACL', () => {
    backing.current.mockReturnValue('current-state');
    expect(acl.current()).toBe('current-state');
  });

  test('merge delegates to backing ACL', () => {
    acl.merge('incoming-changes');
    expect(backing.merge).toHaveBeenCalledWith('incoming-changes');
  });

  test('check without capability delegates to backing ACL', async () => {
    backing.check.mockResolvedValue(true);
    const result = await acl.check('key1');
    expect(result).toBe(true);
  });

  test('check with capability falls back to backing ACL when no UCAN entry', async () => {
    backing.check.mockResolvedValue(true);
    const result = await acl.check('key1', '/doc/write');
    expect(result).toBe(true);
  });

  test('check with capability after grant respects capability hierarchy', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockResolvedValue('changes');

    await (acl.grant as any)('user1', '/doc/write', 'doc-1', {} as CryptoKey, 'issuer');

    const writeResult = await acl.check('user1', '/doc/write');
    expect(writeResult).toBe(true);
    const readResult = await acl.check('user1', '/doc/read');
    expect(readResult).toBe(true);
    const adminResult = await acl.check('user1', '/doc/admin');
    expect(adminResult).toBe(false);
  });

  test('users without capability delegates to backing ACL', async () => {
    backing.users.mockResolvedValue(['userA', 'userB']);
    const result = await acl.users();
    expect(result).toEqual(['userA', 'userB']);
  });

  test('grant creates UCAN and stores entry', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer-b64',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockResolvedValue('changes');

    await (acl.grant as any)('user1', '/doc/write', 'doc-1', {} as CryptoKey, 'issuer-b64', []);
    const entry = await acl.getEntry('user1');
    expect(entry).toBeDefined();
    expect(entry!.ucan).toBe(fakeUcan);
    expect(entry!.capabilities).toEqual(['/doc/write']);
    expect(entry!.revoked).toBe(false);
  });

  test('grant with epochId stores it', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer-b64',
      audience: 'serialized:user2',
      capabilities: [{ resource: 'doc-1', ability: '/doc/admin' }],
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockResolvedValue('changes');

    const epochId = new Uint8Array([10, 20, 30]);
    await (acl.grant as any)('user2', '/doc/admin', 'doc-1', {} as CryptoKey, 'issuer-b64', [], epochId);
    const entry = await acl.getEntry('user2');
    expect(entry!.epochId).toEqual(epochId);
  });

  test('revoke delegates to remove', async () => {
    backing.remove.mockResolvedValue('changes');
    const result = await acl.revoke('user1');
    expect(result).toBe('changes');
  });

  test('getEntry returns undefined for unknown user', async () => {
    const entry = await acl.getEntry('unknown');
    expect(entry).toBeUndefined();
  });

  test('getEntry returns entry after grant', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/read' }],
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockResolvedValue('changes');

    await (acl.grant as any)('user1', '/doc/read', 'doc-1', {} as CryptoKey, 'issuer');
    const entry = await acl.getEntry('user1');
    expect(entry!.publicKeyBase64).toBe('serialized:user1');
  });

  test('getEntry returns undefined after remove', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/read' }],
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockResolvedValue('changes');
    backing.remove.mockResolvedValue('changes-rm');

    await (acl.grant as any)('user1', '/doc/read', 'doc-1', {} as CryptoKey, 'issuer');
    await acl.remove('user1');
    const entry = await acl.getEntry('user1');
    expect(entry).toBeUndefined();
  });
});

describe('UCANACLProvider', () => {
  test('initialize creates a UCANACL with the backing ACL', () => {
    const mockBackingAclProvider = { initialize: jest.fn(() => makeMockAcl()) };
    const serializeKey = jest.fn(async (key: string) => `s:${key}`);
    const provider = new UCANACLProviderImpl(mockBackingAclProvider, serializeKey);
    const acl = provider.initialize();
    expect(acl).toBeInstanceOf(UCANACLImpl);
    expect(mockBackingAclProvider.initialize).toHaveBeenCalledTimes(1);
  });
});
