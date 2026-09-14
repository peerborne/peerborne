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

  test('a successful local add clears a prior revocation tombstone', async () => {
    backing.remove.mockResolvedValue('remove-changes');
    backing.add.mockResolvedValue('add-changes');
    backing.check.mockResolvedValue(true);
    await acl.remove('key1');
    expect(await acl.check('key1', '/doc/read')).toBe(false);

    await acl.add('key1');

    expect(await acl.check('key1', '/doc/read')).toBe(true);
  });

  test('a failed local add preserves a prior revocation tombstone', async () => {
    backing.remove.mockResolvedValue('remove-changes');
    backing.add.mockRejectedValue(new Error('backing add failed'));
    backing.check.mockResolvedValue(true);
    await acl.remove('key1');

    await expect(acl.add('key1')).rejects.toThrow('backing add failed');
    expect(await acl.check('key1', '/doc/read')).toBe(false);
  });

  test('add commits a staged backing addition when available', async () => {
    const commit = jest.fn();
    backing.prepareAdd = jest.fn(async () => ({
      changes: 'staged-changes',
      commit,
    }));

    await expect(acl.add('key1')).resolves.toBe('staged-changes');

    expect(backing.prepareAdd).toHaveBeenCalledWith('key1');
    expect(commit).toHaveBeenCalledTimes(1);
    expect(backing.add).not.toHaveBeenCalled();
  });

  test('prepareAdd delegates without committing backing membership', async () => {
    const commit = jest.fn();
    backing.prepareAdd = jest.fn(async () => ({
      changes: 'staged-changes',
      commit,
    }));

    const prepared = await acl.prepareAdd('key1');

    expect(prepared.changes).toBe('staged-changes');
    expect(commit).not.toHaveBeenCalled();
    prepared.commit();
    expect(commit).toHaveBeenCalledTimes(1);
  });

  test('staged reauthorization clears a tombstone only after commit', async () => {
    backing.remove.mockResolvedValue('remove-changes');
    backing.check.mockResolvedValue(true);
    await acl.remove('key1');
    const commit = jest.fn();
    backing.prepareAdd = jest.fn(async () => ({
      changes: 'staged-changes',
      commit,
    }));

    const prepared = await acl.prepareAdd('key1');
    expect(await acl.check('key1', '/doc/read')).toBe(false);

    prepared.commit();

    expect(commit).toHaveBeenCalledTimes(1);
    expect(await acl.check('key1', '/doc/read')).toBe(true);
  });

  test('a rejected staged reauthorization preserves its tombstone', async () => {
    backing.remove.mockResolvedValue('remove-changes');
    backing.check.mockResolvedValue(true);
    await acl.remove('key1');
    backing.prepareAdd = jest.fn(async () => ({
      changes: 'staged-changes',
      commit: () => {
        throw new Error('stale backing ACL');
      },
    }));

    const prepared = await acl.prepareAdd('key1');
    expect(() => prepared.commit()).toThrow('stale backing ACL');
    expect(await acl.check('key1', '/doc/read')).toBe(false);
  });

  test('prepareAdd fails closed when the backing ACL lacks staging', async () => {
    await expect(acl.prepareAdd('key1')).rejects.toThrow(
      'Backing ACL does not support staged addition',
    );
    expect(backing.add).not.toHaveBeenCalled();
  });

  test('remove revokes access', async () => {
    backing.remove.mockResolvedValue('changes');
    await acl.remove('key1');
    const hasAccess = await acl.check('key1', '/doc/write');
    expect(hasAccess).toBe(false);
  });

  test('prepareRemove leaves UCAN state unchanged until backing commit', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
    });
    const commit = jest.fn();
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockResolvedValue('add-changes');
    backing.check.mockResolvedValue(true);
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'remove-changes',
      commit,
    }));
    await acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );

    const prepared = await acl.prepareRemove('user1');

    expect(prepared.changes).toBe('remove-changes');
    expect(await acl.getEntry('user1')).toBeDefined();
    expect(await acl.check('user1', '/doc/write')).toBe(true);

    prepared.commit();

    expect(commit).toHaveBeenCalledTimes(1);
    expect(await acl.getEntry('user1')).toBeUndefined();
    expect(await acl.check('user1', '/doc/write')).toBe(false);
  });

  test('prepareRemove leaves UCAN state unchanged when backing commit rejects', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockResolvedValue('add-changes');
    backing.check.mockResolvedValue(true);
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'remove-changes',
      commit: () => {
        throw new Error('stale backing ACL');
      },
    }));
    await acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    const prepared = await acl.prepareRemove('user1');

    expect(() => prepared.commit()).toThrow('stale backing ACL');

    expect(await acl.getEntry('user1')).toBeDefined();
    expect(await acl.check('user1', '/doc/write')).toBe(true);
  });

  test('prepareRemove fails closed when the backing ACL lacks staging', async () => {
    await expect(acl.prepareRemove('user1')).rejects.toThrow(
      'Backing ACL does not support staged removal',
    );
    expect(backing.remove).not.toHaveBeenCalled();
  });

  test('legacy backing removal failure leaves UCAN state unchanged', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockResolvedValue('add-changes');
    backing.check.mockResolvedValue(true);
    backing.remove.mockRejectedValue(new Error('legacy removal failed'));
    await acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );

    await expect(acl.remove('user1')).rejects.toThrow(
      'legacy removal failed',
    );

    expect(await acl.getEntry('user1')).toBeDefined();
    expect(await acl.check('user1', '/doc/write')).toBe(true);
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
    backing.check.mockResolvedValue(true);

    await (acl.grant as any)('user1', '/doc/write', 'doc-1', {} as CryptoKey, 'issuer');

    const writeResult = await acl.check('user1', '/doc/write');
    expect(writeResult).toBe(true);
    const readResult = await acl.check('user1', '/doc/read');
    expect(readResult).toBe(true);
    const adminResult = await acl.check('user1', '/doc/admin');
    expect(adminResult).toBe(false);
  });

  test('grant stays unavailable until the backing ACL addition succeeds', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
    });
    let resolveAdd!: (changes: string) => void;
    const addPending = new Promise<string>((resolve) => {
      resolveAdd = resolve;
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockReturnValue(addPending);
    // Model a backing ACL that mutates membership before its Promise settles.
    backing.check.mockResolvedValue(true);

    const grant = acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    await Promise.resolve();
    await Promise.resolve();

    await expect(
      acl.grant(
        'user1',
        '/doc/read',
        'doc-1',
        {} as CryptoKey,
        'issuer',
      ),
    ).rejects.toThrow('already in progress');
    expect(await acl.check('user1', '/doc/write')).toBe(false);
    expect(await acl.getEntry('user1')).toBeUndefined();

    resolveAdd('changes');
    await expect(grant).resolves.toBe('changes');
    expect(await acl.check('user1', '/doc/write')).toBe(true);
  });

  test('a rejected backing ACL addition does not install a capability', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockRejectedValue(new Error('backing add failed'));
    backing.check.mockResolvedValue(false);

    await expect(
      acl.grant(
        'user1',
        '/doc/write',
        'doc-1',
        {} as CryptoKey,
        'issuer',
      ),
    ).rejects.toThrow('backing add failed');

    expect(await acl.getEntry('user1')).toBeUndefined();
    expect(await acl.check('user1', '/doc/write')).toBe(false);
  });

  test('a successful grant clears a prior revocation tombstone', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.remove.mockResolvedValue('remove-changes');
    backing.add.mockResolvedValue('add-changes');
    backing.check.mockResolvedValue(true);
    await acl.remove('user1');

    await acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );

    expect(await acl.check('user1', '/doc/write')).toBe(true);
  });

  test('a remote backing removal disables a cached capability entry', async () => {
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
    });
    let isMember = true;
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockResolvedValue('changes');
    backing.check.mockImplementation(async () => isMember);
    backing.merge.mockImplementation(() => {
      isMember = false;
    });
    await acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    expect(await acl.check('user1', '/doc/write')).toBe(true);

    acl.merge('remote-removal');

    expect(await acl.getEntry('user1')).toBeDefined();
    expect(await acl.check('user1', '/doc/write')).toBe(false);
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
    expect(entry!.ucan).toEqual(fakeUcan);
    expect(entry!.ucan).not.toBe(fakeUcan);
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

  test('grant storage and getEntry results are detached from mutable input', async () => {
    const tokenCapabilities = [
      { resource: 'doc-1', ability: '/doc/write' },
    ];
    const proofs = ['proof-1'];
    const fakeUcan = makeFakeUcan({
      issuer: 'issuer',
      audience: 'serialized:user1',
      capabilities: tokenCapabilities,
      proofs,
    });
    const epochId = new Uint8Array([10, 20, 30]);
    let resolveAdd!: (changes: string) => void;
    const addPending = new Promise<string>((resolve) => {
      resolveAdd = resolve;
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockReturnValue(addPending);
    backing.check.mockResolvedValue(true);

    const grant = acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
      proofs,
      epochId,
    );
    await Promise.resolve();
    await Promise.resolve();

    tokenCapabilities[0]!.ability = '/doc/admin';
    proofs.push('proof-2');
    epochId[0] = 255;
    resolveAdd('changes');
    await grant;

    const first = await acl.getEntry('user1');
    first!.capabilities[0] = '/doc/admin';
    first!.ucan.capabilities[0]!.ability = '/doc/admin';
    first!.ucan.proofs.push('proof-3');
    first!.epochId![1] = 255;

    const second = await acl.getEntry('user1');
    expect(second!.capabilities).toEqual(['/doc/write']);
    expect(second!.ucan.capabilities).toEqual([
      { resource: 'doc-1', ability: '/doc/write' },
    ]);
    expect(second!.ucan.proofs).toEqual(['proof-1']);
    expect(second!.epochId).toEqual(new Uint8Array([10, 20, 30]));
    expect(await acl.check('user1', '/doc/admin')).toBe(false);
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
