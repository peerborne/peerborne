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

  test('quarantines a partially applied failed add until an explicit retry succeeds', async () => {
    let isMember = false;
    let addStarted!: () => void;
    const addWasStarted = new Promise<void>((resolve) => {
      addStarted = resolve;
    });
    let rejectAdd!: (error: Error) => void;
    const pendingAdd = new Promise<string>((_resolve, reject) => {
      rejectAdd = reject;
    });
    backing.add
      .mockImplementationOnce(() => {
        isMember = true;
        addStarted();
        return pendingAdd;
      })
      .mockImplementationOnce(async () => {
        isMember = true;
        return 'recovery-changes';
      });
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () =>
      isMember ? ['key1'] : [],
    );
    backing.current.mockReturnValue('current-state');

    const addition = acl.add('key1');
    await addWasStarted;
    await expect(acl.check('key1')).resolves.toBe(false);
    await expect(acl.check('key1', '/doc/read')).resolves.toBe(false);
    await expect(acl.users()).resolves.toEqual([]);
    expect(() => acl.current()).toThrow(/backing addition is quarantined/);

    rejectAdd(new Error('backing add failed after mutation'));
    await expect(addition).rejects.toThrow(
      'backing add failed after mutation',
    );
    await expect(acl.check('key1')).resolves.toBe(false);
    await expect(acl.check('key1', '/doc/read')).resolves.toBe(false);
    await expect(acl.users()).resolves.toEqual([]);
    expect(() => acl.current()).toThrow(/backing addition is quarantined/);

    await expect(acl.add('key1')).resolves.toBe('recovery-changes');
    await expect(acl.check('key1')).resolves.toBe(true);
    await expect(acl.check('key1', '/doc/read')).resolves.toBe(true);
    await expect(acl.users()).resolves.toEqual(['key1']);
    expect(acl.current()).toBe('current-state');
  });

  test('orders a removal after an in-flight addition', async () => {
    let resolveAdd!: (changes: string) => void;
    const pendingAdd = new Promise<string>((resolve) => {
      resolveAdd = resolve;
    });
    let addStarted!: () => void;
    const addWasStarted = new Promise<void>((resolve) => {
      addStarted = resolve;
    });
    let isMember = false;
    backing.add.mockImplementation(async () => {
      addStarted();
      const changes = await pendingAdd;
      isMember = true;
      return changes;
    });
    backing.remove.mockImplementation(async () => {
      isMember = false;
      return 'remove-changes';
    });
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () =>
      isMember ? ['key1'] : [],
    );

    const add = acl.add('key1');
    await addWasStarted;
    const remove = acl.remove('key1');
    await Promise.resolve();
    expect(backing.remove).not.toHaveBeenCalled();
    resolveAdd('add-changes');

    await expect(add).resolves.toBe('add-changes');
    await expect(remove).resolves.toBe('remove-changes');
    expect(await acl.check('key1')).toBe(false);
    expect(await acl.check('key1', '/doc/read')).toBe(false);
    expect(await acl.users()).toEqual([]);
  });

  test('orders add then remove when codec promises resolve out of order', async () => {
    let resolveFirstSerialization!: (serialized: string) => void;
    const firstSerialization = new Promise<string>((resolve) => {
      resolveFirstSerialization = resolve;
    });
    let serializationCall = 0;
    const serialize = jest.fn((key: string) => {
      serializationCall++;
      return serializationCall === 1
        ? firstSerialization
        : Promise.resolve(`serialized:${key}`);
    });
    const orderedAcl = new UCANACLImpl(backing, serialize);
    const events: string[] = [];
    const members = new Set<string>();
    backing.add.mockImplementation(async (key: string) => {
      events.push(`add:${key}`);
      members.add(key);
      return 'add-changes';
    });
    backing.remove.mockImplementation(async (key: string) => {
      events.push(`remove:${key}`);
      members.delete(key);
      return 'remove-changes';
    });
    backing.check.mockImplementation(async (key: string) => members.has(key));
    backing.users.mockImplementation(async () => [...members]);

    const addition = orderedAcl.add('key1');
    const removal = orderedAcl.remove('key1');
    await Promise.resolve();

    expect(serialize).toHaveBeenCalledTimes(2);
    expect(backing.add).not.toHaveBeenCalled();
    expect(backing.remove).not.toHaveBeenCalled();

    resolveFirstSerialization('serialized:key1');
    await expect(addition).resolves.toBe('add-changes');
    await expect(removal).resolves.toBe('remove-changes');
    expect(events).toEqual(['add:key1', 'remove:key1']);
    expect(await orderedAcl.check('key1')).toBe(false);
    expect(await orderedAcl.users()).toEqual([]);
  });

  test('releases codec admission after a rejected snapshot', async () => {
    const serialize = jest
      .fn()
      .mockRejectedValueOnce(new Error('invalid identity'))
      .mockResolvedValueOnce('serialized:key2');
    const orderedAcl = new UCANACLImpl(backing, serialize);
    backing.add.mockResolvedValue('add-changes');

    const rejected = orderedAcl.add('key1');
    const accepted = orderedAcl.add('key2');

    await expect(rejected).rejects.toThrow('invalid identity');
    await expect(accepted).resolves.toBe('add-changes');
    expect(backing.add).toHaveBeenCalledTimes(1);
    expect(backing.add).toHaveBeenCalledWith('key2');
    expect(() => orderedAcl.merge('remote-changes')).not.toThrow();
  });

  test('serializes backing mutations for different identities', async () => {
    let resolveFirstAdd!: (changes: string) => void;
    const firstAdd = new Promise<string>((resolve) => {
      resolveFirstAdd = resolve;
    });
    let firstAddStarted!: () => void;
    const firstWasStarted = new Promise<void>((resolve) => {
      firstAddStarted = resolve;
    });
    const started: string[] = [];
    backing.add.mockImplementation((key: string) => {
      started.push(key);
      if (key === 'key1') firstAddStarted();
      return key === 'key1' ? firstAdd : Promise.resolve('second-changes');
    });

    const first = acl.add('key1');
    const second = acl.add('key2');
    await firstWasStarted;

    expect(started).toEqual(['key1']);
    resolveFirstAdd('first-changes');
    await expect(first).resolves.toBe('first-changes');
    await expect(second).resolves.toBe('second-changes');
    expect(started).toEqual(['key1', 'key2']);
  });

  test('releases the global mutation queue after a backing failure', async () => {
    backing.add
      .mockRejectedValueOnce(new Error('first add failed'))
      .mockResolvedValueOnce('second-changes');

    const first = acl.add('key1');
    const second = acl.add('key2');

    await expect(first).rejects.toThrow('first add failed');
    await expect(second).resolves.toBe('second-changes');
    expect(backing.add).toHaveBeenNthCalledWith(1, 'key1');
    expect(backing.add).toHaveBeenNthCalledWith(2, 'key2');
    expect(() => acl.merge('remote-changes')).not.toThrow();
  });

  test('remove revokes access', async () => {
    backing.remove.mockResolvedValue('changes');
    await acl.remove('key1');
    const hasAccess = await acl.check('key1', '/doc/write');
    expect(hasAccess).toBe(false);
  });

  test('denies checks and user listings while backing removal is pending', async () => {
    let removalStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      removalStarted = resolve;
    });
    let resolveRemoval!: (changes: string) => void;
    const pendingRemoval = new Promise<string>((resolve) => {
      resolveRemoval = resolve;
    });
    backing.remove.mockImplementation(() => {
      removalStarted();
      return pendingRemoval;
    });
    backing.check.mockResolvedValue(true);
    backing.users.mockResolvedValue(['key1']);

    const removal = acl.remove('key1');
    await started;

    await expect(acl.check('key1')).resolves.toBe(false);
    await expect(acl.check('key1', '/doc/read')).resolves.toBe(false);
    await expect(acl.users()).resolves.toEqual([]);
    await expect(acl.users('/doc/read')).resolves.toEqual([]);
    expect(backing.check).not.toHaveBeenCalled();

    resolveRemoval('changes');
    await expect(removal).resolves.toBe('changes');
    await expect(acl.check('key1')).resolves.toBe(false);
  });

  test('denies an in-flight check when removal starts during its backing await', async () => {
    let checkStarted!: () => void;
    const checkWasStarted = new Promise<void>((resolve) => {
      checkStarted = resolve;
    });
    let resolveCheck!: (allowed: boolean) => void;
    const pendingCheck = new Promise<boolean>((resolve) => {
      resolveCheck = resolve;
    });
    let removalStarted!: () => void;
    const removalWasStarted = new Promise<void>((resolve) => {
      removalStarted = resolve;
    });
    let resolveRemoval!: (changes: string) => void;
    const pendingRemoval = new Promise<string>((resolve) => {
      resolveRemoval = resolve;
    });
    backing.check.mockImplementation(() => {
      checkStarted();
      return pendingCheck;
    });
    backing.remove.mockImplementation(() => {
      removalStarted();
      return pendingRemoval;
    });

    const authorization = acl.check('key1');
    await checkWasStarted;
    const removal = acl.remove('key1');
    await removalWasStarted;

    resolveCheck(true);
    await expect(authorization).resolves.toBe(false);

    resolveRemoval('changes');
    await expect(removal).resolves.toBe('changes');
  });

  test('restores access after a pending backing removal fails', async () => {
    let removalStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      removalStarted = resolve;
    });
    let rejectRemoval!: (error: Error) => void;
    const pendingRemoval = new Promise<string>((_resolve, reject) => {
      rejectRemoval = reject;
    });
    backing.remove.mockImplementation(() => {
      removalStarted();
      return pendingRemoval;
    });
    backing.check.mockResolvedValue(true);
    backing.users.mockResolvedValue(['key1']);

    const removal = acl.remove('key1');
    await started;
    await expect(acl.check('key1')).resolves.toBe(false);

    rejectRemoval(new Error('backing remove failed'));
    await expect(removal).rejects.toThrow('backing remove failed');
    await expect(acl.check('key1')).resolves.toBe(true);
    await expect(acl.users()).resolves.toEqual(['key1']);
  });

  test('current delegates to backing ACL', () => {
    backing.current.mockReturnValue('current-state');
    expect(acl.current()).toBe('current-state');
  });

  test('merge delegates to backing ACL', () => {
    acl.merge('incoming-changes');
    expect(backing.merge).toHaveBeenCalledWith('incoming-changes');
  });

  test('poisons all future operations after a partially applied failed merge', async () => {
    let isMember = false;
    backing.merge.mockImplementation(() => {
      isMember = true;
      throw new Error('backing merge failed after mutation');
    });
    backing.current.mockReturnValue('partially-mutated-state');
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () =>
      isMember ? ['key1'] : [],
    );

    expect(() => acl.merge('incoming-changes')).toThrow(
      'backing merge failed after mutation',
    );

    expect(() => acl.current()).toThrow(
      /failed ACL merge may have partially changed/,
    );
    await expect(acl.check('key1')).rejects.toThrow(
      /failed ACL merge may have partially changed/,
    );
    await expect(acl.users()).rejects.toThrow(
      /failed ACL merge may have partially changed/,
    );
    await expect(acl.getEntry('key1')).rejects.toThrow(
      /failed ACL merge may have partially changed/,
    );
    await expect(acl.add('key1')).rejects.toThrow(
      /failed ACL merge may have partially changed/,
    );
    await expect(acl.remove('key1')).rejects.toThrow(
      /failed ACL merge may have partially changed/,
    );
    await expect(
      acl.grant(
        'key1',
        '/doc/read',
        'doc-1',
        {} as CryptoKey,
        'issuer',
      ),
    ).rejects.toThrow(/failed ACL merge may have partially changed/);
    expect(() => acl.merge('retry')).toThrow(
      /failed ACL merge may have partially changed/,
    );
    expect(backing.add).not.toHaveBeenCalled();
    expect(backing.remove).not.toHaveBeenCalled();
    expect(backing.current).not.toHaveBeenCalled();
  });

  test('rejects merge while identity admission is pending', async () => {
    let serializationStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      serializationStarted = resolve;
    });
    let releaseSerialization!: () => void;
    const release = new Promise<void>((resolve) => {
      releaseSerialization = resolve;
    });
    const serialize = jest.fn(async (key: string) => {
      serializationStarted();
      await release;
      return `serialized:${key}`;
    });
    const orderedAcl = new UCANACLImpl(backing, serialize);
    backing.add.mockResolvedValue('add-changes');

    const addition = orderedAcl.add('key1');
    await started;

    expect(() => orderedAcl.merge('remote-changes')).toThrow(
      /local membership mutation is pending/,
    );
    expect(backing.merge).not.toHaveBeenCalled();

    releaseSerialization();
    await expect(addition).resolves.toBe('add-changes');
    expect(() => orderedAcl.merge('remote-changes')).not.toThrow();
    expect(backing.merge).toHaveBeenCalledWith('remote-changes');
  });

  test('rejects merge while a backing membership mutation is pending', async () => {
    let addStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      addStarted = resolve;
    });
    let resolveAdd!: (changes: string) => void;
    const pendingAdd = new Promise<string>((resolve) => {
      resolveAdd = resolve;
    });
    backing.add.mockImplementation(() => {
      addStarted();
      return pendingAdd;
    });

    const addition = acl.add('key1');
    await started;

    expect(() => acl.merge('remote-changes')).toThrow(
      /local membership mutation is pending/,
    );
    expect(backing.merge).not.toHaveBeenCalled();

    resolveAdd('add-changes');
    await expect(addition).resolves.toBe('add-changes');
    expect(() => acl.merge('remote-changes')).not.toThrow();
    expect(backing.merge).toHaveBeenCalledWith('remote-changes');
  });

  test('check without capability delegates to backing ACL', async () => {
    backing.check.mockResolvedValue(true);
    const result = await acl.check('key1');
    expect(result).toBe(true);
  });

  test('checks backing membership with a detached identity', async () => {
    const callerIdentity = { id: 'user-a' };
    const serialize = jest.fn(async (key: { id: string }) =>
      `serialized:${key.id}`,
    );
    const deserialize = jest.fn(async (serialized: string) => ({
      id: serialized.slice('serialized:'.length),
    }));
    let checkStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      checkStarted = resolve;
    });
    let releaseCheck!: () => void;
    const release = new Promise<void>((resolve) => {
      releaseCheck = resolve;
    });
    let checkedIdentity: { id: string } | undefined;
    backing.check.mockImplementation(async (key: { id: string }) => {
      checkedIdentity = key;
      checkStarted();
      await release;
      return key.id === 'user-a';
    });
    const objectAcl = new UCANACLImpl(backing, serialize, deserialize);

    const check = objectAcl.check(callerIdentity);
    await started;
    callerIdentity.id = 'user-b';
    releaseCheck();

    await expect(check).resolves.toBe(true);
    expect(checkedIdentity).toEqual({ id: 'user-a' });
    expect(checkedIdentity).not.toBe(callerIdentity);
  });

  test('denies an in-flight check when a remote merge changes backing state', async () => {
    let checkStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      checkStarted = resolve;
    });
    let resolveCheck!: (allowed: boolean) => void;
    const pendingCheck = new Promise<boolean>((resolve) => {
      resolveCheck = resolve;
    });
    backing.check.mockImplementation(() => {
      checkStarted();
      return pendingCheck;
    });

    const authorization = acl.check('key1');
    await started;
    acl.merge('remote-removal');
    resolveCheck(true);

    await expect(authorization).resolves.toBe(false);
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

  test('grant stays unavailable until backing membership succeeds', async () => {
    const fakeUcan = makeFakeUcan({
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
    });
    let resolveAdd!: (changes: string) => void;
    const pendingAdd = new Promise<string>((resolve) => {
      resolveAdd = resolve;
    });
    let addStarted!: () => void;
    const addWasStarted = new Promise<void>((resolve) => {
      addStarted = resolve;
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockImplementation(() => {
      addStarted();
      return pendingAdd;
    });
    backing.check.mockResolvedValue(true);

    const grant = acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    await addWasStarted;

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

  test('a rejected backing addition does not install a capability', async () => {
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user1',
        capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
      }),
    );
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

  test('quarantines a partially applied failed grant until an explicit retry succeeds', async () => {
    let isMember = false;
    let grantStarted!: () => void;
    const grantWasStarted = new Promise<void>((resolve) => {
      grantStarted = resolve;
    });
    let rejectGrant!: (error: Error) => void;
    const pendingGrant = new Promise<string>((_resolve, reject) => {
      rejectGrant = reject;
    });
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user1',
        capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
      }),
    );
    backing.add
      .mockImplementationOnce(() => {
        isMember = true;
        grantStarted();
        return pendingGrant;
      })
      .mockImplementationOnce(async () => {
        isMember = true;
        return 'recovery-changes';
      });
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () =>
      isMember ? ['user1'] : [],
    );

    const grant = acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    await grantWasStarted;
    await expect(acl.check('user1')).resolves.toBe(false);
    await expect(acl.check('user1', '/doc/write')).resolves.toBe(false);
    await expect(acl.users()).resolves.toEqual([]);

    rejectGrant(new Error('backing grant failed after mutation'));
    await expect(grant).rejects.toThrow(
      'backing grant failed after mutation',
    );
    await expect(acl.getEntry('user1')).resolves.toBeUndefined();
    await expect(acl.check('user1')).resolves.toBe(false);
    await expect(acl.check('user1', '/doc/write')).resolves.toBe(false);
    await expect(acl.users()).resolves.toEqual([]);

    await expect(
      acl.grant(
        'user1',
        '/doc/write',
        'doc-1',
        {} as CryptoKey,
        'issuer',
      ),
    ).resolves.toBe('recovery-changes');
    await expect(acl.check('user1')).resolves.toBe(true);
    await expect(acl.check('user1', '/doc/write')).resolves.toBe(true);
    await expect(acl.users('/doc/write')).resolves.toEqual(['user1']);
  });

  test('preserves a prior valid capability after a later grant partially fails', async () => {
    let isMember = false;
    let replacementStarted!: () => void;
    const replacementWasStarted = new Promise<void>((resolve) => {
      replacementStarted = resolve;
    });
    let rejectReplacement!: (error: Error) => void;
    const pendingReplacement = new Promise<string>((_resolve, reject) => {
      rejectReplacement = reject;
    });
    mockCreateUCAN
      .mockResolvedValueOnce(
        makeFakeUcan({
          audience: 'serialized:user1',
          capabilities: [{ resource: 'doc-1', ability: '/doc/read' }],
        }),
      )
      .mockResolvedValueOnce(
        makeFakeUcan({
          audience: 'serialized:user1',
          capabilities: [{ resource: 'doc-1', ability: '/doc/admin' }],
        }),
      );
    backing.add
      .mockImplementationOnce(async () => {
        isMember = true;
        return 'initial-changes';
      })
      .mockImplementationOnce(() => {
        isMember = true;
        replacementStarted();
        return pendingReplacement;
      });
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () =>
      isMember ? ['user1'] : [],
    );
    backing.current.mockReturnValue('current-state');

    await acl.grant(
      'user1',
      '/doc/read',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    const replacement = acl.grant(
      'user1',
      '/doc/admin',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    await replacementWasStarted;
    await expect(acl.check('user1', '/doc/read')).resolves.toBe(true);
    await expect(acl.check('user1', '/doc/write')).resolves.toBe(false);
    await expect(acl.users('/doc/read')).resolves.toEqual(['user1']);
    expect(acl.current()).toBe('current-state');

    rejectReplacement(new Error('replacement grant failed after mutation'));
    await expect(replacement).rejects.toThrow(
      'replacement grant failed after mutation',
    );

    await expect(acl.check('user1', '/doc/read')).resolves.toBe(true);
    await expect(acl.check('user1', '/doc/write')).resolves.toBe(false);
    await expect(acl.users('/doc/read')).resolves.toEqual(['user1']);
    expect((await acl.getEntry('user1'))?.capabilities).toEqual([
      '/doc/read',
    ]);
  });

  test('quarantines a cached grant when a failed grant partially re-adds a removed member', async () => {
    let isMember = false;
    let replacementStarted!: () => void;
    const replacementWasStarted = new Promise<void>((resolve) => {
      replacementStarted = resolve;
    });
    let rejectReplacement!: (error: Error) => void;
    const pendingReplacement = new Promise<string>((_resolve, reject) => {
      rejectReplacement = reject;
    });
    mockCreateUCAN
      .mockResolvedValueOnce(
        makeFakeUcan({
          audience: 'serialized:user1',
          capabilities: [{ resource: 'doc-1', ability: '/doc/read' }],
        }),
      )
      .mockResolvedValueOnce(
        makeFakeUcan({
          audience: 'serialized:user1',
          capabilities: [{ resource: 'doc-1', ability: '/doc/admin' }],
        }),
      )
      .mockResolvedValueOnce(
        makeFakeUcan({
          audience: 'serialized:user1',
          capabilities: [{ resource: 'doc-1', ability: '/doc/admin' }],
        }),
      );
    backing.add
      .mockImplementationOnce(async () => {
        isMember = true;
        return 'initial-changes';
      })
      .mockImplementationOnce(() => {
        isMember = true;
        replacementStarted();
        return pendingReplacement;
      })
      .mockImplementationOnce(async () => {
        isMember = true;
        return 'recovery-changes';
      });
    backing.merge.mockImplementation(() => {
      isMember = false;
    });
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () =>
      isMember ? ['user1'] : [],
    );
    backing.current.mockReturnValue('current-state');

    await acl.grant(
      'user1',
      '/doc/read',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    acl.merge('remote-removal');
    await expect(acl.check('user1', '/doc/read')).resolves.toBe(false);
    expect((await acl.getEntry('user1'))?.capabilities).toEqual([
      '/doc/read',
    ]);

    const replacement = acl.grant(
      'user1',
      '/doc/admin',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    await replacementWasStarted;
    await expect(acl.check('user1', '/doc/read')).resolves.toBe(false);
    await expect(acl.users('/doc/read')).resolves.toEqual([]);
    expect(() => acl.current()).toThrow(/backing addition is quarantined/);

    rejectReplacement(new Error('replacement grant failed after mutation'));
    await expect(replacement).rejects.toThrow(
      'replacement grant failed after mutation',
    );
    await expect(acl.check('user1', '/doc/read')).resolves.toBe(false);
    await expect(acl.users('/doc/read')).resolves.toEqual([]);

    await expect(
      acl.grant(
        'user1',
        '/doc/admin',
        'doc-1',
        {} as CryptoKey,
        'issuer',
      ),
    ).resolves.toBe('recovery-changes');
    await expect(acl.check('user1', '/doc/admin')).resolves.toBe(true);
    expect(acl.current()).toBe('current-state');
  });

  test('a successful grant clears a prior revocation tombstone', async () => {
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user1',
        capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
      }),
    );
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

  test('orders a removal after an in-flight capability grant', async () => {
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user1',
        capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
      }),
    );
    let resolveAdd!: (changes: string) => void;
    const pendingAdd = new Promise<string>((resolve) => {
      resolveAdd = resolve;
    });
    let addStarted!: () => void;
    const addWasStarted = new Promise<void>((resolve) => {
      addStarted = resolve;
    });
    let isMember = false;
    backing.add.mockImplementation(async () => {
      addStarted();
      const changes = await pendingAdd;
      isMember = true;
      return changes;
    });
    backing.remove.mockImplementation(async () => {
      isMember = false;
      return 'remove-changes';
    });
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () =>
      isMember ? ['user1'] : [],
    );

    const grant = acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    await addWasStarted;
    const remove = acl.remove('user1');
    await Promise.resolve();
    expect(backing.remove).not.toHaveBeenCalled();
    resolveAdd('add-changes');

    await expect(grant).resolves.toBe('add-changes');
    await expect(remove).resolves.toBe('remove-changes');
    expect(await acl.getEntry('user1')).toBeUndefined();
    expect(await acl.check('user1')).toBe(false);
    expect(await acl.check('user1', '/doc/write')).toBe(false);
    expect(await acl.users()).toEqual([]);
  });

  test('orders grant then revoke when codec promises resolve out of order', async () => {
    let resolveFirstSerialization!: (serialized: string) => void;
    const firstSerialization = new Promise<string>((resolve) => {
      resolveFirstSerialization = resolve;
    });
    let serializationCall = 0;
    const serialize = jest.fn((key: string) => {
      serializationCall++;
      return serializationCall === 1
        ? firstSerialization
        : Promise.resolve(`serialized:${key}`);
    });
    const orderedAcl = new UCANACLImpl(backing, serialize);
    const events: string[] = [];
    const members = new Set<string>();
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user1',
        capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
      }),
    );
    backing.add.mockImplementation(async (key: string) => {
      events.push(`grant:${key}`);
      members.add(key);
      return 'grant-changes';
    });
    backing.remove.mockImplementation(async (key: string) => {
      events.push(`revoke:${key}`);
      members.delete(key);
      return 'revoke-changes';
    });
    backing.check.mockImplementation(async (key: string) => members.has(key));
    backing.users.mockImplementation(async () => [...members]);

    const grant = orderedAcl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    const revoke = orderedAcl.revoke('user1');
    await Promise.resolve();

    expect(serialize).toHaveBeenCalledTimes(2);
    expect(backing.add).not.toHaveBeenCalled();
    expect(backing.remove).not.toHaveBeenCalled();

    resolveFirstSerialization('serialized:user1');
    await expect(grant).resolves.toBe('grant-changes');
    await expect(revoke).resolves.toBe('revoke-changes');
    expect(events).toEqual(['grant:user1', 'revoke:user1']);
    expect(await orderedAcl.getEntry('user1')).toBeUndefined();
    expect(await orderedAcl.check('user1')).toBe(false);
    expect(await orderedAcl.users()).toEqual([]);
  });

  test('a remote backing removal disables cached capability metadata', async () => {
    let isMember = true;
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user1',
        capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
      }),
    );
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

    acl.merge('remote-removal');

    expect(await acl.getEntry('user1')).toBeDefined();
    expect(await acl.check('user1', '/doc/write')).toBe(false);
  });

  test('a remote re-add cannot clear a local revocation tombstone', async () => {
    let isMember = false;
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user1',
        capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
      }),
    );
    backing.add.mockImplementation(async () => {
      isMember = true;
      return 'add-changes';
    });
    backing.remove.mockImplementation(async () => {
      isMember = false;
      return 'remove-changes';
    });
    backing.merge.mockImplementation(() => {
      isMember = true;
    });
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () =>
      isMember ? ['user1'] : [],
    );

    await acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    await acl.revoke('user1');
    acl.merge('remote-re-add');

    expect(await acl.check('user1')).toBe(false);
    expect(await acl.check('user1', '/doc/write')).toBe(false);
    expect(await acl.users()).toEqual([]);
    expect(await acl.users('/doc/write')).toEqual([]);

    await acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    expect(await acl.check('user1')).toBe(true);
    expect(await acl.check('user1', '/doc/write')).toBe(true);
  });

  test('users filters the backing snapshot without redundant membership checks', async () => {
    backing.users.mockResolvedValue(['userA', 'userB']);
    backing.check.mockResolvedValue(true);
    const result = await acl.users();
    expect(result).toEqual(['userA', 'userB']);
    expect(backing.check).not.toHaveBeenCalled();
  });

  test('retries an in-flight user listing when a remote merge changes backing state', async () => {
    let listingStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      listingStarted = resolve;
    });
    let resolveUsers!: (users: string[]) => void;
    const pendingUsers = new Promise<string[]>((resolve) => {
      resolveUsers = resolve;
    });
    backing.users
      .mockImplementationOnce(() => {
        listingStarted();
        return pendingUsers;
      })
      .mockResolvedValueOnce(['key2']);

    const listing = acl.users();
    await started;
    acl.merge('remote-removal');
    resolveUsers(['key1']);

    await expect(listing).resolves.toEqual(['key2']);
    expect(backing.users).toHaveBeenCalledTimes(2);
  });

  test('rejects a user listing after bounded continuous revision races', async () => {
    const attemptStartedResolvers: Array<() => void> = [];
    const attemptStarted = Array.from(
      { length: 3 },
      () =>
        new Promise<void>((resolve) => {
          attemptStartedResolvers.push(resolve);
        }),
    );
    const listingResolvers: Array<(users: string[]) => void> = [];
    const pendingListings = Array.from(
      { length: 3 },
      () =>
        new Promise<string[]>((resolve) => {
          listingResolvers.push(resolve);
        }),
    );
    let attempt = 0;
    backing.users.mockImplementation(() => {
      const currentAttempt = attempt++;
      attemptStartedResolvers[currentAttempt]!();
      return pendingListings[currentAttempt]!;
    });

    const listing = acl.users();
    for (let index = 0; index < 3; index++) {
      await attemptStarted[index];
      acl.merge(`remote-change-${index}`);
      listingResolvers[index]!([`key${index}`]);
    }

    await expect(listing).rejects.toThrow(
      'ACL listing remained stale after 3 attempts',
    );
    expect(backing.users).toHaveBeenCalledTimes(3);
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

  test('detaches stored grants from mutable token inputs and lookup results', async () => {
    const tokenCapabilities = [
      { resource: 'doc-1', ability: '/doc/write' },
    ];
    const proofs = ['proof-1'];
    const fakeUcan = makeFakeUcan({
      audience: 'serialized:user1',
      capabilities: tokenCapabilities,
      proofs,
    });
    const epochId = new Uint8Array([10, 20, 30]);
    let resolveAdd!: (changes: string) => void;
    const addPending = new Promise<string>((resolve) => {
      resolveAdd = resolve;
    });
    let addStarted!: () => void;
    const addWasStarted = new Promise<void>((resolve) => {
      addStarted = resolve;
    });
    mockCreateUCAN.mockResolvedValue(fakeUcan);
    backing.add.mockImplementation(() => {
      addStarted();
      return addPending;
    });
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
    await addWasStarted;
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

  test('binds deferred grant metadata and membership to one detached identity', async () => {
    const callerIdentity = { id: 'user-a' };
    let serializationStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      serializationStarted = resolve;
    });
    let releaseSerialization!: () => void;
    const release = new Promise<void>((resolve) => {
      releaseSerialization = resolve;
    });
    const serialize = jest.fn((key: { id: string }) => {
      const capturedId = key.id;
      return (async () => {
        if (key === callerIdentity) {
          serializationStarted();
          await release;
        }
        return `serialized:${capturedId}`;
      })();
    });
    const deserialize = jest.fn(async (serialized: string) => ({
      id: serialized.slice('serialized:'.length),
    }));
    const members = new Set<string>();
    backing.add.mockImplementation(async (key: { id: string }) => {
      members.add(key.id);
      return 'changes';
    });
    backing.check.mockImplementation(async (key: { id: string }) =>
      members.has(key.id),
    );
    const objectAcl = new UCANACLImpl(backing, serialize, deserialize);
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user-a',
        capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
      }),
    );

    const grant = objectAcl.grant(
      callerIdentity,
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    await started;
    callerIdentity.id = 'user-b';
    releaseSerialization();

    await expect(grant).resolves.toBe('changes');
    expect(backing.add).toHaveBeenCalledWith({ id: 'user-a' });
    expect(
      await objectAcl.check({ id: 'user-a' }, '/doc/write'),
    ).toBe(true);
    expect(
      await objectAcl.check({ id: 'user-b' }, '/doc/admin'),
    ).toBe(false);
  });

  test('fails closed when a mutable identity cannot be detached', async () => {
    const identity = { id: 'user-a' };
    const serialize = jest.fn(async (key: { id: string }) => key.id);
    const withoutDeserializer = new UCANACLImpl(backing, serialize);
    backing.add.mockResolvedValue('changes');

    await expect(withoutDeserializer.add(identity)).rejects.toThrow(
      /requires a public-key deserializer for mutable identities/,
    );
    expect(backing.add).not.toHaveBeenCalled();

    const aliasingDeserializer = new UCANACLImpl(
      backing,
      serialize,
      jest.fn(async () => identity),
    );
    await expect(aliasingDeserializer.add(identity)).rejects.toThrow(
      /return a detached identity/,
    );
    expect(backing.add).not.toHaveBeenCalled();
  });

  test('rejects a non-canonical reconstructed identity', async () => {
    const objectAcl = new UCANACLImpl(
      backing,
      jest.fn(async (key: { id: string }) => `serialized:${key.id}`),
      jest.fn(async () => ({ id: 'different-user' })),
    );

    await expect(objectAcl.add({ id: 'user-a' })).rejects.toThrow(
      /non-canonical public-key round trip/,
    );
    expect(backing.add).not.toHaveBeenCalled();
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
  test('forwards the identity codec to the initialized UCAN ACL', async () => {
    const mockBackingAclProvider = { initialize: jest.fn(() => makeMockAcl()) };
    const serializeKey = jest.fn(async (key: { id: string }) => `s:${key.id}`);
    const deserializeKey = jest.fn(async (serialized: string) => ({
      id: serialized.slice(2),
    }));
    const provider = new UCANACLProviderImpl(
      mockBackingAclProvider,
      serializeKey,
      deserializeKey,
    );
    const acl = provider.initialize();
    const backing = mockBackingAclProvider.initialize.mock.results[0]!.value;
    backing.add.mockResolvedValue('changes');

    expect(acl).toBeInstanceOf(UCANACLImpl);
    expect(mockBackingAclProvider.initialize).toHaveBeenCalledTimes(1);
    await expect(acl.add({ id: 'reader' })).resolves.toBe('changes');
    expect(deserializeKey).toHaveBeenCalledWith('s:reader');
    expect(backing.add).toHaveBeenCalledWith({ id: 'reader' });
  });
});
