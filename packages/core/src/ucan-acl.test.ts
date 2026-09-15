import { describe, expect, test, jest, beforeEach } from '@jest/globals';

const ucanAcl = require('./ucan-acl');
const { MAX_UCAN_ACL_LISTING_IDENTITIES } = ucanAcl;
const UCANACLImpl = ucanAcl.UCANACL;
const UCANACLProviderImpl = ucanAcl.UCANACLProvider;
const {
  ACLOperationInProgressError,
  retryACLConflict,
} = require('./acl');
const { EPOCH_ID_LENGTH } = require('./epoch');

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

async function settleWithinMicrotasks<T>(
  promise: Promise<T>,
): Promise<
  | { status: 'fulfilled'; value: T }
  | { status: 'rejected'; reason: unknown }
  | undefined
> {
  let outcome:
    | { status: 'fulfilled'; value: T }
    | { status: 'rejected'; reason: unknown }
    | undefined;
  void promise.then(
    (value) => {
      outcome = { status: 'fulfilled', value };
    },
    (reason) => {
      outcome = { status: 'rejected', reason };
    },
  );
  for (let turn = 0; turn < 50 && outcome === undefined; turn++) {
    await Promise.resolve();
  }
  return outcome;
}

describe('UCANACL', () => {
  let backing: any;
  let acl: any;

  const rewrapBacking = () => {
    backing = { ...backing };
    return backing;
  };

  beforeEach(() => {
    backing = makeMockAcl();
    acl = new UCANACLImpl(backing, jest.fn(async (key: string) => `serialized:${key}`));
    mockCreateUCAN.mockReset();
  });

  test.each(['', null, 0])('rejects invalid capability %p before consulting membership', async (capability) => {
    await expect(acl.check('key1', capability)).rejects.toThrow(/non-empty string/);
    await expect(acl.users(capability)).rejects.toThrow(/non-empty string/);
    expect(backing.check).not.toHaveBeenCalled();
    expect(backing.users).not.toHaveBeenCalled();
  });

  test.each(['\ud800', '\udc00', 'key\ud800suffix'])(
    'rejects ill-formed canonical identity %p before backing work',
    async (encoding) => {
      const guarded = new UCANACLImpl(rewrapBacking(), async () => encoding);
      await expect(guarded.check('key1')).rejects.toThrow(/well-formed UTF-16/);
      expect(backing.check).not.toHaveBeenCalled();
    },
  );

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

  test('a failed local add poisons reads even with a prior tombstone', async () => {
    backing.remove.mockResolvedValue('remove-changes');
    backing.add.mockRejectedValue(new Error('backing add failed'));
    backing.check.mockResolvedValue(true);
    await acl.remove('key1');

    await expect(acl.add('key1')).rejects.toThrow('backing add failed');
    await expect(acl.check('key1', '/doc/read')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('poisons all identities after a failed add mutates an unrelated member', async () => {
    const members = new Set<string>();
    let addStarted!: () => void;
    const addWasStarted = new Promise<void>((resolve) => {
      addStarted = resolve;
    });
    let rejectAdd!: (error: Error) => void;
    const pendingAdd = new Promise<string>((_resolve, reject) => {
      rejectAdd = reject;
    });
    backing.add.mockImplementationOnce(() => {
      members.add('attacker');
      addStarted();
      return pendingAdd;
    });
    backing.check.mockImplementation(async (key) => members.has(key));
    backing.users.mockImplementation(async () => [...members]);
    backing.current.mockReturnValue('current-state');

    const addition = acl.add('key1');
    await addWasStarted;
    const pendingCheck = expect(
      retryACLConflict(() => acl.check('attacker')),
    ).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    const pendingListing = expect(
      retryACLConflict(() => acl.users()),
    ).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    expect(() => acl.current()).toThrow(ACLOperationInProgressError);

    rejectAdd(new Error('backing add failed after mutation'));
    await expect(addition).rejects.toThrow(
      'backing add failed after mutation',
    );
    await pendingCheck;
    await pendingListing;
    await expect(acl.check('attacker')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.users()).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    expect(() => acl.current()).toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.add('key1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    expect(backing.add).toHaveBeenCalledTimes(1);
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
    const remove = retryACLConflict(() => acl.remove('key1'));
    await Promise.resolve();
    expect(backing.remove).not.toHaveBeenCalled();
    resolveAdd('add-changes');

    await expect(add).resolves.toBe('add-changes');
    await expect(remove).resolves.toBe('remove-changes');
    expect(await acl.check('key1')).toBe(false);
    expect(await acl.check('key1', '/doc/read')).toBe(false);
    expect(await acl.users()).toEqual([]);
  });

  test('retries a removal after an earlier slow identity codec', async () => {
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
    const orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
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
    const removal = retryACLConflict(() => orderedAcl.remove('key1'));
    await Promise.resolve();

    expect(serialize).toHaveBeenCalledTimes(1);
    expect(backing.add).not.toHaveBeenCalled();
    expect(backing.remove).not.toHaveBeenCalled();

    resolveFirstSerialization('serialized:key1');
    await expect(addition).resolves.toBe('add-changes');
    await expect(removal).resolves.toBe('remove-changes');
    expect(events).toEqual(['add:key1', 'remove:key1']);
    expect(await orderedAcl.check('key1')).toBe(false);
    expect(await orderedAcl.users()).toEqual([]);
  });

  test('rejects synchronous serializer reentry without queuing it', async () => {
    const events: string[] = [];
    let reentered = false;
    let reentrantRemoval!: Promise<string>;
    let orderedAcl: any;
    const serialize = jest.fn((key: string) => {
      if (key === 'key1' && !reentered) {
        reentered = true;
        expect(() => orderedAcl.merge('reentrant-merge')).toThrow(
          ACLOperationInProgressError,
        );
        reentrantRemoval = orderedAcl.remove('key2');
      }
      return Promise.resolve(`serialized:${key}`);
    });
    orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    backing.add.mockImplementation(async (key: string) => {
      events.push(`add:${key}`);
      return 'add-changes';
    });
    backing.remove.mockImplementation(async (key: string) => {
      events.push(`remove:${key}`);
      return 'remove-changes';
    });

    await expect(orderedAcl.add('key1')).resolves.toBe('add-changes');
    await expect(reentrantRemoval).rejects.toBeInstanceOf(
      ACLOperationInProgressError,
    );

    expect(events).toEqual(['add:key1']);
    expect(backing.remove).not.toHaveBeenCalled();
    expect(backing.merge).not.toHaveBeenCalled();
  });

  test('rejects serializer reentry after suspension without hanging', async () => {
    let reenter = true;
    let orderedAcl: any;
    const serialize = jest.fn(async (key: string) => {
      await Promise.resolve();
      if (reenter) {
        reenter = false;
        await orderedAcl.remove('key2');
      }
      return `serialized:${key}`;
    });
    orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    backing.add.mockResolvedValue('add-changes');

    await expect(
      settleWithinMicrotasks(orderedAcl.add('key1')),
    ).resolves.toEqual(
      expect.objectContaining({
        status: 'rejected',
        reason: expect.any(ACLOperationInProgressError),
      }),
    );
    expect(backing.add).not.toHaveBeenCalled();
    expect(backing.remove).not.toHaveBeenCalled();

    await expect(orderedAcl.add('key1')).resolves.toBe('add-changes');
  });

  test('rejects deserializer reentry after suspension without hanging', async () => {
    let reenter = true;
    let orderedAcl: any;
    const deserialize = jest.fn(async (serialized: string) => {
      await Promise.resolve();
      if (reenter) {
        reenter = false;
        await orderedAcl.check('key2');
      }
      return serialized.slice('serialized:'.length);
    });
    orderedAcl = new UCANACLImpl(
      rewrapBacking(),
      jest.fn(async (key: string) => `serialized:${key}`),
      deserialize,
    );
    backing.add.mockResolvedValue('add-changes');

    await expect(
      settleWithinMicrotasks(orderedAcl.add('key1')),
    ).resolves.toEqual(
      expect.objectContaining({
        status: 'rejected',
        reason: expect.any(ACLOperationInProgressError),
      }),
    );
    expect(backing.add).not.toHaveBeenCalled();
    expect(backing.check).not.toHaveBeenCalled();

    await expect(orderedAcl.add('key1')).resolves.toBe('add-changes');
  });

  test('tracks a check through delayed identity-codec reentry', async () => {
    let reenter = true;
    let orderedAcl: any;
    const serialize = jest.fn(async (key: string) => {
      await Promise.resolve();
      if (reenter) {
        reenter = false;
        await orderedAcl.check('key2');
      }
      return `serialized:${key}`;
    });
    orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    backing.check.mockResolvedValue(true);

    await expect(
      settleWithinMicrotasks(orderedAcl.check('key1')),
    ).resolves.toEqual(
      expect.objectContaining({
        status: 'rejected',
        reason: expect.any(ACLOperationInProgressError),
      }),
    );
    expect(backing.check).not.toHaveBeenCalled();
    await expect(orderedAcl.check('key1')).resolves.toBe(true);
  });

  test('tracks a listing through delayed identity-codec reentry', async () => {
    let reenter = true;
    let orderedAcl: any;
    const serialize = jest.fn(async (key: string) => {
      await Promise.resolve();
      if (reenter) {
        reenter = false;
        await orderedAcl.users();
      }
      return `serialized:${key}`;
    });
    orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    backing.users.mockResolvedValue(['key1']);

    await expect(
      settleWithinMicrotasks(orderedAcl.users()),
    ).resolves.toEqual(
      expect.objectContaining({
        status: 'rejected',
        reason: expect.any(ACLOperationInProgressError),
      }),
    );
    expect(backing.users).toHaveBeenCalledTimes(1);
    await expect(orderedAcl.users()).resolves.toEqual(['key1']);
  });

  test('keeps listing admission until every identity codec settles', async () => {
    let releaseSlowCodec!: () => void;
    const releaseSlow = new Promise<void>((resolve) => {
      releaseSlowCodec = resolve;
    });
    let slowCodecStarted!: () => void;
    const slowStarted = new Promise<void>((resolve) => {
      slowCodecStarted = resolve;
    });
    let reentryError: unknown;
    let orderedAcl: any;
    const serialize = jest.fn(async (key: string) => {
      if (key === 'bad') throw new Error('malformed listing identity');
      slowCodecStarted();
      await releaseSlow;
      try {
        await orderedAcl.remove('victim');
      } catch (error) {
        reentryError = error;
        throw error;
      }
      return `serialized:${key}`;
    });
    orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    backing.users.mockResolvedValue(['bad', 'slow']);

    const listing = orderedAcl.users();
    await slowStarted;
    expect(await settleWithinMicrotasks(listing)).toBeUndefined();
    releaseSlowCodec();

    await expect(listing).rejects.toThrow('malformed listing identity');
    expect(reentryError).toBeInstanceOf(ACLOperationInProgressError);
    expect(backing.remove).not.toHaveBeenCalled();
  });

  test('does not invoke a backing listing map override', async () => {
    const listedUsers = ['key1'];
    Object.defineProperty(listedUsers, 'map', {
      configurable: true,
      get: () => {
        throw new Error('hostile listing map');
      },
    });
    backing.users.mockResolvedValue(listedUsers);

    await expect(acl.users()).resolves.toEqual(['key1']);
  });

  test('rejects oversized sparse and proxied listings before starting codecs', async () => {
    const serialize = jest.fn(async (key: string) => `serialized:${key}`);
    const boundedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    backing.users.mockResolvedValueOnce(
      new Array(MAX_UCAN_ACL_LISTING_IDENTITIES + 1),
    );

    await expect(boundedAcl.users()).rejects.toThrow(
      `exceeds ${MAX_UCAN_ACL_LISTING_IDENTITIES} identities`,
    );

    let indexed = false;
    const oversizedProxy = new Proxy([], {
      get: (target, property, receiver) => {
        if (property === 'length') {
          return MAX_UCAN_ACL_LISTING_IDENTITIES + 1;
        }
        if (typeof property === 'string' && /^\d+$/.test(property)) {
          indexed = true;
        }
        return Reflect.get(target, property, receiver);
      },
    });
    backing.users.mockResolvedValueOnce(oversizedProxy);

    await expect(boundedAcl.users()).rejects.toThrow(
      `exceeds ${MAX_UCAN_ACL_LISTING_IDENTITIES} identities`,
    );
    expect(indexed).toBe(false);
    expect(serialize).not.toHaveBeenCalled();
  });

  test('rejects listings with holes before reading inherited entries', async () => {
    const serialize = jest.fn(async (key: string) => `serialized:${key}`);
    const boundedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    const sparse: string[] = new Array(2);
    sparse[1] = 'key1';
    const inherited = Object.getOwnPropertyDescriptor(Array.prototype, '0');
    Object.defineProperty(Array.prototype, '0', {
      configurable: true,
      value: 'phantom',
    });
    try {
      backing.users.mockResolvedValueOnce(sparse);
      await expect(boundedAcl.users()).rejects.toThrow(
        'Backing ACL listing must not contain holes',
      );
    } finally {
      delete (Array.prototype as unknown as Record<string, unknown>)['0'];
      if (inherited) Object.defineProperty(Array.prototype, '0', inherited);
    }
    expect(serialize).not.toHaveBeenCalled();

    backing.users.mockResolvedValueOnce(['key1']);
    await expect(boundedAcl.users()).resolves.toEqual(['key1']);
  });

  test('preserves a throwing listing length and releases admission', async () => {
    const serialize = jest.fn(async (key: string) => `serialized:${key}`);
    const boundedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    const hostileLength = new Proxy([], {
      get: (target, property, receiver) => {
        if (property === 'length') {
          throw new Error('unstable listing length');
        }
        return Reflect.get(target, property, receiver);
      },
    });
    backing.users
      .mockResolvedValueOnce(hostileLength)
      .mockResolvedValueOnce(['key1']);

    await expect(boundedAcl.users()).rejects.toThrow(
      'unstable listing length',
    );
    expect(serialize).not.toHaveBeenCalled();
    await expect(boundedAcl.users()).resolves.toEqual(['key1']);
  });

  test('settles started listing codecs before preserving an undefined index failure', async () => {
    let releaseSlowCodec!: () => void;
    const releaseSlow = new Promise<void>((resolve) => {
      releaseSlowCodec = resolve;
    });
    let slowCodecStarted!: () => void;
    const slowStarted = new Promise<void>((resolve) => {
      slowCodecStarted = resolve;
    });
    let reentryError: unknown;
    let orderedAcl: any;
    const serialize = jest.fn(async (key: string) => {
      slowCodecStarted();
      await releaseSlow;
      try {
        await orderedAcl.remove(key);
      } catch (error) {
        reentryError = error;
        throw error;
      }
      return `serialized:${key}`;
    });
    orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    const listedUsers = ['slow', 'unread'];
    Object.defineProperty(listedUsers, '1', {
      enumerable: true,
      get: () => {
        throw undefined;
      },
    });
    backing.users.mockResolvedValue(listedUsers);

    const listing = orderedAcl.users();
    await slowStarted;
    expect(await settleWithinMicrotasks(listing)).toBeUndefined();
    releaseSlowCodec();

    await expect(settleWithinMicrotasks(listing)).resolves.toEqual({
      status: 'rejected',
      reason: undefined,
    });
    expect(reentryError).toBeInstanceOf(ACLOperationInProgressError);
    expect(backing.remove).not.toHaveBeenCalled();
  });

  test('releases codec admission after a rejected snapshot', async () => {
    const serialize = jest
      .fn()
      .mockRejectedValueOnce(new Error('invalid identity'))
      .mockResolvedValueOnce('serialized:key2');
    const orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    backing.add.mockResolvedValue('add-changes');

    const rejected = orderedAcl.add('key1');
    const accepted = retryACLConflict(() => orderedAcl.add('key2'));

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
    const second = retryACLConflict(() => acl.add('key2'));
    await firstWasStarted;

    expect(started).toEqual(['key1']);
    resolveFirstAdd('first-changes');
    await expect(first).resolves.toBe('first-changes');
    await expect(second).resolves.toBe('second-changes');
    expect(started).toEqual(['key1', 'key2']);
  });

  test('rejects a retried mutation after a backing failure', async () => {
    backing.add
      .mockRejectedValueOnce(new Error('first add failed'))
      .mockResolvedValueOnce('second-changes');

    const first = acl.add('key1');
    const second = retryACLConflict(() => acl.add('key2'));

    await expect(first).rejects.toThrow('first add failed');
    await expect(second).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    expect(backing.add).toHaveBeenNthCalledWith(1, 'key1');
    expect(backing.add).toHaveBeenCalledTimes(1);
    expect(() => acl.merge('remote-changes')).toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('keeps current state available after an addition rejected before admission', async () => {
    let checkStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      checkStarted = resolve;
    });
    let resolveCheck!: (isMember: boolean) => void;
    const pendingCheck = new Promise<boolean>((resolve) => {
      resolveCheck = resolve;
    });
    backing.check.mockImplementation(() => {
      checkStarted();
      return pendingCheck;
    });
    backing.current.mockReturnValue('current-state');
    backing.add.mockResolvedValue('add-changes');

    const check = acl.check('key1');
    await started;
    await expect(acl.add('key2')).rejects.toBeInstanceOf(
      ACLOperationInProgressError,
    );
    expect(backing.add).not.toHaveBeenCalled();

    resolveCheck(false);
    await expect(check).resolves.toBe(false);
    expect(acl.current()).toBe('current-state');
    await expect(acl.add('key2')).resolves.toBe('add-changes');
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

  test('prepareAdd rejects after a remote backing merge', async () => {
    const commit = jest.fn();
    backing.prepareAdd = jest.fn(async () => ({
      changes: 'add-changes',
      commit,
    }));

    const prepared = await acl.prepareAdd('key1');
    acl.merge('remote-changes');

    expect(() => prepared.commit()).toThrow(/backing ACL changed/);
    expect(commit).not.toHaveBeenCalled();
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

  test('an in-flight staged add cannot clear a newer removal tombstone', async () => {
    let resolvePreparation!: (prepared: {
      changes: string;
      commit(): void;
    }) => void;
    const pendingPreparation = new Promise<{
      changes: string;
      commit(): void;
    }>((resolve) => {
      resolvePreparation = resolve;
    });
    let preparationStarted!: () => void;
    const preparationWasStarted = new Promise<void>((resolve) => {
      preparationStarted = resolve;
    });
    const commit = jest.fn();
    backing.prepareAdd = jest.fn(() => {
      preparationStarted();
      return pendingPreparation;
    });
    backing.remove.mockResolvedValue('remove-changes');
    backing.check.mockResolvedValue(true);

    const addition = acl.prepareAdd('key1');
    await preparationWasStarted;
    await acl.remove('key1');
    resolvePreparation({ changes: 'add-changes', commit });

    await expect(addition).rejects.toThrow(/Prepared ACL addition became stale/);
    expect(commit).not.toHaveBeenCalled();
    expect(await acl.check('key1', '/doc/read')).toBe(false);
  });

  test('prepareAdd cannot commit during another member mutation', async () => {
    const members = new Set(['user-b']);
    const addCommit = jest.fn(() => {
      members.add('user-a');
    });
    backing.prepareAdd = jest.fn(async () => ({
      changes: 'add-changes',
      commit: addCommit,
    }));
    let removalStarted!: () => void;
    const removalWasStarted = new Promise<void>((resolve) => {
      removalStarted = resolve;
    });
    let resolveRemoval!: (prepared: {
      changes: string;
      commit(): void;
    }) => void;
    const pendingRemoval = new Promise<{
      changes: string;
      commit(): void;
    }>((resolve) => {
      resolveRemoval = resolve;
    });
    backing.prepareRemove = jest.fn(() => {
      removalStarted();
      return pendingRemoval;
    });
    backing.check.mockImplementation(async (key: string) => members.has(key));
    backing.users.mockImplementation(async () => [...members]);

    const prepared = await acl.prepareAdd('user-a');
    const removal = acl.remove('user-b');
    await removalWasStarted;

    expect(() => prepared.commit()).toThrow(/active membership mutation/);
    expect(addCommit).not.toHaveBeenCalled();

    resolveRemoval({
      changes: 'remove-changes',
      commit: () => {
        members.delete('user-b');
      },
    });
    await expect(removal).resolves.toBe('remove-changes');

    const replacement = await acl.prepareAdd('user-a');
    replacement.commit();
    expect(addCommit).toHaveBeenCalledTimes(1);
    expect(await acl.check('user-a')).toBe(true);
    expect(await acl.check('user-a', '/doc/write')).toBe(true);
    expect(await acl.check('user-b')).toBe(false);
    expect(await acl.users()).toEqual(['user-a']);
  });

  test('prepareAdd cannot commit while another identity codec is pending', async () => {
    let resolveSerialization!: (serialized: string) => void;
    const pendingSerialization = new Promise<string>((resolve) => {
      resolveSerialization = resolve;
    });
    const serialize = jest.fn((key: string) =>
      key === 'user-b'
        ? pendingSerialization
        : Promise.resolve(`serialized:${key}`),
    );
    const orderedAcl = new UCANACLImpl(backing, serialize);
    const members = new Set(['user-b']);
    const addCommit = jest.fn(() => {
      members.add('user-a');
    });
    backing.prepareAdd = jest.fn(async () => ({
      changes: 'add-changes',
      commit: addCommit,
    }));
    backing.remove.mockImplementation(async (key: string) => {
      members.delete(key);
      return 'remove-changes';
    });
    backing.check.mockImplementation(async (key: string) => members.has(key));
    backing.users.mockImplementation(async () => [...members]);

    const prepared = await orderedAcl.prepareAdd('user-a');
    const removal = orderedAcl.remove('user-b');

    expect(() => prepared.commit()).toThrow(/active membership mutation/);
    expect(addCommit).not.toHaveBeenCalled();
    expect(backing.remove).not.toHaveBeenCalled();

    resolveSerialization('serialized:user-b');
    await expect(removal).resolves.toBe('remove-changes');

    const replacement = await orderedAcl.prepareAdd('user-a');
    replacement.commit();
    expect(addCommit).toHaveBeenCalledTimes(1);
    expect(await orderedAcl.check('user-a')).toBe(true);
    expect(await orderedAcl.check('user-a', '/doc/write')).toBe(true);
    expect(await orderedAcl.check('user-b')).toBe(false);
    expect(await orderedAcl.users()).toEqual(['user-a']);
  });

  test('prepareAdd passes a detached identity to the backing ACL', async () => {
    const callerIdentity = { id: 'user-a' };
    const serialize = jest.fn((key: { id: string }) => {
      const capturedId = key.id;
      return Promise.resolve(`serialized:${capturedId}`);
    });
    const deserialize = jest.fn(async (serialized: string) => ({
      id: serialized.slice('serialized:'.length),
    }));
    const commit = jest.fn();
    backing.prepareAdd = jest.fn(async () => ({
      changes: 'add-changes',
      commit,
    }));
    const objectAcl = new UCANACLImpl(backing, serialize, deserialize);

    const preparation = objectAcl.prepareAdd(callerIdentity);
    callerIdentity.id = 'user-b';
    const prepared = await preparation;
    prepared.commit();

    expect(backing.prepareAdd).toHaveBeenCalledWith({ id: 'user-a' });
    expect(commit).toHaveBeenCalledTimes(1);
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

  test('quarantines a partially applied failed prepared addition until retry', async () => {
    let isMember = false;
    backing.prepareAdd = jest.fn();
    backing.prepareAdd
      .mockResolvedValueOnce({
        changes: 'failed-changes',
        commit: () => {
          isMember = true;
          throw new Error('prepared add failed after mutation');
        },
      })
      .mockResolvedValueOnce({
        changes: 'recovery-changes',
        commit: () => {
          isMember = true;
        },
      });
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () =>
      isMember ? ['key1'] : [],
    );
    backing.current.mockReturnValue('current-state');

    const failed = await acl.prepareAdd('key1');
    expect(() => failed.commit()).toThrow(
      'prepared add failed after mutation',
    );
    await expect(acl.check('key1')).resolves.toBe(false);
    await expect(acl.users()).resolves.toEqual([]);
    expect(() => acl.current()).toThrow(/backing addition is quarantined/);

    const recovery = await acl.prepareAdd('key1');
    expect(() => recovery.commit()).not.toThrow();
    await expect(acl.check('key1')).resolves.toBe(true);
    await expect(acl.users()).resolves.toEqual(['key1']);
    expect(acl.current()).toBe('current-state');
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

  test('retries checks and user listings after a backing removal', async () => {
    let removalStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      removalStarted = resolve;
    });
    let resolveRemoval!: (changes: string) => void;
    const pendingRemoval = new Promise<string>((resolve) => {
      resolveRemoval = resolve;
    });
    let isMember = true;
    backing.remove.mockImplementation(() => {
      removalStarted();
      return pendingRemoval.then((changes) => {
        isMember = false;
        return changes;
      });
    });
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () => (isMember ? ['key1'] : []));

    const removal = retryACLConflict(() => acl.remove('key1'));
    await started;

    const directConflict = acl.check('key1');
    await expect(directConflict).rejects.toBeInstanceOf(
      ACLOperationInProgressError,
    );
    const membershipCheck = retryACLConflict(() => acl.check('key1'));
    const capabilityCheck = retryACLConflict(() =>
      acl.check('key1', '/doc/read'),
    );
    const listing = retryACLConflict(() => acl.users());
    const capabilityListing = retryACLConflict(() =>
      acl.users('/doc/read'),
    );
    await Promise.resolve();
    expect(backing.check).not.toHaveBeenCalled();
    expect(backing.users).not.toHaveBeenCalled();

    resolveRemoval('changes');
    await expect(removal).resolves.toBe('changes');
    await expect(membershipCheck).resolves.toBe(false);
    await expect(capabilityCheck).resolves.toBe(false);
    await expect(listing).resolves.toEqual([]);
    await expect(capabilityListing).resolves.toEqual([]);
  });

  test('rejects a check reentered by a backing addition without deadlocking', async () => {
    backing.add.mockImplementation(async () => {
      await acl.check('key2');
      return 'changes';
    });

    await expect(acl.add('key1')).rejects.toThrow(
      /cannot reenter the UCAN ACL from a backing ACL operation/,
    );
    await expect(acl.check('key2')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('rejects a listing reentered by a backing removal without deadlocking', async () => {
    backing.remove.mockImplementation(async () => {
      await acl.users();
      return 'changes';
    });

    await expect(acl.remove('key1')).rejects.toThrow(
      /cannot reenter the UCAN ACL from a backing ACL operation/,
    );
    await expect(acl.users()).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('rejects a check reentered after a backing addition suspends', async () => {
    backing.add.mockImplementation(async () => {
      await Promise.resolve();
      await acl.check('key2');
      return 'changes';
    });

    await expect(
      settleWithinMicrotasks(acl.add('key1')),
    ).resolves.toEqual(
      expect.objectContaining({
        status: 'rejected',
        reason: expect.objectContaining({
          message: expect.stringMatching(
            /retry conflict after invocation; backing state is uncertain/,
          ),
        }),
      }),
    );
    await expect(acl.check('key2')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('rejects a listing reentered after a backing removal suspends', async () => {
    backing.remove.mockImplementation(async () => {
      await Promise.resolve();
      await acl.users();
      return 'changes';
    });

    await expect(
      settleWithinMicrotasks(acl.remove('key1')),
    ).resolves.toEqual(
      expect.objectContaining({
        status: 'rejected',
        reason: expect.objectContaining({
          message: expect.stringMatching(
            /retry conflict after invocation; backing state is uncertain/,
          ),
        }),
      }),
    );
    await expect(acl.users()).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('rejects a mutation reentered after a backing addition suspends', async () => {
    backing.add.mockImplementation(async () => {
      await Promise.resolve();
      await acl.remove('key2');
      return 'changes';
    });

    await expect(
      settleWithinMicrotasks(acl.add('key1')),
    ).resolves.toEqual(
      expect.objectContaining({
        status: 'rejected',
        reason: expect.objectContaining({
          message: expect.stringMatching(
            /retry conflict after invocation; backing state is uncertain/,
          ),
        }),
      }),
    );
    expect(backing.remove).not.toHaveBeenCalled();
    await expect(acl.remove('key2')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('rejects wrapper recursion from a backing read operation', async () => {
    backing.check.mockImplementation(async () => acl.getEntry('key1'));

    await expect(acl.check('key1')).rejects.toThrow(
      /cannot reenter the UCAN ACL from a backing ACL operation/,
    );
  });

  test('rejects backing check recursion after the backing read suspends', async () => {
    backing.check.mockImplementation(async () => {
      await Promise.resolve();
      return acl.check('key1');
    });

    await expect(
      settleWithinMicrotasks(acl.check('key1')),
    ).resolves.toEqual(
      expect.objectContaining({
        status: 'rejected',
        reason: expect.objectContaining({
          message: expect.stringMatching(
            /Backing ACL read cannot reenter this UCAN ACL/,
          ),
        }),
      }),
    );
  });

  test('rejects backing listing recursion after the backing read suspends', async () => {
    backing.users.mockImplementation(async () => {
      await Promise.resolve();
      return acl.users();
    });

    await expect(settleWithinMicrotasks(acl.users())).resolves.toEqual(
      expect.objectContaining({
        status: 'rejected',
        reason: expect.objectContaining({
          message: expect.stringMatching(
            /Backing ACL read cannot reenter this UCAN ACL/,
          ),
        }),
      }),
    );
  });

  test('preserves a foreign retryable conflict from a backing check', async () => {
    let settle!: () => void;
    const settlement = new Promise<void>((resolve) => {
      settle = resolve;
    });
    backing.check
      .mockRejectedValueOnce(
        new ACLOperationInProgressError(
          'Nested ACL check',
          settlement,
        ),
      )
      .mockResolvedValueOnce(true);

    const check = retryACLConflict(() => acl.check('key1'));
    expect(await settleWithinMicrotasks(check)).toBeUndefined();
    expect(backing.check).toHaveBeenCalledTimes(1);
    settle();

    await expect(check).resolves.toBe(true);
    expect(backing.check).toHaveBeenCalledTimes(2);
  });

  test('preserves a foreign retryable conflict from a backing listing', async () => {
    let settle!: () => void;
    const settlement = new Promise<void>((resolve) => {
      settle = resolve;
    });
    backing.users
      .mockRejectedValueOnce(
        new ACLOperationInProgressError(
          'Nested ACL listing',
          settlement,
        ),
      )
      .mockResolvedValueOnce(['key1']);

    const listing = retryACLConflict(() => acl.users());
    expect(await settleWithinMicrotasks(listing)).toBeUndefined();
    expect(backing.users).toHaveBeenCalledTimes(1);
    settle();

    await expect(listing).resolves.toEqual(['key1']);
    expect(backing.users).toHaveBeenCalledTimes(2);
  });

  test('poisons when a backing addition propagates a foreign conflict', async () => {
    let settle!: () => void;
    const settlement = new Promise<void>((resolve) => {
      settle = resolve;
    });
    backing.add
      .mockRejectedValueOnce(
        new ACLOperationInProgressError(
          'Nested ACL addition',
          settlement,
        ),
      )
      .mockResolvedValueOnce('changes');
    backing.current.mockReturnValue('current-state');

    const addition = retryACLConflict(() => acl.add('key1'));
    await expect(addition).rejects.toThrow(
      /retry conflict after invocation; backing state is uncertain/,
    );
    expect(backing.add).toHaveBeenCalledTimes(1);
    expect(() => acl.current()).toThrow(
      /failed ACL backing mutation may have partially changed/,
    );

    settle();
    await Promise.resolve();
    expect(backing.add).toHaveBeenCalledTimes(1);
  });

  test('poisons when a backing removal propagates a foreign conflict', async () => {
    let settle!: () => void;
    const settlement = new Promise<void>((resolve) => {
      settle = resolve;
    });
    backing.remove
      .mockRejectedValueOnce(
        new ACLOperationInProgressError(
          'Nested ACL removal',
          settlement,
        ),
      )
      .mockResolvedValueOnce('changes');
    backing.current.mockReturnValue('current-state');

    const removal = retryACLConflict(() => acl.remove('key1'));
    await expect(removal).rejects.toThrow(
      /retry conflict after invocation; backing state is uncertain/,
    );
    expect(backing.remove).toHaveBeenCalledTimes(1);
    expect(() => acl.current()).toThrow(
      /failed ACL backing mutation may have partially changed/,
    );

    settle();
    await Promise.resolve();
    expect(backing.remove).toHaveBeenCalledTimes(1);
  });

  test('reports overlapping reads and permits an external retry', async () => {
    let firstCheckStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      firstCheckStarted = resolve;
    });
    let resolveFirstCheck!: (allowed: boolean) => void;
    const firstCheck = new Promise<boolean>((resolve) => {
      resolveFirstCheck = resolve;
    });
    backing.check
      .mockImplementationOnce(() => {
        firstCheckStarted();
        return firstCheck;
      })
      .mockResolvedValueOnce(true);

    const first = acl.check('key1');
    await started;
    await expect(acl.check('key2')).rejects.toBeInstanceOf(
      ACLOperationInProgressError,
    );
    const retried = retryACLConflict(() => acl.check('key2'));
    expect(await settleWithinMicrotasks(retried)).toBeUndefined();
    expect(backing.check).toHaveBeenCalledTimes(1);

    resolveFirstCheck(true);
    await expect(first).resolves.toBe(true);
    await expect(retried).resolves.toBe(true);
    expect(backing.check).toHaveBeenCalledTimes(2);
  });

  test('linearizes a removal after an in-flight backing check', async () => {
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
    let isMember = true;
    backing.check
      .mockImplementationOnce(() => {
        checkStarted();
        return pendingCheck;
      })
      .mockImplementation(async () => isMember);
    backing.remove.mockImplementation(() => {
      removalStarted();
      return pendingRemoval.then((changes) => {
        isMember = false;
        return changes;
      });
    });

    const authorization = retryACLConflict(() => acl.check('key1'));
    await checkWasStarted;
    const removal = retryACLConflict(() => acl.remove('key1'));
    await Promise.resolve();
    expect(backing.remove).not.toHaveBeenCalled();

    resolveCheck(true);
    await expect(authorization).resolves.toBe(true);
    await removalWasStarted;
    resolveRemoval('changes');
    await expect(removal).resolves.toBe('changes');
    await expect(acl.check('key1')).resolves.toBe(false);
  });

  test('poisons access after a pending backing removal fails', async () => {
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
    const pendingCheck = expect(
      retryACLConflict(() => acl.check('key1')),
    ).rejects.toThrow(/failed ACL backing mutation may have partially changed/);

    rejectRemoval(new Error('backing remove failed'));
    await expect(removal).rejects.toThrow('backing remove failed');
    await pendingCheck;
    await expect(acl.check('key1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.users()).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
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

  test('prepareRemove rejects after a remote backing merge', async () => {
    const commit = jest.fn();
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'remove-changes',
      commit,
    }));

    const prepared = await acl.prepareRemove('user1');
    acl.merge('remote-changes');

    expect(() => prepared.commit()).toThrow(/backing ACL changed/);
    expect(commit).not.toHaveBeenCalled();
  });

  test('prepareRemove poisons reads when the backing commit rejects', async () => {
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

    await expect(acl.getEntry('user1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.check('user1', '/doc/write')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('prepareRemove rejects after the same member receives a newer grant', async () => {
    const firstUcan = makeFakeUcan({
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/read' }],
    });
    const replacementUcan = makeFakeUcan({
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/admin' }],
      nonce: 'nonce-2',
    });
    const commit = jest.fn();
    mockCreateUCAN
      .mockResolvedValueOnce(firstUcan)
      .mockResolvedValueOnce(replacementUcan);
    backing.add.mockResolvedValue('add-changes');
    backing.check.mockResolvedValue(true);
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'remove-changes',
      commit,
    }));
    await acl.grant(
      'user1',
      '/doc/read',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    const prepared = await acl.prepareRemove('user1');

    await acl.grant(
      'user1',
      '/doc/admin',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );

    expect(() => prepared.commit()).toThrow(/Prepared ACL removal became stale/);
    expect(commit).not.toHaveBeenCalled();
    expect((await acl.getEntry('user1'))?.ucan.nonce).toBe('nonce-2');
    expect(await acl.check('user1', '/doc/admin')).toBe(true);
  });

  test('prepareRemove rejects and retries later metadata changes until preparation settles', async () => {
    const firstUcan = makeFakeUcan({
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/read' }],
    });
    const replacementUcan = makeFakeUcan({
      audience: 'serialized:user1',
      capabilities: [{ resource: 'doc-1', ability: '/doc/admin' }],
      nonce: 'nonce-2',
    });
    let resolvePreparation!: (prepared: {
      changes: string;
      commit(): void;
    }) => void;
    const pendingPreparation = new Promise<{
      changes: string;
      commit(): void;
    }>((resolve) => {
      resolvePreparation = resolve;
    });
    let preparationStarted!: () => void;
    const preparationWasStarted = new Promise<void>((resolve) => {
      preparationStarted = resolve;
    });
    const commit = jest.fn();
    mockCreateUCAN
      .mockResolvedValueOnce(firstUcan)
      .mockResolvedValueOnce(replacementUcan);
    backing.add.mockResolvedValue('add-changes');
    backing.check.mockResolvedValue(true);
    backing.prepareRemove = jest.fn(() => {
      preparationStarted();
      return pendingPreparation;
    });
    await acl.grant(
      'user1',
      '/doc/read',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );

    const preparation = acl.prepareRemove('user1');
    await preparationWasStarted;
    const grant = retryACLConflict(() =>
      acl.grant(
        'user1',
        '/doc/admin',
        'doc-1',
        {} as CryptoKey,
        'issuer',
      ),
    );
    await Promise.resolve();
    expect(backing.add).toHaveBeenCalledTimes(1);
    expect(() => acl.merge('remote-changes')).toThrow(
      ACLOperationInProgressError,
    );
    expect(backing.merge).not.toHaveBeenCalled();
    resolvePreparation({ changes: 'remove-changes', commit });

    const prepared = await preparation;
    await expect(grant).resolves.toBe('add-changes');
    expect(() => prepared.commit()).toThrow(/Prepared ACL removal became stale/);
    expect(commit).not.toHaveBeenCalled();
    expect((await acl.getEntry('user1'))?.ucan.nonce).toBe('nonce-2');
    expect(await acl.check('user1', '/doc/admin')).toBe(true);
  });

  test('a safe backing preparation rejection does not poison later operations', async () => {
    backing.prepareRemove = jest.fn(async () => {
      throw new Error('could not stage removal');
    });
    backing.add.mockResolvedValue('add-changes');

    await expect(acl.prepareRemove('user1')).rejects.toThrow(
      'could not stage removal',
    );
    await expect(acl.add('user2')).resolves.toBe('add-changes');
    expect(backing.add).toHaveBeenCalledWith('user2');
  });

  test('discovers missing staging without invoking Proxy get or has traps', async () => {
    const target = makeMockAcl();
    const members = new Set<string>();
    const touched: PropertyKey[] = [];
    target.remove.mockImplementation(async (key: string) => {
      members.delete(key);
      return 'legacy-removal';
    });
    const proxied = new Proxy(target, {
      get(proxyTarget, property, receiver) {
        if (property === 'prepareRemove') {
          touched.push(property);
          members.add('attacker');
        }
        return Reflect.get(proxyTarget, property, receiver);
      },
      has(proxyTarget, property) {
        if (property === 'prepareRemove') {
          touched.push(property);
          members.add('attacker');
        }
        return Reflect.has(proxyTarget, property);
      },
    });
    const proxiedAcl = new UCANACLImpl(
      proxied,
      jest.fn(async (key: string) => key),
    );

    await expect(proxiedAcl.remove('user1')).resolves.toBe('legacy-removal');

    expect(touched).toEqual([]);
    expect(members.has('attacker')).toBe(false);
    expect(target.remove).toHaveBeenCalledWith('user1');
  });

  test('treats an explicit undefined staging data property as absent', async () => {
    Object.defineProperty(backing, 'prepareRemove', {
      configurable: true,
      value: undefined,
    });
    backing.remove.mockResolvedValue('legacy-removal');

    await expect(acl.remove('user1')).resolves.toBe('legacy-removal');

    expect(backing.remove).toHaveBeenCalledWith('user1');
  });

  test('rejects an accessor-backed staging capability without falling back', async () => {
    let getterCalled = false;
    Object.defineProperty(backing, 'prepareRemove', {
      configurable: true,
      get() {
        getterCalled = true;
        return undefined;
      },
    });
    backing.remove.mockResolvedValue('legacy-removal');

    await expect(acl.remove('user1')).rejects.toThrow(
      'Backing ACL prepareRemove must be a data property',
    );

    expect(getterCalled).toBe(false);
    expect(backing.remove).not.toHaveBeenCalled();
    await expect(acl.check('user1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('rejects backing capability-lookup reentry and poisons later operations', async () => {
    let guardedAcl: any;
    const proxied = new Proxy(backing, {
      getOwnPropertyDescriptor(target, property) {
        if (property === 'prepareRemove') {
          guardedAcl.current();
        }
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });
    guardedAcl = new UCANACLImpl(
      proxied,
      jest.fn(async (key: string) => key),
    );

    await expect(guardedAcl.prepareRemove('user1')).rejects.toThrow(
      /cannot reenter the UCAN ACL from a backing ACL operation/,
    );

    expect(backing.current).not.toHaveBeenCalled();
    await expect(guardedAcl.check('user1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('poisons a prepared-result descriptor trap that mutates then throws', async () => {
    const members = new Set<string>();
    const returned = new Proxy(
      {
        changes: 'remove-changes',
        commit: jest.fn(),
      },
      {
        getOwnPropertyDescriptor(target, property) {
          if (property === 'changes') {
            members.add('attacker');
            throw new Error('prepared capture failed');
          }
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      },
    );
    backing.prepareRemove = jest.fn(async () => returned);
    backing.check.mockImplementation(async (key: string) => members.has(key));

    await expect(acl.prepareRemove('user1')).rejects.toThrow(
      'prepared capture failed',
    );

    expect(members.has('attacker')).toBe(true);
    await expect(acl.check('attacker', '/doc/admin')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    expect(backing.check).not.toHaveBeenCalled();
  });

  test('rejects prepared-result capture reentry and poisons later operations', async () => {
    const target = {
      changes: 'remove-changes',
      commit: jest.fn(),
    };
    const returned = new Proxy(target, {
      getOwnPropertyDescriptor(proxyTarget, property) {
        if (property === 'commit') {
          acl.current();
        }
        return Reflect.getOwnPropertyDescriptor(proxyTarget, property);
      },
    });
    backing.prepareRemove = jest.fn(async () => returned);

    await expect(acl.prepareRemove('user1')).rejects.toThrow(
      /cannot reenter the UCAN ACL from a backing ACL operation/,
    );

    expect(backing.current).not.toHaveBeenCalled();
    await expect(acl.check('user1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('rejects accessor-backed prepared fields without invoking them', async () => {
    let changesGetterCalled = false;
    backing.prepareRemove = jest.fn(async () => ({
      get changes() {
        changesGetterCalled = true;
        return 'remove-changes';
      },
      commit: jest.fn(),
    }));

    await expect(acl.prepareRemove('user1')).rejects.toThrow(
      'Backing ACL prepared-removal changes must be a data property',
    );

    expect(changesGetterCalled).toBe(false);
    await expect(acl.check('user1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('captures stable prepared fields and preserves the commit receiver', async () => {
    let commitReceiver: unknown;
    const originalCommit = jest.fn(function (this: unknown) {
      commitReceiver = this;
    });
    const replacementCommit = jest.fn();
    const target = {
      changes: 'remove-changes',
      commit: originalCommit,
    };
    const touched: PropertyKey[] = [];
    const returned = new Proxy(target, {
      get(proxyTarget, property, receiver) {
        if (property === 'changes' || property === 'commit') {
          touched.push(property);
        }
        return Reflect.get(proxyTarget, property, receiver);
      },
      has(proxyTarget, property) {
        if (property === 'changes' || property === 'commit') {
          touched.push(property);
        }
        return Reflect.has(proxyTarget, property);
      },
    });
    backing.prepareRemove = jest.fn(async () => returned);

    const prepared = await acl.prepareRemove('user1');
    target.changes = 'replaced-changes';
    target.commit = replacementCommit;

    expect(prepared.changes).toBe('remove-changes');
    prepared.commit();

    expect(touched).toEqual([]);
    expect(originalCommit).toHaveBeenCalledTimes(1);
    expect(replacementCommit).not.toHaveBeenCalled();
    expect(commitReceiver).toBe(returned);
  });

  test('rejects delayed backing preparation recursion without hanging', async () => {
    const commit = jest.fn();
    backing.prepareRemove = jest
      .fn()
      .mockImplementationOnce(async () => {
        await Promise.resolve();
        return acl.prepareRemove('user2');
      })
      .mockResolvedValueOnce({
        changes: 'remove-changes',
        commit,
      });

    await expect(
      settleWithinMicrotasks(acl.prepareRemove('user1')),
    ).resolves.toEqual(
      expect.objectContaining({
        status: 'rejected',
        reason: expect.objectContaining({
          message: expect.stringMatching(
            /Backing ACL preparation cannot reenter this UCAN ACL/,
          ),
        }),
      }),
    );
    expect(backing.prepareRemove).toHaveBeenCalledTimes(1);

    const prepared = await acl.prepareRemove('user1');
    prepared.commit();
    expect(commit).toHaveBeenCalledTimes(1);
  });

  test('retries a foreign conflict reported by backing preparation', async () => {
    let settle!: () => void;
    const settlement = new Promise<void>((resolve) => {
      settle = resolve;
    });
    const commit = jest.fn();
    backing.prepareRemove = jest
      .fn()
      .mockRejectedValueOnce(
        new ACLOperationInProgressError(
          'Nested ACL preparation',
          settlement,
        ),
      )
      .mockResolvedValueOnce({
        changes: 'remove-changes',
        commit,
      });
    backing.current.mockReturnValue('current-state');

    const preparation = retryACLConflict(() =>
      acl.prepareRemove('user1'),
    );
    expect(await settleWithinMicrotasks(preparation)).toBeUndefined();
    expect(backing.prepareRemove).toHaveBeenCalledTimes(1);

    settle();
    const prepared = await preparation;
    prepared.commit();
    expect(backing.prepareRemove).toHaveBeenCalledTimes(2);
    expect(commit).toHaveBeenCalledTimes(1);
  });

  test('poisons an asynchronous backing prepared-commit contract violation', async () => {
    let asynchronousCommit!: Promise<unknown>;
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'remove-changes',
      commit: () => {
        asynchronousCommit = (async () => {
          await Promise.resolve();
          return acl.check('user1');
        })();
        return asynchronousCommit;
      },
    }));

    const prepared = await acl.prepareRemove('user1');
    expect(() => prepared.commit()).toThrow(
      'Backing ACL commit must complete synchronously',
    );
    await expect(asynchronousCommit).rejects.toThrow(
      /backing ACL violated a synchronous operation contract/,
    );
    await expect(acl.check('user1')).rejects.toThrow(
      /backing ACL violated a synchronous operation contract/,
    );
    expect(backing.check).not.toHaveBeenCalled();
  });

  test('poisons a foreign conflict reported by a backing prepared commit', async () => {
    let settle!: () => void;
    const settlement = new Promise<void>((resolve) => {
      settle = resolve;
    });
    const commit = jest.fn(() => {
      throw new ACLOperationInProgressError(
        'Nested ACL commit',
        settlement,
      );
    });
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'remove-changes',
      commit,
    }));
    backing.current.mockReturnValue('current-state');

    const prepared = await acl.prepareRemove('user1');
    await expect(
      retryACLConflict(() => prepared.commit()),
    ).rejects.toThrow(
      /retry conflict after invocation; backing state is uncertain/,
    );
    expect(commit).toHaveBeenCalledTimes(1);
    expect(() => acl.current()).toThrow(
      /failed ACL backing mutation may have partially changed/,
    );

    settle();
    await settlement;
    expect(commit).toHaveBeenCalledTimes(1);
  });

  test('retries a prepared commit after an overlapping read settles', async () => {
    let checkStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      checkStarted = resolve;
    });
    let resolveCheck!: (allowed: boolean) => void;
    const pendingCheck = new Promise<boolean>((resolve) => {
      resolveCheck = resolve;
    });
    const commit = jest.fn();
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'remove-changes',
      commit,
    }));
    backing.check.mockImplementationOnce(() => {
      checkStarted();
      return pendingCheck;
    });

    const prepared = await acl.prepareRemove('user1');
    const check = acl.check('user2');
    await started;
    const committed = retryACLConflict(() => prepared.commit());
    expect(await settleWithinMicrotasks(committed)).toBeUndefined();
    expect(commit).not.toHaveBeenCalled();

    resolveCheck(false);
    await expect(check).resolves.toBe(false);
    await expect(committed).resolves.toBeUndefined();
    expect(commit).toHaveBeenCalledTimes(1);
  });

  test('prepareRemove cannot commit during another member mutation', async () => {
    const fakeUcan = makeFakeUcan({
      audience: 'serialized:user-b',
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
    const members = new Set(['user-a']);
    const removeCommit = jest.fn(() => {
      members.delete('user-a');
    });
    backing.add.mockImplementation(async (key: string) => {
      addStarted();
      const changes = await pendingAdd;
      members.add(key);
      return changes;
    });
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'remove-changes',
      commit: removeCommit,
    }));
    backing.check.mockImplementation(async (key: string) => members.has(key));
    backing.users.mockImplementation(async () => [...members]);
    mockCreateUCAN.mockResolvedValue(fakeUcan);

    const prepared = await acl.prepareRemove('user-a');
    const grant = acl.grant(
      'user-b',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );
    await addWasStarted;

    expect(() => prepared.commit()).toThrow(
      ACLOperationInProgressError,
    );
    expect(removeCommit).not.toHaveBeenCalled();

    resolveAdd('add-changes');
    await expect(grant).resolves.toBe('add-changes');
    expect(await acl.check('user-b')).toBe(true);
    expect(await acl.check('user-b', '/doc/write')).toBe(true);
    expect(await acl.getEntry('user-b')).toBeDefined();

    const replacement = await acl.prepareRemove('user-a');
    replacement.commit();
    expect(removeCommit).toHaveBeenCalledTimes(1);
    expect(await acl.check('user-a')).toBe(false);
    expect(await acl.check('user-b')).toBe(true);
    expect(await acl.check('user-b', '/doc/write')).toBe(true);
    expect(await acl.users()).toEqual(['user-b']);
  });

  test('prepareRemove cannot commit while another identity codec is pending', async () => {
    let resolveSerialization!: (serialized: string) => void;
    const pendingSerialization = new Promise<string>((resolve) => {
      resolveSerialization = resolve;
    });
    const serialize = jest.fn((key: string) =>
      key === 'user-b'
        ? pendingSerialization
        : Promise.resolve(`serialized:${key}`),
    );
    const orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    const members = new Set(['user-a']);
    const removeCommit = jest.fn(() => {
      members.delete('user-a');
    });
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'remove-changes',
      commit: removeCommit,
    }));
    backing.add.mockImplementation(async (key: string) => {
      members.add(key);
      return 'add-changes';
    });
    backing.check.mockImplementation(async (key: string) => members.has(key));
    backing.users.mockImplementation(async () => [...members]);
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user-b',
        capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
      }),
    );

    const prepared = await orderedAcl.prepareRemove('user-a');
    const grant = orderedAcl.grant(
      'user-b',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );

    expect(() => prepared.commit()).toThrow(
      ACLOperationInProgressError,
    );
    expect(removeCommit).not.toHaveBeenCalled();
    expect(backing.add).not.toHaveBeenCalled();

    resolveSerialization('serialized:user-b');
    await expect(grant).resolves.toBe('add-changes');
    expect(await orderedAcl.check('user-b')).toBe(true);
    expect(await orderedAcl.check('user-b', '/doc/write')).toBe(true);
    expect(await orderedAcl.getEntry('user-b')).toBeDefined();

    const replacement = await orderedAcl.prepareRemove('user-a');
    replacement.commit();
    expect(removeCommit).toHaveBeenCalledTimes(1);
    expect(await orderedAcl.check('user-a')).toBe(false);
    expect(await orderedAcl.check('user-b')).toBe(true);
    expect(await orderedAcl.check('user-b', '/doc/write')).toBe(true);
    expect(await orderedAcl.users()).toEqual(['user-b']);
  });

  test('prepareRemove passes a detached identity to the backing ACL', async () => {
    const callerIdentity = { id: 'user-a' };
    const serialize = jest.fn((key: { id: string }) => {
      const capturedId = key.id;
      return Promise.resolve(`serialized:${capturedId}`);
    });
    const deserialize = jest.fn(async (serialized: string) => ({
      id: serialized.slice('serialized:'.length),
    }));
    const commit = jest.fn();
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'remove-changes',
      commit,
    }));
    const objectAcl = new UCANACLImpl(rewrapBacking(), serialize, deserialize);

    const preparation = objectAcl.prepareRemove(callerIdentity);
    callerIdentity.id = 'user-b';
    const prepared = await preparation;
    prepared.commit();

    expect(backing.prepareRemove).toHaveBeenCalledWith({ id: 'user-a' });
    expect(commit).toHaveBeenCalledTimes(1);
  });

  test('remove commits a staged backing removal when available', async () => {
    const commit = jest.fn();
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'staged-removal',
      commit,
    }));
    backing.check.mockResolvedValue(true);

    await expect(acl.remove('user1')).resolves.toBe('staged-removal');

    expect(backing.prepareRemove).toHaveBeenCalledWith('user1');
    expect(commit).toHaveBeenCalledTimes(1);
    expect(backing.remove).not.toHaveBeenCalled();
    expect(await acl.check('user1', '/doc/read')).toBe(false);
  });

  test('prepareRemove fails closed when the backing ACL lacks staging', async () => {
    await expect(acl.prepareRemove('user1')).rejects.toThrow(
      'Backing ACL does not support staged removal',
    );
    expect(backing.remove).not.toHaveBeenCalled();
  });

  test('legacy backing removal failure poisons subsequent reads', async () => {
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

    await expect(acl.getEntry('user1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.check('user1', '/doc/write')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('current delegates to backing ACL', () => {
    backing.current.mockReturnValue('current-state');
    expect(acl.current()).toBe('current-state');
  });

  test('merge delegates to backing ACL', () => {
    acl.merge('incoming-changes');
    expect(backing.merge).toHaveBeenCalledWith('incoming-changes');
  });

  test('poisons an asynchronous backing current-state contract violation', async () => {
    let asynchronousCurrent!: Promise<unknown>;
    backing.current.mockImplementation(() => {
      asynchronousCurrent = (async () => {
        await Promise.resolve();
        return acl.check('key1');
      })();
      return asynchronousCurrent;
    });

    expect(() => acl.current()).toThrow(
      'Backing ACL current-state read must complete synchronously',
    );
    await expect(asynchronousCurrent).rejects.toThrow(
      /backing ACL violated a synchronous operation contract/,
    );
    await expect(acl.check('key1')).rejects.toThrow(
      /backing ACL violated a synchronous operation contract/,
    );
    expect(backing.check).not.toHaveBeenCalled();
  });

  test('poisons an asynchronous backing merge contract violation', async () => {
    let asynchronousMerge!: Promise<unknown>;
    backing.merge.mockImplementation(() => {
      asynchronousMerge = (async () => {
        await Promise.resolve();
        return acl.remove('key1');
      })();
      return asynchronousMerge;
    });

    expect(() => acl.merge('incoming-changes')).toThrow(
      'Backing ACL merge must complete synchronously',
    );
    await expect(asynchronousMerge).rejects.toThrow(
      /backing ACL violated a synchronous operation contract/,
    );
    await expect(acl.remove('key1')).rejects.toThrow(
      /backing ACL violated a synchronous operation contract/,
    );
    expect(backing.remove).not.toHaveBeenCalled();
  });

  test('reports a foreign backing merge conflict without poisoning', async () => {
    let settle!: () => void;
    const settlement = new Promise<void>((resolve) => {
      settle = resolve;
    });
    backing.merge
      .mockImplementationOnce(() => {
        throw new ACLOperationInProgressError(
          'Nested ACL merge',
          settlement,
        );
      })
      .mockImplementationOnce(() => undefined);
    backing.current.mockReturnValue('current-state');

    const merge = retryACLConflict(() => acl.merge('incoming-changes'));
    await expect(merge).rejects.toThrow(
      /Backing ACL merge reported a retry conflict after invocation/,
    );
    expect(backing.merge).toHaveBeenCalledTimes(1);
    expect(acl.current()).toBe('current-state');

    settle();
    await Promise.resolve();
    expect(backing.merge).toHaveBeenCalledTimes(1);
  });

  test('rejects a reentrant merge while the backing merge is active', () => {
    let reentrantError: unknown;
    backing.merge.mockImplementationOnce(() => {
      try {
        acl.merge('reentrant-changes');
      } catch (error) {
        reentrantError = error;
      }
    });

    expect(() => acl.merge('incoming-changes')).not.toThrow();

    expect(reentrantError).toEqual(
      expect.objectContaining({
        message: expect.stringMatching(
          /cannot reenter the UCAN ACL from a backing ACL operation/,
        ),
      }),
    );
    expect(backing.merge).toHaveBeenCalledTimes(1);
  });

  test('keeps the ACL available after a partially applied failed merge', async () => {
    let isMember = false;
    backing.merge.mockImplementationOnce(() => {
      isMember = true;
      throw new Error('backing merge failed after mutation');
    });
    backing.current.mockReturnValue('partially-mutated-state');
    backing.check.mockImplementation(async () => isMember);
    backing.users.mockImplementation(async () =>
      isMember ? ['key1'] : [],
    );
    backing.remove.mockImplementation(async () => {
      isMember = false;
      return 'remove-changes';
    });

    expect(() => acl.merge('malformed-remote-changes')).toThrow(
      'backing merge failed after mutation',
    );

    expect(acl.current()).toBe('partially-mutated-state');
    await expect(acl.check('key1')).resolves.toBe(true);
    await expect(acl.users()).resolves.toEqual(['key1']);
    await expect(acl.getEntry('key1')).resolves.toBeUndefined();
    expect(() => acl.merge('valid-remote-changes')).not.toThrow();
    expect(backing.merge).toHaveBeenCalledTimes(2);
    backing.prepareRemove = jest.fn(async () => ({
      changes: 'prepared-remove-changes',
      commit: () => {
        isMember = false;
      },
    }));
    const prepared = await acl.prepareRemove('key1');
    expect(prepared.changes).toBe('prepared-remove-changes');
    prepared.commit();
    await expect(acl.check('key1')).resolves.toBe(false);
    await expect(acl.users()).resolves.toEqual([]);
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
    const orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
    backing.add.mockResolvedValue('add-changes');

    const addition = orderedAcl.add('key1');
    await started;

    expect(() => orderedAcl.merge('remote-changes')).toThrow(
      ACLOperationInProgressError,
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
      ACLOperationInProgressError,
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
    const objectAcl = new UCANACLImpl(rewrapBacking(), serialize, deserialize);

    const check = objectAcl.check(callerIdentity);
    await started;
    callerIdentity.id = 'user-b';
    releaseCheck();

    await expect(check).resolves.toBe(true);
    expect(checkedIdentity).toEqual({ id: 'user-a' });
    expect(checkedIdentity).not.toBe(callerIdentity);
  });

  test('uses canonical value equality across detached backing identities', async () => {
    const members = new Set<string>();
    const serialize = jest.fn(async (key: { id: string }) => `s:${key.id}`);
    const deserialize = jest.fn(async (serialized: string) => ({
      id: serialized.slice(2),
    }));
    const seen: Array<{ id: string }> = [];
    backing.add.mockImplementation(async (key: { id: string }) => {
      seen.push(key);
      members.add(key.id);
      return 'add-changes';
    });
    backing.check.mockImplementation(async (key: { id: string }) => {
      seen.push(key);
      return members.has(key.id);
    });
    backing.remove.mockImplementation(async (key: { id: string }) => {
      seen.push(key);
      members.delete(key.id);
      return 'remove-changes';
    });
    const objectAcl = new UCANACLImpl(rewrapBacking(), serialize, deserialize);

    await objectAcl.add({ id: 'user-a' });
    await expect(objectAcl.check({ id: 'user-a' })).resolves.toBe(true);
    await objectAcl.remove({ id: 'user-a' });

    expect(new Set(seen).size).toBe(seen.length);
    expect(members).toEqual(new Set());
  });

  test('rejects a remote merge until an in-flight backing check settles', async () => {
    let checkStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      checkStarted = resolve;
    });
    let resolveCheck!: (allowed: boolean) => void;
    const pendingCheck = new Promise<boolean>((resolve) => {
      resolveCheck = resolve;
    });
    backing.check
      .mockImplementationOnce(() => {
        checkStarted();
        return pendingCheck;
      })
      .mockResolvedValueOnce(false);

    const authorization = acl.check('key1');
    await started;
    let conflict: unknown;
    try {
      acl.merge('remote-removal');
    } catch (error) {
      conflict = error;
    }
    expect(conflict).toBeInstanceOf(
      ACLOperationInProgressError,
    );
    resolveCheck(true);

    await expect(authorization).resolves.toBe(true);
    await (conflict as any).waitForSettlement();
    acl.merge('remote-removal');
    await expect(acl.check('key1')).resolves.toBe(false);
    expect(backing.check).toHaveBeenCalledTimes(2);
  });

  test('runs a failing remote merge only after an in-flight check settles', async () => {
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
    backing.merge.mockImplementation(() => {
      throw new Error('backing merge failed');
    });

    const authorization = acl.check('key1');
    await started;
    let conflict: unknown;
    try {
      acl.merge('remote-changes');
    } catch (error) {
      conflict = error;
    }
    expect(conflict).toBeInstanceOf(
      ACLOperationInProgressError,
    );
    expect(backing.merge).not.toHaveBeenCalled();
    resolveCheck(false);

    await expect(authorization).resolves.toBe(false);
    await (conflict as any).waitForSettlement();
    expect(() => acl.merge('remote-changes')).toThrow('backing merge failed');
    await expect(acl.check('key1')).resolves.toBe(false);
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

  test('reserves a grant before iterating caller-owned proofs', async () => {
    let reentryError: unknown;
    const proofs = ['proof-1'];
    Object.defineProperty(proofs, Symbol.iterator, {
      configurable: true,
      value: function* () {
        try {
          acl.merge('reentrant-merge');
        } catch (error) {
          reentryError = error;
        }
        yield 'proof-1';
      },
    });
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user1',
        capabilities: [{ resource: 'doc-1', ability: '/doc/write' }],
        proofs: ['proof-1'],
      }),
    );
    backing.add.mockResolvedValue('changes');

    await expect(
      acl.grant(
        'user1',
        '/doc/write',
        'doc-1',
        {} as CryptoKey,
        'issuer',
        proofs,
      ),
    ).resolves.toBe('changes');

    expect(reentryError).toBeInstanceOf(ACLOperationInProgressError);
    expect(backing.merge).not.toHaveBeenCalled();
    expect(mockCreateUCAN).toHaveBeenCalledWith(
      expect.anything(),
      'issuer',
      'serialized:user1',
      [{ resource: 'doc-1', ability: '/doc/write' }],
      ['proof-1'],
    );
  });

  test('releases grant admission after abrupt proof iteration', async () => {
    let reentrantRemoval!: Promise<string>;
    const proofs: string[] = [];
    Object.defineProperty(proofs, Symbol.iterator, {
      configurable: true,
      value: function* () {
        reentrantRemoval = acl.remove('key2');
        throw undefined;
      },
    });

    const grant = acl.grant(
      'user1',
      '/doc/write',
      'doc-1',
      {} as CryptoKey,
      'issuer',
      proofs,
    );
    const grantOutcome = settleWithinMicrotasks(grant);
    const removalOutcome = expect(reentrantRemoval).rejects.toBeInstanceOf(
      ACLOperationInProgressError,
    );

    await removalOutcome;
    await expect(grantOutcome).resolves.toEqual({
      status: 'rejected',
      reason: undefined,
    });
    expect(mockCreateUCAN).not.toHaveBeenCalled();
    expect(backing.remove).not.toHaveBeenCalled();

    backing.add.mockResolvedValue('add-changes');
    await expect(acl.add('key3')).resolves.toBe('add-changes');
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
    ).rejects.toBeInstanceOf(ACLOperationInProgressError);
    const pendingCheck = retryACLConflict(() =>
      acl.check('user1', '/doc/write'),
    );
    const pendingEntry = retryACLConflict(() => acl.getEntry('user1'));

    resolveAdd('changes');
    await expect(grant).resolves.toBe('changes');
    await expect(pendingCheck).resolves.toBe(true);
    await expect(pendingEntry).resolves.toEqual(
      expect.objectContaining({ capabilities: ['/doc/write'] }),
    );
    expect(await acl.check('user1', '/doc/write')).toBe(true);
  });

  test('a rejected backing capability addition poisons subsequent reads', async () => {
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
    await expect(acl.getEntry('user1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.check('user1', '/doc/write')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('poisons a partially applied failed grant', async () => {
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
    backing.add.mockImplementationOnce(() => {
      isMember = true;
      grantStarted();
      return pendingGrant;
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
    const pendingMembershipCheck = expect(
      retryACLConflict(() => acl.check('user1')),
    ).rejects.toThrow(/failed ACL backing mutation may have partially changed/);
    const pendingCapabilityCheck = expect(
      retryACLConflict(() => acl.check('user1', '/doc/write')),
    ).rejects.toThrow(/failed ACL backing mutation may have partially changed/);
    const pendingListing = expect(
      retryACLConflict(() => acl.users()),
    ).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );

    rejectGrant(new Error('backing grant failed after mutation'));
    await expect(grant).rejects.toThrow(
      'backing grant failed after mutation',
    );
    await pendingMembershipCheck;
    await pendingCapabilityCheck;
    await pendingListing;
    await expect(acl.getEntry('user1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.check('user1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.users()).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(
      acl.grant(
        'user1',
        '/doc/write',
        'doc-1',
        {} as CryptoKey,
        'issuer',
      ),
    ).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    expect(backing.add).toHaveBeenCalledTimes(1);
  });

  test('blocks a prior capability while a replacement is unresolved or fails', async () => {
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
    const pendingReadCheck = expect(
      retryACLConflict(() => acl.check('user1', '/doc/read')),
    ).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    const pendingWriteCheck = expect(
      retryACLConflict(() => acl.check('user1', '/doc/write')),
    ).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    const pendingListing = expect(
      retryACLConflict(() => acl.users('/doc/read')),
    ).rejects.toThrow(/failed ACL backing mutation may have partially changed/);
    expect(() => acl.current()).toThrow(ACLOperationInProgressError);

    rejectReplacement(new Error('replacement grant failed after mutation'));
    await expect(replacement).rejects.toThrow(
      'replacement grant failed after mutation',
    );
    await pendingReadCheck;
    await pendingWriteCheck;
    await pendingListing;

    await expect(acl.check('user1', '/doc/read')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.users('/doc/read')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.getEntry('user1')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
  });

  test('poisons a cached grant when a failed grant partially re-adds a removed member', async () => {
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
    const pendingReadCheck = expect(
      retryACLConflict(() => acl.check('user1', '/doc/read')),
    ).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    const pendingListing = expect(
      retryACLConflict(() => acl.users('/doc/read')),
    ).rejects.toThrow(/failed ACL backing mutation may have partially changed/);
    expect(() => acl.current()).toThrow(ACLOperationInProgressError);

    rejectReplacement(new Error('replacement grant failed after mutation'));
    await expect(replacement).rejects.toThrow(
      'replacement grant failed after mutation',
    );
    await pendingReadCheck;
    await pendingListing;
    await expect(acl.check('user1', '/doc/read')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    await expect(acl.users('/doc/read')).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );

    await expect(
      acl.grant(
        'user1',
        '/doc/admin',
        'doc-1',
        {} as CryptoKey,
        'issuer',
      ),
    ).rejects.toThrow(
      /failed ACL backing mutation may have partially changed/,
    );
    expect(backing.add).toHaveBeenCalledTimes(2);
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
    const remove = retryACLConflict(() => acl.remove('user1'));
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

  test('retries revoke after an earlier slow grant identity codec', async () => {
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
    const orderedAcl = new UCANACLImpl(rewrapBacking(), serialize);
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
    const revoke = retryACLConflict(() => orderedAcl.revoke('user1'));
    await Promise.resolve();

    expect(serialize).toHaveBeenCalledTimes(1);
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

  test('a remote re-add cannot clear a local capability tombstone', async () => {
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

    expect(await acl.check('user1')).toBe(true);
    expect(await acl.check('user1', '/doc/write')).toBe(false);
    expect(await acl.check('user1', '/doc/read')).toBe(false);
    expect(await acl.users()).toEqual(['user1']);
    expect(await acl.users('/doc/write')).toEqual([]);

    await expect(acl.revoke('user1')).resolves.toBe('remove-changes');
    expect(backing.remove).toHaveBeenCalledTimes(2);
    expect(await acl.check('user1')).toBe(false);
    acl.merge('remote-re-add');

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

  test('reuses private detached listing identities within one backing revision', async () => {
    const backingIdentity = {
      id: 'user-a',
      nested: { label: 'original' },
    };
    const decodedIdentities: Array<{
      id: string;
      nested: { label: string };
    }> = [];
    const serialize = jest.fn(
      async (key: { id: string; nested: { label: string } }) =>
        `serialized:${key.id}`,
    );
    const deserialize = jest.fn(async (serialized: string) => {
      const identity = {
        id: serialized.slice('serialized:'.length),
        nested: { label: 'original' },
      };
      decodedIdentities.push(identity);
      return identity;
    });
    backing.users.mockImplementation(async () => [backingIdentity]);
    const objectAcl = new UCANACLImpl(rewrapBacking(), serialize, deserialize);

    const first = (await objectAcl.users())[0];
    expect(first).toEqual({ id: 'user-a', nested: { label: 'original' } });
    expect(serialize).toHaveBeenCalledTimes(2);
    expect(deserialize).toHaveBeenCalledTimes(1);

    first.id = 'caller-mutated';
    first.nested.label = 'caller-mutated';
    decodedIdentities[0]!.nested.label = 'decoder-mutated';
    const second = (await objectAcl.users())[0];

    expect(second).toEqual({ id: 'user-a', nested: { label: 'original' } });
    expect(second).not.toBe(first);
    expect(second.nested).not.toBe(first.nested);
    expect(serialize).toHaveBeenCalledTimes(3);
    expect(deserialize).toHaveBeenCalledTimes(1);

    backingIdentity.id = 'user-b';
    await expect(objectAcl.users()).resolves.toEqual([
      { id: 'user-b', nested: { label: 'original' } },
    ]);
    expect(serialize).toHaveBeenCalledTimes(5);
    expect(deserialize).toHaveBeenCalledTimes(2);

    objectAcl.merge('remote-change');
    await expect(objectAcl.users()).resolves.toEqual([
      { id: 'user-b', nested: { label: 'original' } },
    ]);
    expect(serialize).toHaveBeenCalledTimes(7);
    expect(deserialize).toHaveBeenCalledTimes(3);
  });

  test('avoids repeat imports and validation exports for CryptoKey listings', async () => {
    const rawKey = new Uint8Array(16).fill(7);
    const backingKey = await crypto.subtle.importKey(
      'raw',
      rawKey,
      'AES-GCM',
      true,
      ['encrypt'],
    );
    const serialize = jest.fn(async (key: CryptoKey) =>
      Buffer.from(await crypto.subtle.exportKey('raw', key)).toString('base64'),
    );
    const deserialize = jest.fn(async (serialized: string) =>
      crypto.subtle.importKey(
        'raw',
        Buffer.from(serialized, 'base64'),
        'AES-GCM',
        true,
        ['encrypt'],
      ),
    );
    backing.users.mockResolvedValue([backingKey]);
    const objectAcl = new UCANACLImpl(rewrapBacking(), serialize, deserialize);

    const first = (await objectAcl.users())[0];
    const second = (await objectAcl.users())[0];

    expect(first).not.toBe(backingKey);
    expect(second).not.toBe(first);
    expect(serialize).toHaveBeenCalledTimes(3);
    expect(deserialize).toHaveBeenCalledTimes(1);
  });

  test('reconstructs callable listing identities instead of caching references', async () => {
    const identity = (id: string) => Object.assign(() => id, { id });
    const backingIdentity = identity('user-a');
    const serialize = jest.fn(async (key: ReturnType<typeof identity>) => key.id);
    const deserialize = jest.fn(async (id: string) => identity(id));
    backing.users.mockResolvedValue([backingIdentity]);
    const functionAcl = new UCANACLImpl(rewrapBacking(), serialize, deserialize);

    const first = (await functionAcl.users())[0];
    first.id = 'mutated-by-caller';
    const second = (await functionAcl.users())[0];
    expect(second).not.toBe(first);
    expect(second).not.toBe(backingIdentity);
    expect(second.id).toBe('user-a');
    expect(backingIdentity.id).toBe('user-a');
    expect(deserialize).toHaveBeenCalledTimes(2);
  });

  test('does not cache identities whose canonical representation cannot be cloned', async () => {
    type Identity = { id: string; canonicalMarker: string };
    const makeIdentity = (id: string): Identity =>
      Object.defineProperty({ id }, 'canonicalMarker', {
        configurable: true,
        enumerable: false,
        value: 'marker',
        writable: true,
      }) as Identity;
    const serialize = jest.fn(
      async (key: Identity) => `${key.id}:${key.canonicalMarker}`,
    );
    const deserialize = jest.fn(async (serialized: string) =>
      makeIdentity(serialized.slice(0, serialized.indexOf(':'))),
    );
    backing.users.mockResolvedValue([makeIdentity('user-a')]);
    const objectAcl = new UCANACLImpl(rewrapBacking(), serialize, deserialize);

    const first = (await objectAcl.users())[0];
    const second = (await objectAcl.users())[0];

    expect(first).not.toBe(second);
    expect(first.canonicalMarker).toBe('marker');
    expect(
      Object.getOwnPropertyDescriptor(first, 'canonicalMarker')?.enumerable,
    ).toBe(false);
    expect(serialize).toHaveBeenCalledTimes(4);
    expect(deserialize).toHaveBeenCalledTimes(2);
  });

  test('rejects a remote merge until an in-flight backing listing settles', async () => {
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
    let conflict: unknown;
    try {
      acl.merge('remote-removal');
    } catch (error) {
      conflict = error;
    }
    expect(conflict).toBeInstanceOf(
      ACLOperationInProgressError,
    );
    resolveUsers(['key1']);

    await expect(listing).resolves.toEqual(['key1']);
    await (conflict as any).waitForSettlement();
    acl.merge('remote-removal');
    await expect(acl.users()).resolves.toEqual(['key2']);
    expect(backing.users).toHaveBeenCalledTimes(2);
  });

  test('holds listing admission through identity serialization', async () => {
    let serializationStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      serializationStarted = resolve;
    });
    let resolveSerialization!: (value: string) => void;
    const pendingSerialization = new Promise<string>((resolve) => {
      resolveSerialization = resolve;
    });
    backing.users.mockResolvedValue(['key1']);
    const serialize = jest.fn(() => {
      serializationStarted();
      return pendingSerialization;
    });
    const racingAcl = new UCANACLImpl(rewrapBacking(), serialize);

    const listing = racingAcl.users();
    await started;
    expect(() => racingAcl.merge('remote-change')).toThrow(
      ACLOperationInProgressError,
    );
    const merge = retryACLConflict(() =>
      racingAcl.merge('remote-change'),
    );
    expect(await settleWithinMicrotasks(merge)).toBeUndefined();
    expect(backing.merge).not.toHaveBeenCalled();

    resolveSerialization('serialized:key1');
    await expect(listing).resolves.toEqual(['key1']);
    await expect(merge).resolves.toBeUndefined();
    expect(backing.merge).toHaveBeenCalledWith('remote-change');
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

    const epochId = new Uint8Array(EPOCH_ID_LENGTH).fill(10);
    await (acl.grant as any)('user2', '/doc/admin', 'doc-1', {} as CryptoKey, 'issuer-b64', [], epochId);
    const entry = await acl.getEntry('user2');
    expect(entry!.epochId).toEqual(epochId);
  });

  test('rejects unsafe or incorrectly sized epoch IDs before grant side effects', async () => {
    const invalidEpochIds: unknown[] = [
      new Uint8Array(EPOCH_ID_LENGTH - 1),
      new Uint8Array(EPOCH_ID_LENGTH + 1),
      new Uint16Array(EPOCH_ID_LENGTH / 2),
      new Proxy(new Uint8Array(EPOCH_ID_LENGTH), {}),
      {
        byteLength: EPOCH_ID_LENGTH,
        buffer: new ArrayBuffer(EPOCH_ID_LENGTH),
        [Symbol.toStringTag]: 'Uint8Array',
      },
      null,
    ];
    if (typeof SharedArrayBuffer !== 'undefined') {
      invalidEpochIds.push(
        new Uint8Array(new SharedArrayBuffer(EPOCH_ID_LENGTH)),
      );
    }

    for (const epochId of invalidEpochIds) {
      await expect(
        acl.grant(
          'user2',
          '/doc/admin',
          'doc-1',
          {} as CryptoKey,
          'issuer-b64',
          [],
          epochId,
        ),
      ).rejects.toThrow(/UCAN ACL epoch ID/);
    }
    expect(mockCreateUCAN).not.toHaveBeenCalled();
    expect(backing.add).not.toHaveBeenCalled();
    await expect(acl.getEntry('user2')).resolves.toBeUndefined();
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
    const epochId = Uint8Array.from(
      { length: EPOCH_ID_LENGTH },
      (_, index) => index,
    );
    const originalEpochId = new Uint8Array(epochId);
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
    expect(second!.epochId).toEqual(originalEpochId);
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
    const objectAcl = new UCANACLImpl(rewrapBacking(), serialize, deserialize);
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
    const withoutDeserializer = new UCANACLImpl(rewrapBacking(), serialize);
    backing.add.mockResolvedValue('changes');

    await expect(withoutDeserializer.add(identity)).rejects.toThrow(
      /requires a public-key deserializer for mutable identities/,
    );
    expect(backing.add).not.toHaveBeenCalled();

    const aliasingDeserializer = new UCANACLImpl(
      rewrapBacking(),
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
      rewrapBacking(),
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

  test('getEntry requires detached snapshots for mutable identities', async () => {
    const objectAcl = new UCANACLImpl(
      rewrapBacking(),
      jest.fn(async (key: { id: string }) => `serialized:${key.id}`),
    );

    await expect(objectAcl.getEntry({ id: 'user-a' })).rejects.toThrow(
      /requires a public-key deserializer for mutable identities/,
    );
  });

  test('getEntry binds lookup to a detached canonical identity snapshot', async () => {
    const callerIdentity = { id: 'user-a' };
    let lookupStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      lookupStarted = resolve;
    });
    let releaseLookup!: () => void;
    const release = new Promise<void>((resolve) => {
      releaseLookup = resolve;
    });
    let blockLookup = false;
    const serialize = jest.fn((key: { id: string }) => {
      const capturedId = key.id;
      return (async () => {
        if (blockLookup && key === callerIdentity) {
          lookupStarted();
          await release;
        }
        return `serialized:${capturedId}`;
      })();
    });
    const deserialize = jest.fn(async (serialized: string) => ({
      id: serialized.slice('serialized:'.length),
    }));
    const objectAcl = new UCANACLImpl(rewrapBacking(), serialize, deserialize);
    mockCreateUCAN.mockResolvedValue(
      makeFakeUcan({
        audience: 'serialized:user-a',
        capabilities: [{ resource: 'doc-1', ability: '/doc/read' }],
      }),
    );
    backing.add.mockResolvedValue('changes');
    await objectAcl.grant(
      { id: 'user-a' },
      '/doc/read',
      'doc-1',
      {} as CryptoKey,
      'issuer',
    );

    blockLookup = true;
    const lookup = objectAcl.getEntry(callerIdentity);
    await started;
    callerIdentity.id = 'user-b';
    releaseLookup();

    await expect(lookup).resolves.toMatchObject({
      publicKeyBase64: 'serialized:user-a',
    });
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

  test('rejects a second UCAN ACL over the same backing instance', () => {
    const sharedBacking = makeMockAcl();
    const serialize = jest.fn(async (key: string) => key);

    expect(new UCANACLImpl(sharedBacking, serialize)).toBeInstanceOf(
      UCANACLImpl,
    );
    expect(() => new UCANACLImpl(sharedBacking, serialize)).toThrow(
      /already wrapped by another UCAN ACL/,
    );
    expect(new UCANACLImpl({ ...sharedBacking }, serialize)).toBeInstanceOf(
      UCANACLImpl,
    );
  });

  test('rejects a backing provider that reuses mutable ACL state', () => {
    const sharedBacking = makeMockAcl();
    const backingProvider = {
      initialize: jest.fn(() => sharedBacking),
    };
    const provider = new UCANACLProviderImpl(
      backingProvider,
      jest.fn(async (key: string) => key),
    );

    expect(provider.initialize()).toBeInstanceOf(UCANACLImpl);
    expect(() => provider.initialize()).toThrow(
      /initialize\(\) must return isolated ACL state/,
    );
    expect(backingProvider.initialize).toHaveBeenCalledTimes(2);
  });
});
