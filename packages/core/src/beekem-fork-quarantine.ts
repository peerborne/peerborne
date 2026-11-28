import { assertBoundedUtf8 } from './internal/canonical-encoding.js';
import { canAdvanceBeeKEMForkAnchor } from './policy/beekem-fork-anchor.js';
import { snapshotEnumerableOwnDataObject } from './internal/data-snapshot.js';
import { MAX_DOCUMENT_PATH_LENGTH } from './shared-protocol-request.js';
import { randomHex } from './internal/random.js';

export interface BeeKEMForkScope {
  readonly documentPath: string;
  /** Canonical application authentication identity, independent of libp2p. */
  readonly identity: string;
}

export type BeeKEMForkRecord =
  | { readonly phase: 'available'; readonly revision: number }
  | {
      readonly phase: 'active';
      readonly revision: number;
      readonly lease: string;
    }
  | {
      readonly phase: 'quarantined';
      readonly revision: number;
      readonly generation: number;
    };

/**
 * Application-owned storage that survives document loss and restart without
 * rollback. Every handle using a scope must share this exact CAS authority.
 * Keep enrolled records, including active and quarantined records, durable.
 */
export interface DurableBeeKEMForkStore {
  load(scope: BeeKEMForkScope): Promise<BeeKEMForkRecord | undefined>;
  /** Compare all fields (or exact absence) and durably commit before returning true. */
  compareAndSwap(
    scope: BeeKEMForkScope,
    expected: BeeKEMForkRecord | undefined,
    next: BeeKEMForkRecord,
  ): Promise<boolean>;
}

const LEASE_PATTERN = /^[0-9a-f]{32}$/;

function captureRecord(input: BeeKEMForkRecord): BeeKEMForkRecord {
  const record = snapshotEnumerableOwnDataObject<Record<string, unknown>>(
    input,
    'BeeKEM fork anchor',
    { maxProperties: 3, maxKeyBytes: 64 },
  );
  const { phase, revision, lease, generation } = record;
  if (
    typeof revision === 'number' &&
    Number.isSafeInteger(revision) &&
    revision >= 0 &&
    !Object.is(revision, -0)
  ) {
    const fieldCount = Object.keys(record).length;
    if (phase === 'available' && fieldCount === 2) {
      return Object.freeze({ phase, revision });
    }
    if (
      phase === 'active' &&
      fieldCount === 3 &&
      typeof lease === 'string' &&
      LEASE_PATTERN.test(lease)
    ) {
      return Object.freeze({ phase, revision, lease });
    }
    if (
      phase === 'quarantined' &&
      fieldCount === 3 &&
      typeof generation === 'number' &&
      validGeneration(generation)
    ) {
      return Object.freeze({ phase, revision, generation });
    }
  }
  throw new Error('Invalid durable BeeKEM fork anchor');
}

function validGeneration(generation: number): boolean {
  return (
    Number.isInteger(generation) && generation > 0 && generation <= 0xffff_ffff
  );
}

/** One handle's ownership of its durable active record. */
export class BeeKEMForkQuarantine {
  private readonly load: DurableBeeKEMForkStore['load'];
  private readonly compareAndSwap: DurableBeeKEMForkStore['compareAndSwap'];
  private scope?: Promise<BeeKEMForkScope>;
  private acquisition?: Promise<void>;
  private active?: Extract<BeeKEMForkRecord, { phase: 'active' }>;
  private closing = false;
  private stopGeneration?: number;

  constructor(
    store: DurableBeeKEMForkStore,
    private readonly documentPath: string,
    private readonly serializeIdentity: () => string | Promise<string>,
  ) {
    this.load = store.load.bind(store);
    this.compareAndSwap = store.compareAndSwap.bind(store);
  }

  get acceptsWork(): boolean {
    return (
      this.active !== undefined &&
      !this.closing &&
      this.stopGeneration === undefined
    );
  }

  get acceptsSetup(): boolean {
    return (
      (this.acquisition === undefined && !this.closing) || this.acceptsWork
    );
  }

  get competingGeneration(): number | undefined {
    return this.stopGeneration;
  }

  assertAcceptsWork(): void {
    if (!this.acceptsWork)
      throw new Error('Durable BeeKEM fork guard blocks document access');
  }

  private getScope(): Promise<BeeKEMForkScope> {
    return (this.scope ??= this.captureScope());
  }

  private async captureScope(): Promise<BeeKEMForkScope> {
    assertBoundedUtf8(
      this.documentPath,
      MAX_DOCUMENT_PATH_LENGTH,
      'BeeKEM document path',
    );
    const identity = await this.serializeIdentity();
    assertBoundedUtf8(identity, 4096, 'BeeKEM document identity');
    return Object.freeze({ documentPath: this.documentPath, identity });
  }

  async provision(): Promise<boolean> {
    if (this.acquisition !== undefined || this.closing) {
      throw new Error('Provision a new BeeKEM fork scope before activation');
    }
    const scope = await this.getScope();
    if (this.acquisition !== undefined || this.closing) {
      throw new Error('Provision a new BeeKEM fork scope before activation');
    }
    return (
      (await this.compareAndSwap(
        scope,
        undefined,
        Object.freeze({ phase: 'available', revision: 0 }),
      )) === true
    );
  }

  async acquire(): Promise<void> {
    if (!this.closing) {
      await (this.acquisition ??= this.acquireOnce());
    }
    this.assertAcceptsWork();
  }

  private async acquireOnce(): Promise<void> {
    const scope = await this.getScope();
    const loaded = await this.load(scope);
    if (loaded === undefined)
      throw new Error('Durable BeeKEM fork scope is not provisioned');
    const expected = captureRecord(loaded);
    if (expected.phase === 'quarantined')
      this.stopGeneration = expected.generation;
    if (
      this.closing ||
      !canAdvanceBeeKEMForkAnchor(
        expected.phase,
        expected.revision,
        'acquire',
        false,
        false,
      )
    ) {
      throw new Error('Durable BeeKEM fork anchor blocks document activation');
    }
    const active = Object.freeze({
      phase: 'active',
      revision: expected.revision + 1,
      lease: randomHex(16),
    } as const);
    if ((await this.compareAndSwap(scope, expected, active)) !== true) {
      throw new Error('Durable BeeKEM fork anchor changed before activation');
    }
    this.active = active;
  }

  beginClose(): void {
    this.closing = true;
  }

  async quarantine(generation: number): Promise<void> {
    if (this.stopGeneration !== undefined) return;
    this.stopGeneration = generation;
    const expected = this.active;
    if (
      !expected ||
      !validGeneration(generation) ||
      !canAdvanceBeeKEMForkAnchor(
        expected.phase,
        expected.revision,
        'quarantine',
        true,
        true,
      )
    ) {
      throw new Error('Unable to persist the authenticated BeeKEM fork stop');
    }
    if (
      (await this.compareAndSwap(
        await this.getScope(),
        expected,
        Object.freeze({
          phase: 'quarantined',
          revision: expected.revision + 1,
          generation,
        }),
      )) !== true
    ) {
      throw new Error('Unable to persist the authenticated BeeKEM fork stop');
    }
  }

  async release(): Promise<void> {
    if (!this.closing)
      throw new Error('Close the BeeKEM fork guard before releasing');
    await this.acquisition?.catch(() => {});
    const expected = this.active;
    if (!expected) return;
    const scope = await this.getScope();
    if (
      !canAdvanceBeeKEMForkAnchor(
        expected.phase,
        expected.revision,
        'release',
        true,
        this.stopGeneration !== undefined,
      )
    ) {
      return;
    }
    if (
      (await this.compareAndSwap(
        scope,
        expected,
        Object.freeze({
          phase: 'available',
          revision: expected.revision + 1,
        }),
      )) !== true
    ) {
      throw new Error('Unable to release the durable BeeKEM fork lease');
    }
    this.active = undefined;
  }
}
