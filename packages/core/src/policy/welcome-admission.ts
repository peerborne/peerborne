export interface PendingWelcomeMetadata {
  readonly key: string;
  readonly bytes: number;
  readonly authenticated: boolean;
}

export interface PendingWelcomeBudget {
  readonly total: number;
  readonly protectedBytes: number;
  readonly protectedCount: number;
  readonly previousBytes: number;
}

export interface PendingWelcomePlan {
  readonly admitted: boolean;
  readonly replaced: boolean;
  readonly kept: readonly PendingWelcomeMetadata[];
  readonly evictedKeys: readonly string[];
  readonly retainedBytes: number;
}

export interface PendingWelcomeRemoval {
  readonly kept: readonly PendingWelcomeMetadata[];
  readonly retainedBytes: number;
  readonly removed: boolean;
}

export function pendingWelcomeBudget(
  entries: readonly PendingWelcomeMetadata[],
  key: string,
): PendingWelcomeBudget {
  //@ verify
  //@ requires entries.length <= 16
  //@ requires forall(i: int, 0 <= i && i < entries.length ==> 1 <= entries[i].bytes && entries[i].bytes <= 10485760)
  //@ requires forall(i: int, forall(j: int, 0 <= i && i < j && j < entries.length ==> entries[i].key !== entries[j].key))
  //@ ensures 0 <= \result.total && \result.total <= entries.length * 10485760
  //@ ensures 0 <= \result.protectedBytes && \result.protectedBytes <= \result.total
  //@ ensures 0 <= \result.protectedCount && \result.protectedCount <= entries.length
  //@ ensures 0 <= \result.previousBytes && \result.previousBytes <= 10485760
  //@ ensures \result.previousBytes === 0 <==> forall(i: int, 0 <= i && i < entries.length ==> entries[i].key !== key)
  //@ ensures \result.previousBytes > 0 ==> exists(i: int, 0 <= i && i < entries.length && entries[i].key === key && entries[i].bytes === \result.previousBytes)
  let total = 0;
  let protectedBytes = 0;
  let protectedCount = 0;
  let previousBytes = 0;
  for (let index = 0; index < entries.length; index++) {
    //@ invariant 0 <= index && index <= entries.length
    //@ invariant 0 <= total && total <= index * 10485760
    //@ invariant 0 <= protectedBytes && protectedBytes <= total
    //@ invariant 0 <= protectedCount && protectedCount <= index
    //@ invariant 0 <= previousBytes && previousBytes <= 10485760
    //@ invariant previousBytes === 0 <==> forall(i: int, 0 <= i && i < index ==> entries[i].key !== key)
    //@ invariant previousBytes > 0 ==> exists(i: int, 0 <= i && i < index && entries[i].key === key && entries[i].bytes === previousBytes)
    //@ decreases entries.length - index
    const entry = entries[index];
    total += entry.bytes;
    if (entry.authenticated) {
      protectedBytes += entry.bytes;
      protectedCount++;
    }
    if (entry.key === key) previousBytes = entry.bytes;
  }
  return { total, protectedBytes, protectedCount, previousBytes };
}

export function canAdmitPendingWelcome(
  existing: boolean,
  authenticated: boolean,
  protectedCount: number,
  protectedBytes: number,
  incomingBytes: number,
  maximumEntries: number,
  maximumBytes: number,
): boolean {
  //@ verify
  //@ requires 0 <= protectedCount && protectedCount <= 16
  //@ requires 0 <= protectedBytes && protectedBytes <= 167772160
  //@ requires 1 <= maximumEntries && maximumEntries <= 16
  //@ requires 1 <= incomingBytes && incomingBytes <= 10485760
  //@ requires incomingBytes <= maximumBytes && maximumBytes <= 20971520
  //@ ensures \result <==> (!existing || authenticated) && (authenticated || (protectedCount < maximumEntries && protectedBytes <= maximumBytes - incomingBytes))
  return (
    (!existing || authenticated) &&
    (authenticated ||
      (protectedCount < maximumEntries &&
        protectedBytes <= maximumBytes - incomingBytes))
  );
}

export function planPendingWelcomeAdmission(
  entries: readonly PendingWelcomeMetadata[],
  key: string,
  incomingBytes: number,
  authenticated: boolean,
  maximumEntries: number,
  maximumBytes: number,
): PendingWelcomePlan {
  //@ verify
  //@ requires entries.length <= 16
  //@ requires forall(i: int, 0 <= i && i < entries.length ==> 1 <= entries[i].bytes && entries[i].bytes <= 10485760)
  //@ requires forall(i: int, forall(j: int, 0 <= i && i < j && j < entries.length ==> entries[i].key !== entries[j].key))
  //@ requires 1 <= maximumEntries && maximumEntries <= 16
  //@ requires 1 <= incomingBytes && incomingBytes <= 10485760
  //@ requires incomingBytes <= maximumBytes && maximumBytes <= 20971520
  //@ ensures \result.kept.length <= entries.length
  //@ ensures forall(i: int, 0 <= i && i < \result.kept.length ==> entries.includes(\result.kept[i]))
  //@ ensures forall(i: int, forall(j: int, 0 <= i && i < j && j < \result.kept.length ==> \result.kept[i].key !== \result.kept[j].key))
  //@ ensures 0 <= \result.retainedBytes && \result.retainedBytes <= 167772160
  //@ ensures \result.admitted ==> \result.kept.length < maximumEntries && \result.retainedBytes <= maximumBytes
  //@ ensures \result.admitted ==> forall(i: int, 0 <= i && i < \result.kept.length ==> \result.kept[i].key !== key)
  //@ ensures !\result.admitted ==> !\result.replaced && \result.evictedKeys.length === 0 && \result.kept.length === entries.length
  //@ ensures !\result.admitted ==> forall(i: int, 0 <= i && i < entries.length ==> \result.kept[i] === entries[i])
  //@ ensures !authenticated ==> forall(i: int, 0 <= i && i < entries.length && entries[i].authenticated ==> \result.kept.includes(entries[i]))
  //@ ensures \result.replaced <==> \result.admitted && exists(i: int, 0 <= i && i < entries.length && entries[i].key === key)
  //@ ensures \result.admitted ==> \result.kept.length + \result.evictedKeys.length + (\result.replaced ? 1 : 0) === entries.length
  const budget = pendingWelcomeBudget(entries, key);
  if (
    !canAdmitPendingWelcome(
      budget.previousBytes > 0,
      authenticated,
      budget.protectedCount,
      budget.protectedBytes,
      incomingBytes,
      maximumEntries,
      maximumBytes,
    )
  ) {
    return {
      admitted: false,
      replaced: false,
      kept: [...entries],
      evictedKeys: [],
      retainedBytes: budget.total,
    };
  }
  const removal = planPendingWelcomeRemoval(entries, key);
  if (
    removal.kept.length < maximumEntries &&
    removal.retainedBytes <= maximumBytes - incomingBytes
  ) {
    return {
      admitted: true,
      replaced: removal.removed,
      kept: removal.kept,
      evictedKeys: [],
      retainedBytes: removal.retainedBytes + incomingBytes,
    };
  }
  const unverified = trimPendingWelcomes(
    removal.kept,
    incomingBytes,
    false,
    maximumEntries,
    maximumBytes,
  );
  if (
    authenticated &&
    (unverified.kept.length >= maximumEntries ||
      unverified.retainedBytes > maximumBytes - incomingBytes)
  ) {
    const trusted = trimPendingWelcomes(
      unverified.kept,
      incomingBytes,
      true,
      maximumEntries,
      maximumBytes,
    );
    return {
      admitted: true,
      replaced: removal.removed,
      kept: trusted.kept,
      evictedKeys: [...unverified.evictedKeys, ...trusted.evictedKeys],
      retainedBytes: trusted.retainedBytes + incomingBytes,
    };
  }
  return {
    admitted: true,
    replaced: removal.removed,
    kept: unverified.kept,
    evictedKeys: unverified.evictedKeys,
    retainedBytes: unverified.retainedBytes + incomingBytes,
  };
}

export function planPendingWelcomeRemoval(
  entries: readonly PendingWelcomeMetadata[],
  key: string,
): PendingWelcomeRemoval {
  //@ verify
  //@ requires entries.length <= 16
  //@ requires forall(i: int, 0 <= i && i < entries.length ==> 1 <= entries[i].bytes && entries[i].bytes <= 10485760)
  //@ requires forall(i: int, forall(j: int, 0 <= i && i < j && j < entries.length ==> entries[i].key !== entries[j].key))
  //@ ensures \result.kept.length <= entries.length
  //@ ensures 0 <= \result.retainedBytes && \result.retainedBytes <= \result.kept.length * 10485760
  //@ ensures forall(i: int, 0 <= i && i < \result.kept.length ==> entries.includes(\result.kept[i]) && \result.kept[i].key !== key)
  //@ ensures forall(i: int, 0 <= i && i < entries.length ==> (\result.kept.includes(entries[i]) <==> entries[i].key !== key))
  //@ ensures forall(i: int, forall(j: int, 0 <= i && i < j && j < \result.kept.length ==> \result.kept[i].key !== \result.kept[j].key))
  //@ ensures \result.removed <==> exists(i: int, 0 <= i && i < entries.length && entries[i].key === key)
  //@ ensures \result.kept.length + (\result.removed ? 1 : 0) === entries.length
  const kept: PendingWelcomeMetadata[] = [];
  let retainedBytes = 0;
  let removed = false;
  for (let index = 0; index < entries.length; index++) {
    //@ invariant 0 <= index && index <= entries.length
    //@ invariant kept.length <= index
    //@ invariant 0 <= retainedBytes && retainedBytes <= kept.length * 10485760
    //@ invariant forall(i: int, 0 <= i && i < kept.length ==> exists(j: int, 0 <= j && j < index && entries[j] === kept[i]) && kept[i].key !== key)
    //@ invariant forall(i: int, 0 <= i && i < index ==> (kept.includes(entries[i]) <==> entries[i].key !== key))
    //@ invariant forall(i: int, forall(j: int, 0 <= i && i < j && j < kept.length ==> kept[i].key !== kept[j].key))
    //@ invariant removed <==> exists(i: int, 0 <= i && i < index && entries[i].key === key)
    //@ invariant kept.length + (removed ? 1 : 0) === index
    //@ decreases entries.length - index
    const entry = entries[index];
    if (entry.key === key) {
      removed = true;
    } else {
      kept.push(entry);
      retainedBytes += entry.bytes;
    }
  }
  return { kept, retainedBytes, removed };
}

/** @internal Project owned values without copying their retained byte bodies. */
export function retainPendingWelcomeValues<Value>(
  values: Map<string, Value>,
  kept: readonly PendingWelcomeMetadata[],
): Map<string, Value> {
  //@ verify
  //@ type Value (==)
  //@ requires kept.length <= 16
  //@ requires forall(i: int, 0 <= i && i < kept.length ==> values.has(kept[i].key))
  //@ requires forall(i: int, forall(j: int, 0 <= i && i < j && j < kept.length ==> kept[i].key !== kept[j].key))
  //@ ensures \result.size === kept.length
  //@ ensures forall(key: string, \result.has(key) <==> exists(i: int, 0 <= i && i < kept.length && kept[i].key === key))
  //@ ensures forall(key: string, \result.has(key) ==> values.has(key) && \result.get(key) === values.get(key))
  const result = new Map<string, Value>();
  for (let index = 0; index < kept.length; index++) {
    //@ invariant 0 <= index && index <= kept.length
    //@ invariant result.size === index
    //@ invariant forall(key: string, result.has(key) <==> exists(i: int, 0 <= i && i < index && kept[i].key === key))
    //@ invariant forall(key: string, result.has(key) ==> values.has(key) && result.get(key) === values.get(key))
    //@ decreases kept.length - index
    const key = kept[index].key;
    result.set(key, values.get(key)!);
  }
  return result;
}

/** @internal Install one owned body after the retained projection is prepared. */
export function insertPendingWelcomeValue<Value>(
  values: Map<string, Value>,
  key: string,
  value: Value,
): Map<string, Value> {
  //@ verify
  //@ type Value (==)
  //@ requires !values.has(key) && values.size < 16
  //@ ensures \result.size === values.size + 1
  //@ ensures \result.has(key) && \result.get(key) === value
  //@ ensures forall(other: string, \result.has(other) <==> values.has(other) || other === key)
  //@ ensures forall(other: string, values.has(other) ==> \result.has(other) && \result.get(other) === values.get(other))
  const result = new Map(values);
  result.set(key, value);
  return result;
}

export interface PendingWelcomePressure {
  readonly kept: readonly PendingWelcomeMetadata[];
  readonly evictedKeys: readonly string[];
  readonly retainedBytes: number;
}

export function trimPendingWelcomes(
  entries: readonly PendingWelcomeMetadata[],
  incomingBytes: number,
  allowAuthenticated: boolean,
  maximumEntries: number,
  maximumBytes: number,
): PendingWelcomePressure {
  //@ verify
  //@ requires entries.length <= 16
  //@ requires forall(i: int, 0 <= i && i < entries.length ==> 1 <= entries[i].bytes && entries[i].bytes <= 10485760)
  //@ requires forall(i: int, forall(j: int, 0 <= i && i < j && j < entries.length ==> entries[i].key !== entries[j].key))
  //@ requires 1 <= maximumEntries && maximumEntries <= 16
  //@ requires 1 <= incomingBytes && incomingBytes <= 10485760
  //@ requires incomingBytes <= maximumBytes && maximumBytes <= 20971520
  //@ ensures \result.kept.length <= entries.length
  //@ ensures forall(i: int, 0 <= i && i < \result.kept.length ==> entries.includes(\result.kept[i]))
  //@ ensures forall(i: int, forall(j: int, 0 <= i && i < j && j < \result.kept.length ==> \result.kept[i].key !== \result.kept[j].key))
  //@ ensures \result.kept.length + \result.evictedKeys.length === entries.length
  //@ ensures 0 <= \result.retainedBytes && \result.retainedBytes <= 167772160
  //@ ensures !allowAuthenticated ==> forall(i: int, 0 <= i && i < entries.length && entries[i].authenticated ==> \result.kept.includes(entries[i]))
  //@ ensures allowAuthenticated ==> \result.kept.length < maximumEntries && \result.retainedBytes <= maximumBytes - incomingBytes
  const budget = pendingWelcomeBudget(entries, '');
  let remainingCount = entries.length;
  let remainingBytes = budget.total;
  const kept: PendingWelcomeMetadata[] = [];
  const evictedKeys: string[] = [];
  for (let index = 0; index < entries.length; index++) {
    //@ invariant 0 <= index && index <= entries.length
    //@ invariant kept.length <= index
    //@ invariant 0 <= remainingCount && remainingCount <= entries.length
    //@ invariant 0 <= remainingBytes && remainingBytes <= 167772160
    //@ invariant remainingCount + evictedKeys.length === entries.length
    //@ decreases entries.length - index
    const entry = entries[index];
    if (
      (allowAuthenticated || !entry.authenticated) &&
      (remainingCount >= maximumEntries ||
        remainingBytes > maximumBytes - incomingBytes)
    ) {
      evictedKeys.push(entry.key);
      remainingCount--;
      remainingBytes -= entry.bytes;
    } else {
      kept.push(entry);
    }
  }
  return { kept, evictedKeys, retainedBytes: remainingBytes };
}

export function advancePendingWelcomeClock(
  previous: number,
  now: number,
): number {
  //@ verify
  //@ requires 0 <= previous && previous <= 9007199254740991
  //@ requires 0 <= now && now <= 9007199254740991
  //@ ensures \result === (previous >= now ? previous : now)
  //@ ensures previous <= \result && now <= \result && \result <= 9007199254740991
  return previous >= now ? previous : now;
}

export function isPendingWelcomeExpired(
  bufferedAtMs: number,
  now: number,
  ttl: number,
): boolean {
  //@ verify
  //@ requires 0 <= bufferedAtMs && bufferedAtMs <= 9007199254740991
  //@ requires 0 <= now && now <= 9007199254740991
  //@ requires 0 <= ttl && ttl <= 9007199254740991
  //@ ensures \result <==> now - bufferedAtMs > ttl
  //@ ensures \result ==> bufferedAtMs < now
  return now - bufferedAtMs > ttl;
}

export interface PendingWelcomeExpiry {
  readonly kept: readonly PendingWelcomeMetadata[];
  readonly expiredKeys: readonly string[];
  readonly retainedBytes: number;
}

export function planPendingWelcomeExpiry(
  entries: readonly PendingWelcomeMetadata[],
  bufferedAtMs: readonly number[],
  now: number,
  ttl: number,
): PendingWelcomeExpiry {
  //@ verify
  //@ requires entries.length <= 16 && bufferedAtMs.length === entries.length
  //@ requires forall(i: int, 0 <= i && i < entries.length ==> 1 <= entries[i].bytes && entries[i].bytes <= 10485760 && 0 <= bufferedAtMs[i] && bufferedAtMs[i] <= 9007199254740991)
  //@ requires forall(i: int, forall(j: int, 0 <= i && i < j && j < entries.length ==> entries[i].key !== entries[j].key))
  //@ requires 0 <= now && now <= 9007199254740991
  //@ requires 0 <= ttl && ttl <= 9007199254740991
  //@ ensures \result.kept.length + \result.expiredKeys.length === entries.length
  //@ ensures 0 <= \result.retainedBytes && \result.retainedBytes <= \result.kept.length * 10485760
  //@ ensures forall(i: int, 0 <= i && i < \result.kept.length ==> entries.includes(\result.kept[i]))
  //@ ensures forall(i: int, 0 <= i && i < entries.length ==> (\result.kept.includes(entries[i]) <==> !isPendingWelcomeExpired(bufferedAtMs[i], now, ttl)))
  //@ ensures forall(i: int, 0 <= i && i < entries.length ==> (\result.expiredKeys.includes(entries[i].key) <==> isPendingWelcomeExpired(bufferedAtMs[i], now, ttl)))
  //@ ensures forall(key: string, \result.expiredKeys.includes(key) ==> exists(j: int, 0 <= j && j < entries.length && entries[j].key === key && isPendingWelcomeExpired(bufferedAtMs[j], now, ttl)))
  //@ ensures forall(i: int, forall(j: int, 0 <= i && i < j && j < \result.kept.length ==> \result.kept[i].key !== \result.kept[j].key))
  const kept: PendingWelcomeMetadata[] = [];
  const expiredKeys: string[] = [];
  let retainedBytes = 0;
  for (let index = 0; index < entries.length; index++) {
    //@ invariant 0 <= index && index <= entries.length
    //@ invariant kept.length + expiredKeys.length === index
    //@ invariant 0 <= retainedBytes && retainedBytes <= kept.length * 10485760
    //@ invariant forall(i: int, 0 <= i && i < kept.length ==> exists(j: int, 0 <= j && j < index && entries[j] === kept[i]))
    //@ invariant forall(i: int, 0 <= i && i < index ==> (kept.includes(entries[i]) <==> !isPendingWelcomeExpired(bufferedAtMs[i], now, ttl)))
    //@ invariant forall(i: int, 0 <= i && i < index ==> (expiredKeys.includes(entries[i].key) <==> isPendingWelcomeExpired(bufferedAtMs[i], now, ttl)))
    //@ invariant forall(key: string, expiredKeys.includes(key) ==> exists(j: int, 0 <= j && j < index && entries[j].key === key && isPendingWelcomeExpired(bufferedAtMs[j], now, ttl)))
    //@ invariant forall(i: int, forall(j: int, 0 <= i && i < j && j < kept.length ==> kept[i].key !== kept[j].key))
    //@ decreases entries.length - index
    const entry = entries[index];
    if (isPendingWelcomeExpired(bufferedAtMs[index], now, ttl)) {
      expiredKeys.push(entry.key);
    } else {
      kept.push(entry);
      retainedBytes += entry.bytes;
    }
  }
  return { kept, expiredKeys, retainedBytes };
}
