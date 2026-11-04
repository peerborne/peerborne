export interface CapturedDocumentMember {
  readonly id: string;
  readonly publicKey: string;
  readonly role: number;
}

export interface CapturedDocumentRoster {
  readonly valid: boolean;
  readonly members: Map<string, CapturedDocumentMember>;
}

export function isCapturedDocumentMemberValid(
  count: number,
  duplicate: boolean,
  idLength: number,
  publicKeyLength: number,
  role: number,
): boolean {
  //@ verify
  //@ requires 0 <= count && count <= 256
  //@ requires 0 <= idLength && idLength <= 9007199254740991
  //@ requires 0 <= publicKeyLength && publicKeyLength <= 9007199254740991
  //@ requires -9007199254740991 <= role && role <= 9007199254740991
  //@ ensures \result <==> count < 256 && !duplicate && idLength === 64 && 1 <= publicKeyLength && publicKeyLength <= 16384 && (role === 1 || role === 2 || role === 3)
  return (
    count < 256 &&
    !duplicate &&
    idLength === 64 &&
    publicKeyLength >= 1 &&
    publicKeyLength <= 16384 &&
    (role === 1 || role === 2 || role === 3)
  );
}

/** @internal Build a bounded roster from detached scalar snapshots. */
export function captureDocumentRoster(
  entries: readonly CapturedDocumentMember[],
  localId: string,
): CapturedDocumentRoster {
  //@ verify
  //@ requires entries.length <= 256
  //@ requires forall(i: int, 0 <= i && i < entries.length ==> entries[i].id.length <= 9007199254740991 && entries[i].publicKey.length <= 9007199254740991 && -9007199254740991 <= entries[i].role && entries[i].role <= 9007199254740991)
  //@ ensures !\result.valid ==> \result.members.size === 0
  //@ ensures \result.valid ==> \result.members.size === entries.length && \result.members.size <= 256 && \result.members.has(localId)
  //@ ensures \result.valid ==> forall(key: string, \result.members.has(key) <==> exists(i: int, 0 <= i && i < entries.length && entries[i].id === key))
  //@ ensures \result.valid ==> forall(i: int, 0 <= i && i < entries.length ==> \result.members.has(entries[i].id) && \result.members.get(entries[i].id) === entries[i])
  //@ ensures \result.valid <==> 1 <= entries.length && exists(i: int, 0 <= i && i < entries.length && entries[i].id === localId) && forall(i: int, 0 <= i && i < entries.length ==> entries[i].id.length === 64 && 1 <= entries[i].publicKey.length && entries[i].publicKey.length <= 16384 && (entries[i].role === 1 || entries[i].role === 2 || entries[i].role === 3)) && forall(i: int, forall(j: int, 0 <= i && i < j && j < entries.length ==> entries[i].id !== entries[j].id))
  if (entries.length === 0) return { valid: false, members: new Map() };
  const members = new Map<string, CapturedDocumentMember>();
  for (let index = 0; index < entries.length; index++) {
    //@ invariant 0 <= index && index <= entries.length
    //@ invariant members.size === index
    //@ invariant forall(key: string, members.has(key) <==> exists(i: int, 0 <= i && i < index && entries[i].id === key))
    //@ invariant forall(i: int, 0 <= i && i < index ==> members.has(entries[i].id) && members.get(entries[i].id) === entries[i])
    //@ invariant forall(i: int, 0 <= i && i < index ==> entries[i].id.length === 64 && 1 <= entries[i].publicKey.length && entries[i].publicKey.length <= 16384 && (entries[i].role === 1 || entries[i].role === 2 || entries[i].role === 3))
    //@ invariant forall(i: int, forall(j: int, 0 <= i && i < j && j < index ==> entries[i].id !== entries[j].id))
    //@ decreases entries.length - index
    const entry = entries[index];
    if (
      !isCapturedDocumentMemberValid(
        members.size,
        members.has(entry.id),
        entry.id.length,
        entry.publicKey.length,
        entry.role,
      )
    ) {
      return { valid: false, members: new Map() };
    }
    members.set(entry.id, entry);
  }
  if (!members.has(localId)) return { valid: false, members: new Map() };
  return { valid: true, members };
}
