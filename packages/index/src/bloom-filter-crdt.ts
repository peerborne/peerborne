/**
 * A Bloom filter implemented as a grow-only CRDT.
 *
 * Merge semantics: bitwise OR -- bits can be set but never unset.
 * This makes it a valid state-based CRDT (join-semilattice).
 *
 * Uses double hashing: h(i, x) = h1(x) + i * h2(x) mod m
 * where h1 and h2 are two independent hash functions derived from FNV-1a.
 *
 * Reference: "CRDTs for Approximate Membership Queries" (PaPoC 2025)
 */
export class BloomFilterCRDT {
  private _bits: Uint8Array;
  private _numHashFunctions: number;
  private _sizeInBits: number;

  /**
   * @param sizeInBits Total number of bits in the filter (default: 65536 = 8 KB).
   * @param numHashFunctions Number of hash functions (default: 7).
   */
  constructor(sizeInBits: number = 65536, numHashFunctions: number = 7) {
    if (!Number.isInteger(sizeInBits) || sizeInBits <= 0) {
      throw new RangeError(`sizeInBits must be a positive integer, got ${sizeInBits}`);
    }
    if (!Number.isInteger(numHashFunctions) || numHashFunctions <= 0) {
      throw new RangeError(`numHashFunctions must be a positive integer, got ${numHashFunctions}`);
    }
    this._sizeInBits = sizeInBits;
    this._numHashFunctions = numHashFunctions;
    this._bits = new Uint8Array(Math.ceil(sizeInBits / 8));
  }

  /** Number of bits in the filter. */
  get sizeInBits(): number { return this._sizeInBits; }

  /** Number of hash functions. */
  get numHashFunctions(): number { return this._numHashFunctions; }

  /**
   * Add a term to the filter.
   */
  add(term: string): void {
    const [h1, h2] = this._baseHashes(term);
    for (let i = 0; i < this._numHashFunctions; i++) {
      const bitIndex = Math.abs((h1 + i * h2) % this._sizeInBits);
      this._setBit(bitIndex);
    }
  }

  /**
   * Test if a term might be in the filter.
   * False positives are possible; false negatives are not.
   */
  has(term: string): boolean {
    const [h1, h2] = this._baseHashes(term);
    for (let i = 0; i < this._numHashFunctions; i++) {
      const bitIndex = Math.abs((h1 + i * h2) % this._sizeInBits);
      if (!this._getBit(bitIndex)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Merge another Bloom filter into this one (bitwise OR).
   * This is the CRDT join operation.
   * Both filters must have the same size and number of hash functions.
   */
  merge(other: BloomFilterCRDT): void {
    if (this._sizeInBits !== other._sizeInBits) {
      throw new Error(`Cannot merge filters of different sizes: ${this._sizeInBits} vs ${other._sizeInBits}`);
    }
    if (this._numHashFunctions !== other._numHashFunctions) {
      throw new Error(`Cannot merge filters with different hash function counts: ${this._numHashFunctions} vs ${other._numHashFunctions}`);
    }
    for (let i = 0; i < this._bits.length; i++) {
      this._bits[i] |= other._bits[i];
    }
  }

  /**
   * Serialize the filter to bytes for transmission.
   */
  serialize(): Uint8Array {
    return new Uint8Array(this._bits);
  }

  /**
   * Deserialize a filter from bytes.
   */
  static deserialize(data: Uint8Array, sizeInBits: number, numHashFunctions: number = 7): BloomFilterCRDT {
    const expectedLength = Math.ceil(sizeInBits / 8);
    if (data.length !== expectedLength) {
      throw new Error(`Expected ${expectedLength} bytes for ${sizeInBits}-bit filter, got ${data.length}`);
    }
    const filter = new BloomFilterCRDT(sizeInBits, numHashFunctions);
    filter._bits = new Uint8Array(data);
    return filter;
  }

  /**
   * Returns the fill ratio (fraction of bits that are set).
   * Useful for estimating false positive rate and deciding when to resize.
   */
  fillRatio(): number {
    let count = 0;
    for (let i = 0; i < this._bits.length; i++) {
      // Count bits set in each byte (Brian Kernighan's method)
      let byte = this._bits[i];
      while (byte) {
        byte &= byte - 1;
        count++;
      }
    }
    return count / this._sizeInBits;
  }

  private _setBit(index: number): void {
    const byteIndex = Math.floor(index / 8);
    const bitOffset = index % 8;
    this._bits[byteIndex] |= (1 << bitOffset);
  }

  private _getBit(index: number): boolean {
    const byteIndex = Math.floor(index / 8);
    const bitOffset = index % 8;
    return (this._bits[byteIndex] & (1 << bitOffset)) !== 0;
  }

  /**
   * Compute two independent hash values using FNV-1a variants.
   * Double hashing: h(i) = h1(x) + i * h2(x)
   */
  private _baseHashes(term: string): [number, number] {
    // FNV-1a hash (32-bit)
    let h1 = 0x811c9dc5; // FNV offset basis
    for (let i = 0; i < term.length; i++) {
      h1 ^= term.charCodeAt(i);
      h1 = Math.imul(h1, 0x01000193); // FNV prime
    }

    // Second hash: FNV-1a with different seed
    let h2 = 0x6c62272e; // Different offset basis
    for (let i = 0; i < term.length; i++) {
      h2 ^= term.charCodeAt(i);
      h2 = Math.imul(h2, 0x01000193);
    }
    // Ensure h2 is odd (better distribution with double hashing)
    h2 = h2 | 1;

    return [h1 >>> 0, h2 >>> 0]; // unsigned
  }
}
