/** An allowance that refills continuously up to its capacity. */
export class RefillingBucket {
  private balance: number
  private refilledAt: number

  constructor(
    readonly capacity: number,
    private readonly perMs: number,
    now: number,
  ) {
    this.balance = capacity
    this.refilledAt = now
  }

  available(now: number): number {
    if (now > this.refilledAt) {
      this.balance = Math.min(
        this.capacity,
        this.balance + (now - this.refilledAt) * this.perMs,
      )
      this.refilledAt = now
    }
    return this.balance
  }

  /** Charges the amount even past zero and reports whether the balance covered it. */
  spend(amount: number, now: number): boolean {
    this.balance = this.available(now) - amount
    return this.balance >= 0
  }

  msUntil(amount: number, now: number): number {
    return Math.max(0, (amount - this.available(now)) / this.perMs)
  }
}
