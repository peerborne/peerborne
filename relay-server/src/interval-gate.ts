export class IntervalGate {
  #lastOpenedAtMs: number | undefined

  constructor(
    private readonly intervalMs: number,
    private readonly now: () => number = Date.now,
  ) {
    if (!Number.isFinite(intervalMs) || intervalMs < 0) {
      throw new Error('IntervalGate interval must be finite and non-negative')
    }
  }

  open(): boolean {
    const nowMs = this.now()
    if (!Number.isFinite(nowMs)) {
      return false
    }
    if (this.#lastOpenedAtMs === undefined) {
      this.#lastOpenedAtMs = nowMs
      return true
    }
    if (nowMs < this.#lastOpenedAtMs) {
      this.#lastOpenedAtMs = nowMs
      return false
    }
    if (nowMs - this.#lastOpenedAtMs < this.intervalMs) {
      return false
    }
    this.#lastOpenedAtMs = nowMs
    return true
  }
}
