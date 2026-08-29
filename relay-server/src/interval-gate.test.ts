import { IntervalGate } from './interval-gate.js'

describe('IntervalGate', () => {
  it('opens immediately and at most once per interval', () => {
    let now = 1_000
    const gate = new IntervalGate(60_000, () => now)

    expect(gate.open()).toBe(true)
    expect(gate.open()).toBe(false)
    now += 59_999
    expect(gate.open()).toBe(false)
    now += 1
    expect(gate.open()).toBe(true)
  })

  it('resets safely when the wall clock moves backwards', () => {
    let now = 100_000
    const gate = new IntervalGate(1_000, () => now)

    expect(gate.open()).toBe(true)
    now = 10
    expect(gate.open()).toBe(false)
    now = 1_010
    expect(gate.open()).toBe(true)
  })

  it('rejects invalid intervals and fails closed for an invalid clock', () => {
    expect(() => new IntervalGate(-1)).toThrow()
    expect(() => new IntervalGate(Number.NaN)).toThrow()
    expect(new IntervalGate(0, () => Number.NaN).open()).toBe(false)
  })
})
