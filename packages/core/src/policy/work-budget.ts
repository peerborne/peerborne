/** Internal policy for non-negative safe-integer resource counters. */
export function consumeWorkBudget(
  used: number,
  amount: number,
  limit: number,
): number {
  //@ verify
  //@ requires 0 <= used && used <= limit && limit <= 9007199254740991
  //@ requires 0 <= amount && amount <= 9007199254740991
  //@ ensures \result === -1 <==> amount > limit - used
  //@ ensures \result !== -1 ==> \result === used + amount
  //@ ensures \result !== -1 ==> used <= \result && \result <= limit
  if (amount > limit - used) return -1;
  return used + amount;
}
