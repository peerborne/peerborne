export const MAX_CONNECTION_ATTEMPTS = 3;

export function shouldRetryConnection(
  retryable: boolean,
  aborted: boolean,
  attempt: number,
  maximum: number,
): boolean {
  //@ verify
  //@ requires 1 <= attempt && attempt <= MAX_CONNECTION_ATTEMPTS
  //@ requires 1 <= maximum && maximum <= MAX_CONNECTION_ATTEMPTS
  //@ ensures \result <==> retryable && !aborted && attempt < maximum
  return retryable && !aborted && attempt < maximum;
}
