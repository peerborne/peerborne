const LOCK_NAME = 'peerborne-note-active-tab';

export interface SingleTabLease {
  readonly acquired: boolean;
  readonly supported: boolean;
  release(): void;
}

export async function acquireSingleTabLease(): Promise<SingleTabLease> {
  if (!navigator.locks) {
    return {
      acquired: true,
      supported: false,
      release: () => undefined,
    };
  }

  let releaseHold: (() => void) | undefined;
  let resolveAcquisition: (acquired: boolean) => void = () => undefined;
  const acquisition = new Promise<boolean>((resolve) => {
    resolveAcquisition = resolve;
  });

  const request = navigator.locks.request(
    LOCK_NAME,
    { ifAvailable: true, mode: 'exclusive' },
    async (lock) => {
      if (!lock) {
        resolveAcquisition(false);
        return;
      }
      resolveAcquisition(true);
      await new Promise<void>((resolve) => {
        releaseHold = resolve;
      });
    },
  );
  void request.catch(() => resolveAcquisition(false));

  const acquired = await acquisition;
  let released = false;
  return {
    acquired,
    supported: true,
    release: () => {
      if (released) return;
      released = true;
      releaseHold?.();
    },
  };
}
