import * as mls from 'ts-mls';
import { runProbe } from './probe.mjs';
import { observeNativeCrypto } from './native-crypto.mjs';

const observation = observeNativeCrypto();
try {
  window.candidateResult = {
    result: await runProbe(mls),
    nativeCrypto: observation.counts,
  };
} catch {
  window.candidateResult = { failed: true };
} finally {
  observation.restore();
}
