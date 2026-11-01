import * as mls from 'ts-mls';
import { runProbe } from '../mls-candidate/probe.mjs';
import { observeNativeCrypto } from '../mls-candidate/native-crypto.mjs';
import { runProviderChecks } from './provider-tests.ts';
import { runCoordinatorChecks } from './coordinator-tests.ts';
import { runReferenceVectors } from './reference-vectors.mjs';

export async function runChecks() {
  const observation = observeNativeCrypto();
  try {
    const retention = await runProbe(mls);
    if (
      !retention.zeroEpochRetentionHonored ||
      retention.retentionObservation.delayedEpochReadable
    ) {
      throw new Error('Patched retention gate failed');
    }
    const provider = await runProviderChecks();
    const coordinator = await runCoordinatorChecks();
    const referenceVectors = await runReferenceVectors();
    return {
      retention,
      provider,
      coordinator,
      referenceVectors,
      nativeCrypto: observation.counts,
    };
  } finally {
    observation.restore();
  }
}
