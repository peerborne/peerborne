import { runChecks } from './checks.mjs';
try {
  window.mlsProviderResult = { result: await runChecks() };
} catch {
  window.mlsProviderResult = { failed: true };
}
