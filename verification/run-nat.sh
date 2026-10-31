#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# The topology, bounded readiness probes and unconditional teardown match the
# peerborne-cross-nat job in .github/workflows/ci.yml.
teardown() { docker compose -p peerborne-technical-verification -f docker-compose.peerborne-nat.yaml down -v; }
trap teardown EXIT
docker compose -p peerborne-technical-verification -f docker-compose.peerborne-nat.yaml up -d --build
node scripts/wait-remote-chromium.mjs ws://127.0.0.1:3101/ ws://127.0.0.1:3102/
yarn verify:technical:nat
