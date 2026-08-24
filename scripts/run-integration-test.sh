#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.integration.yaml"

echo "=== Peerborne Integration Test ==="
echo "Project directory: $PROJECT_DIR"
echo ""

# Cleanup function
cleanup() {
  echo ""
  echo "=== Cleaning up ==="
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# Step 1: Build all containers
echo "=== Step 1: Building Docker containers ==="
docker compose -f "$COMPOSE_FILE" build
echo ""

# Step 2: Start relay and wait for health
echo "=== Step 2: Starting relay server ==="
docker compose -f "$COMPOSE_FILE" up -d relay
echo "Waiting for relay to be healthy..."

TIMEOUT=60
ELAPSED=0
while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
  STATUS=$(docker compose -f "$COMPOSE_FILE" ps relay --format json 2>/dev/null | grep -o '"Health":"[^"]*"' | head -1 || echo "")
  if echo "$STATUS" | grep -q "healthy"; then
    echo "Relay is healthy after ${ELAPSED}s"
    break
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done

if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
  echo "ERROR: Relay failed to become healthy after ${TIMEOUT}s"
  docker compose -f "$COMPOSE_FILE" logs relay
  exit 1
fi

# Show relay info
echo "Relay logs:"
docker compose -f "$COMPOSE_FILE" logs relay | tail -10
echo ""

# Step 3: Start test apps
echo "=== Step 3: Starting test apps ==="
docker compose -f "$COMPOSE_FILE" up -d test-app-1 test-app-2
echo "Waiting for test apps to be ready..."

for PORT in 3001 3002; do
  TIMEOUT=120
  ELAPSED=0
  while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:${PORT}" 2>/dev/null | grep -q "200"; then
      echo "  test-app on port ${PORT} ready after ${ELAPSED}s"
      break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
  done
  if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    echo "ERROR: test-app on port ${PORT} not ready after ${TIMEOUT}s"
    docker compose -f "$COMPOSE_FILE" logs
    exit 1
  fi
done

echo ""

# Step 4: Run Playwright tests
echo "=== Step 4: Running Playwright integration tests ==="
cd "$PROJECT_DIR"
set +e
yarn exec playwright test --config=playwright.integration.config.ts "$@"
TEST_EXIT=$?
set -e

echo ""
if [ "$TEST_EXIT" -eq 0 ]; then
  echo "=== ALL INTEGRATION TESTS PASSED ==="
else
  echo "=== INTEGRATION TESTS FAILED (exit code: $TEST_EXIT) ==="
  echo ""
  echo "Docker logs:"
  docker compose -f "$COMPOSE_FILE" logs --tail=50
fi

exit $TEST_EXIT
