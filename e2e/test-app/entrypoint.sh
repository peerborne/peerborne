#!/bin/sh
set -e

SHARED_INFO="/shared/relay-info.json"
TIMEOUT=60
ELAPSED=0

echo "Waiting for relay info at $SHARED_INFO..."

while [ ! -f "$SHARED_INFO" ]; do
  if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    echo "ERROR: Timed out waiting for $SHARED_INFO after ${TIMEOUT}s"
    exit 1
  fi
  sleep 1
  ELAPSED=$((ELAPSED + 1))
done

echo "Found relay info after ${ELAPSED}s"

# Extract relay multiaddr from the shared file
RELAY_MULTIADDR=$(cat "$SHARED_INFO" | sed -n 's/.*"wsMultiaddr"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

if [ -z "$RELAY_MULTIADDR" ]; then
  echo "ERROR: Could not extract multiaddr from $SHARED_INFO"
  cat "$SHARED_INFO"
  exit 1
fi

echo "Relay multiaddr: $RELAY_MULTIADDR"

# Write config.json for the browser app
cat > dist/config.json <<EOF
{
  "relayMultiaddr": "$RELAY_MULTIADDR"
}
EOF

echo "Starting test app on port 3000..."
exec node serve.mjs
