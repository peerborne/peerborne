#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
  echo 'The kernel packet-loss scenario requires Linux with sudo, iproute2, iptables, unshare and setpriv.' >&2
  exit 1
fi

cd "$(dirname "$0")/../.."
task_uid="$(id -u)"
task_gid="$(id -g)"
task_node="$(command -v node)"
task_cli="$PWD/node_modules/@playwright/test/cli.js"

# All interfaces and packet filters below exist only in this new network namespace.
# An unprivileged test process then uses sudo for its scoped packet-loss controls.
exec sudo -n --preserve-env=HOME,PATH unshare --net --uts -- bash -euo pipefail -c '
  hostname localhost
  ip link set lo up
  sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  sysctl -qw net.ipv6.conf.default.disable_ipv6=1
  ip link add pbverify0 type veth peer name pbverify1
  ip address add 198.18.0.1/24 dev pbverify0
  ip address add 198.18.0.2/24 dev pbverify1
  ip link set pbverify0 up
  ip link set pbverify1 up
  ip route add default via 198.18.0.2 dev pbverify0
  exec setpriv --reuid "$1" --regid "$2" --init-groups env \
    PEERBORNE_VERIFY_KERNEL_LOSS=isolated \
    PEERBORNE_VERIFY_PROFILE="$5" PEERBORNE_VERIFY_SEED="$6" PEERBORNE_VERIFY_STRICT="$7" \
    "$3" "$4" test --config=verification/advanced/playwright.config.ts --grep slow-peer
' bash "$task_uid" "$task_gid" "$task_node" "$task_cli" \
  "${PEERBORNE_VERIFY_PROFILE:-smoke}" "${PEERBORNE_VERIFY_SEED:-9420}" "${PEERBORNE_VERIFY_STRICT:-0}"
