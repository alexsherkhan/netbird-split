#!/usr/bin/env bash
set -euo pipefail

# WARNING: Run this script only in a disposable VM or an isolated network
# namespace. It runs read-only unit tests and prints privileged commands for a
# later disposable-VM experiment. Never run it on a workstation or server whose
# connectivity matters.

cd "$(git rev-parse --show-toplevel)"

echo "== exit-node mutual exclusion tests =="
go test ./client/internal/routemanager/ -count=1 -v \
    -run 'TestSelectRoutes_ExitNodeExclusivity|TestEnforceSingleExitNode|TestUpdateRouteSelectorFromManagement_MirrorsV6ExitPair'

echo "== v6 exit pair expansion tests =="
go test ./route/ -count=1 -v -run 'TestExpandV6ExitPairs'

echo "== WireGuard AllowedIPs singleton and handover tests =="
go test ./client/internal/routemanager/refcounter/ -count=1 -v \
    -run 'TestAllowedIPs_SwapOnActivePeerRemoval|TestAllowedIPs_SamePeerMultipleRefs'

cat <<'EOF'

PENDING PRIVILEGED EXECUTION (disposable VM only):
  The tests above prove the in-process model treats an AllowedIP prefix as a
  singleton owned by exactly one peer. The kernel WireGuard experiment below
  is not run by this script because it needs root and a throwaway VM.

  1. Start two exit-node peers on one WireGuard interface and inspect ownership:

       wg show <iface> allowedips
       wg set <iface> peer <pubkey-A> allowed-ips 0.0.0.0/0
       wg set <iface> peer <pubkey-B> allowed-ips 0.0.0.0/0
       wg show <iface> allowedips

     Expected: 0.0.0.0/0 is programmed on only one peer; the second assignment
     moves the prefix instead of creating two paths.

  2. Repeat with one WireGuard interface per exit node:

       ip link add dev wg-split-a type wireguard
       ip link add dev wg-split-b type wireguard
       wg set wg-split-a peer <pubkey-A> allowed-ips 0.0.0.0/0
       wg set wg-split-b peer <pubkey-B> allowed-ips 0.0.0.0/0

     Expected: both interfaces can hold the same prefix. This is the prototype
     direction for multiple exit nodes; it still needs per-interface marks,
     routes, transport handling and management semantics.

  3. Send packets through each interface and verify the selected egress with
     tcpdump on both tunnels.
EOF
