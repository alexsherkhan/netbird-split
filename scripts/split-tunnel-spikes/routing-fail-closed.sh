#!/usr/bin/env bash
set -euo pipefail

# WARNING: Run this script only in a disposable VM or an isolated network
# namespace. It creates dummy interfaces, nftables rules, routing tables and
# policy rules inside a new network namespace. The host network namespace is
# not modified, but run it only on a disposable system. Never run it on a
# workstation or server whose connectivity matters.

if ! command -v unshare >/dev/null 2>&1; then
    echo "unshare is required (util-linux)." >&2
    exit 1
fi
if ! command -v nft >/dev/null 2>&1; then
    echo "nft is required." >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to send UDP probes." >&2
    exit 1
fi
if ! unshare -Urn true >/dev/null 2>&1; then
    echo "unprivileged user and network namespaces are not available." >&2
    exit 1
fi

unshare -Urn --map-root-user bash -eu -c '
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

ip link set lo up
ip link add dA type dummy
ip link set dA up
ip addr add 10.10.0.1/24 dev dA
ip addr add 10.10.0.99/24 dev dA
ip link add dB type dummy
ip link set dB up
ip addr add 10.20.0.1/24 dev dB

ip route add default dev dB
ip route add default dev dA table 100
ip route add 10.99.0.0/24 dev dA table 100
ip rule add fwmark 0x42/0xff lookup 100 priority 1000

nft add table inet kilo_rt
nft add chain inet kilo_rt post "{ type filter hook postrouting priority -150; }"
nft add rule inet kilo_rt post oifname "dA" counter
nft add rule inet kilo_rt post oifname "dB" counter

counter() {
    nft -a list chain inet kilo_rt post |
        awk -v dev="$1" "index(\$0, \"oifname \\\"\" dev \"\\\"\") { for (i = 1; i <= NF; i++) if (\$i == \"packets\") { print \$(i + 1); exit } }"
}

send() {
    python3 - "$1" "$2" <<PY
import socket
import sys

dest = sys.argv[1]
mark = int(sys.argv[2], 0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if mark:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
s.sendto(b"probe", (dest, 9))
s.close()
PY
}

assert_egress() {
    local dest=$1 mark=$2 want=$3
    local a0 b0 a1 b1 da db
    a0=$(counter dA)
    b0=$(counter dB)
    send "$dest" "$mark"
    a1=$(counter dA)
    b1=$(counter dB)
    da=$((a1 - a0))
    db=$((b1 - b0))
    if [[ "$want" == dA ]]; then
        [[ $da -eq 1 && $db -eq 0 ]] || fail "$dest mark=$mark: want dA, got dA=$da dB=$db"
    elif [[ "$want" == dB ]]; then
        [[ $da -eq 0 && $db -eq 1 ]] || fail "$dest mark=$mark: want dB, got dA=$da dB=$db"
    else
        fail "unknown expected egress $want"
    fi
}

echo "== 1. no mark uses main table =="
assert_egress 192.0.2.1 0 dB

echo "== 2. SO_MARK is honored by policy routing =="
assert_egress 192.0.2.1 0x42 dA

echo "== 3. filter-type OUTPUT mark does not reroute =="
nft add chain inet kilo_rt out_filter "{ type filter hook output priority mangle; }"
nft add rule inet kilo_rt out_filter ip daddr 198.51.100.1 meta mark set 0x42
assert_egress 198.51.100.1 0 dB
nft delete chain inet kilo_rt out_filter

echo "== 4. route-type OUTPUT mark reroutes =="
nft add chain inet kilo_rt out_route "{ type route hook output priority mangle; }"
nft add rule inet kilo_rt out_route ip daddr 198.51.100.2 meta mark set 0x42
assert_egress 198.51.100.2 0 dA

echo "== 5. table miss falls through to main until an unreachable default is added =="
ip route add 10.99.0.0/24 dev dA table 101
ip rule add fwmark 0x43/0xff lookup 101 priority 1001
assert_egress 198.51.100.3 0x43 dB
ip route add unreachable default table 101
if ip route get 198.51.100.3 mark 0x43 >/dev/null 2>&1; then
    fail "unreachable default in table 101 did not stop the lookup"
fi
if send 198.51.100.3 0x43 >/dev/null 2>&1; then
    fail "expected the send to fail after the unreachable default"
fi
out=$(ip route get 10.99.0.5 mark 0x43)
[[ "$out" == *"dev dA"* && "$out" == *"table 101"* ]] || fail "covered route in table 101 stopped working: $out"

echo "== 6. source address follows the selected route and pref src =="
out=$(ip route get 203.0.113.1 mark 0x42)
[[ "$out" == *"src 10.10.0.1"* ]] || fail "expected src 10.10.0.1: $out"
ip route add 10.77.0.0/24 dev dA table 100 src 10.10.0.99
out=$(ip route get 10.77.0.5 mark 0x42)
[[ "$out" == *"src 10.10.0.99"* ]] || fail "expected pref src 10.10.0.99: $out"

echo "== 7. fwmark masks select only the configured bits =="
out=$(ip route get 203.0.113.1 mark 0x44)
[[ "$out" != *"table 100"* && "$out" != *"table 101"* ]] || fail "0x44 unexpectedly matched a split rule: $out"
out=$(ip route get 203.0.113.1 mark 0x142)
[[ "$out" == *"table 100"* ]] || fail "0x142 should match the low byte of 0x42/0xff: $out"

echo "PASS: routing, reroute, source selection and fail-closed probes"
'

echo
echo "== 8. split rule priority relative to upstream rules 105 and 110 =="
unshare -Urn --map-root-user bash -eu -c '
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

ip link set lo up
for d in sA sB sC; do
    ip link add "$d" type dummy
    ip link set "$d" up
done
ip addr add 10.10.0.1/24 dev sA
ip addr add 10.20.0.1/24 dev sB
ip addr add 10.30.0.1/24 dev sC
ip route add default dev sB
ip route add default dev sA table 100
ip route add default dev sC table 200

# Mimic the upstream rules observed on the probe host: 105 main with
# suppress_prefixlength 0, 110 not-control-plane-mark -> netbird table.
ip rule add priority 105 lookup main suppress_prefixlength 0
ip rule add priority 110 not fwmark 0x1bd00/0xffffffff lookup 200
# The split rule must be evaluated after 105 and before 110.
ip rule add priority 108 fwmark 0x1bd01/0xff lookup 100

out=$(ip route get 203.0.113.1 mark 0x1bd01)
[[ "$out" == *"dev sA"* && "$out" == *"table 100"* ]] || fail "split mark did not select table 100: $out"
out=$(ip route get 203.0.113.1 mark 0x1bd00)
[[ "$out" == *"dev sB"* ]] || fail "control-plane mark did not bypass the split table: $out"
out=$(ip route get 203.0.113.1)
[[ "$out" == *"dev sC"* && "$out" == *"table 200"* ]] || fail "unmarked traffic did not use the upstream-like table: $out"

# A split table miss must not silently become DIRECT. In this layout it falls
# through to rule 110 (the upstream table), which is why the split table needs
# its own unreachable default.
ip route del default table 100
ip route add 10.99.0.0/24 dev sA table 100
out=$(ip route get 203.0.113.1 mark 0x1bd01)
[[ "$out" == *"table 200"* ]] || fail "expected fall-through to the upstream-like table: $out"
ip route add unreachable default table 100
if ip route get 203.0.113.1 mark 0x1bd01 >/dev/null 2>&1; then
    fail "unreachable default in the split table did not stop the lookup"
fi
out=$(ip route get 10.99.0.5 mark 0x1bd01)
[[ "$out" == *"dev sA"* && "$out" == *"table 100"* ]] || fail "covered split route stopped working: $out"

echo "PASS: split rule priority and fail-closed with upstream-like rules"
'
