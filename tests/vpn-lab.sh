#!/usr/bin/env bash
#
# Create a throw-away net-namespace whose default route points to tun0.
#

set -e
NS=deadlight-test
VETH_HOST=veth-h
VETH_NS=veth-c
GW=10.8.0.1          # tun0 address
CLI=10.8.0.100/24    # client address

cleanup() {
    ip netns del $NS 2>/dev/null || true
    ip link del $VETH_HOST 2>/dev/null || true
}
trap cleanup EXIT

echo "[*] Cleaning old testbed (if any)"
cleanup

echo "[*] Creating namespace $NS"
ip netns add $NS

echo "[*] Creating veth pair"
ip link add $VETH_HOST type veth peer name $VETH_NS
ip link set $VETH_NS netns $NS

echo "[*] Configuring host side"
ip addr add $GW/24 dev $VETH_HOST      # host gets 10.8.0.1/24 too
ip link set $VETH_HOST up

echo "[*] Configuring namespace side"
ip netns exec $NS ip addr add $CLI dev $VETH_NS
ip netns exec $NS ip link set $VETH_NS up
ip netns exec $NS ip link set lo up
ip netns exec $NS ip route add default via $GW

echo ""
echo "Namespace ready.  Launch a shell with:"
echo "  sudo ip netns exec $NS bash"
echo ""
echo "Inside the shell try, for example:"
echo "  curl http://example.com"
