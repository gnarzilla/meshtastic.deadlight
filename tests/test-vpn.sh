#!/bin/bash
# VPN Test Environment Setup Script

set -e

echo "=== Deadlight VPN Test Environment ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo"
    exit 1
fi

# Configuration
VPN_NAMESPACE="deadlight-vpn-test"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
VPN_GATEWAY="10.8.0.1"
CLIENT_IP="10.8.0.100"

echo "[1/6] Cleaning up any previous test environment..."
ip netns delete $VPN_NAMESPACE 2>/dev/null || true
ip link delete $VETH_HOST 2>/dev/null || true

echo "[2/6] Creating network namespace..."
ip netns add $VPN_NAMESPACE

echo "[3/6] Creating veth pair to connect namespace to VPN..."
ip link add $VETH_HOST type veth peer name $VETH_NS
ip link set $VETH_NS netns $VPN_NAMESPACE

echo "[4/6] Configuring host side..."
ip addr add ${VPN_GATEWAY}/24 dev $VETH_HOST
ip link set $VETH_HOST up

echo "[5/6] Configuring namespace side..."
ip netns exec $VPN_NAMESPACE ip addr add ${CLIENT_IP}/24 dev $VETH_NS
ip netns exec $VPN_NAMESPACE ip link set $VETH_NS up
ip netns exec $VPN_NAMESPACE ip link set lo up

echo "[6/6] Setting up routing in namespace..."
ip netns exec $VPN_NAMESPACE ip route add default via $VPN_GATEWAY

echo ""
echo "✓ VPN test environment ready!"
echo ""
echo "Test commands:"
echo "  # Enter the test namespace:"
echo "  sudo ip netns exec $VPN_NAMESPACE bash"
echo ""
echo "  # Then run tests:"
echo "  curl http://example.com"
echo "  curl http://wttr.in/Paris"
echo "  dig google.com"
echo ""
echo "Cleanup:"
echo "  sudo ./cleanup-vpn-test.sh"
