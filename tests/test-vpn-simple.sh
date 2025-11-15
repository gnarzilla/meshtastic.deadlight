#!/bin/bash
set -e

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    ip netns delete vpntest 2>/dev/null || true
}

trap cleanup EXIT

# Setup
echo "Setting up VPN test namespace..."
cleanup
ip netns add vpntest

# Move tun0 into the namespace temporarily
# Actually, don't move it - instead create a route

# Setup routing in the namespace
ip netns exec vpntest ip link set lo up
ip netns exec vpntest ip addr add 10.8.0.100/24 dev lo
ip netns exec vpntest ip route add default via 10.8.0.1

echo "Namespace ready. Trying to curl through VPN..."
ip netns exec vpntest curl -v http://example.com --connect-timeout 5

