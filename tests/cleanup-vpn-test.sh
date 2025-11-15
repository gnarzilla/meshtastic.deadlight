#!/bin/bash
# Cleanup VPN Test Environment

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo"
    exit 1
fi

VPN_NAMESPACE="deadlight-vpn-test"
VETH_HOST="veth-host"

echo "Cleaning up VPN test environment..."
ip netns delete $VPN_NAMESPACE 2>/dev/null || true
ip link delete $VETH_HOST 2>/dev/null || true
echo "✓ Cleanup complete"
