#!/bin/bash
# vpn_test.sh - Safe VPN testing script

set -e

echo "=== VPN Gateway Test Setup ==="

# Check if VPN is running
if ! ip link show tun0 &>/dev/null; then
    echo "ERROR: tun0 device not found. Is Deadlight VPN running?"
    exit 1
fi

echo "✓ TUN device tun0 exists"

# Check gateway IP
if ! ip addr show tun0 | grep -q "10.8.0.1"; then
    echo "ERROR: Gateway IP 10.8.0.1 not configured on tun0"
    exit 1
fi

echo "✓ Gateway IP configured"

# Add route for test domains only (safe)
echo "Adding routes for test domains..."
sudo ip route add 93.184.216.34/32 via 10.8.0.1 dev tun0 2>/dev/null || echo "  (route already exists)"
sudo ip route add 8.8.8.8/32 via 10.8.0.1 dev tun0 2>/dev/null || echo "  (route already exists)"

echo "✓ Routes configured"
echo ""
echo "=== Testing VPN Gateway ==="
echo ""

# Test HTTP
echo "1. Testing HTTP (example.com)..."
if curl -s -m 5 http://example.com | grep -q "Example Domain"; then
    echo "   ✓ HTTP works!"
else
    echo "   ✗ HTTP failed"
fi

# Test DNS
echo "2. Testing DNS (via 8.8.8.8)..."
if dig @8.8.8.8 +short google.com | grep -q "^[0-9]"; then
    echo "   ✓ DNS works!"
else
    echo "   ✗ DNS failed"
fi

echo ""
echo "=== Cleanup ==="
sudo ip route del 93.184.216.34/32 via 10.8.0.1 dev tun0 2>/dev/null || true
sudo ip route del 8.8.8.8/32 via 10.8.0.1 dev tun0 2>/dev/null || true
echo "✓ Routes removed"
