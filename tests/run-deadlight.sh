#!/bin/bash
# save as: run-deadlight.sh

echo "Cleaning up any existing TUN devices..."
sudo ip link delete tun0 2>/dev/null
sudo ip route flush dev tun0 2>/dev/null

echo "Starting Deadlight..."
sudo ./bin/deadlight -c deadlight.conf.pluggedin -v
