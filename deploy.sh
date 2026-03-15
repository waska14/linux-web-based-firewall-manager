#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Must be run from the repo root (where main.go lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "main.go" ]; then
    echo "Error: main.go not found. Run this script from the repo root."
    exit 1
fi

# Stop if running
if systemctl is-active --quiet firewall-manager; then
    echo "Stopping firewall-manager..."
    systemctl stop firewall-manager
fi

# Build
echo "Building..."
./build.sh

# Install binary (templates are embedded, no need to copy them)
echo "Installing binary..."
cp firewall-manager /opt/firewall-manager/firewall-manager
chmod +x /opt/firewall-manager/firewall-manager

# Also update init-db in case schema changed
cp init-db /opt/firewall-manager/init-db
chmod +x /opt/firewall-manager/init-db

# Start
echo "Starting firewall-manager..."
systemctl start firewall-manager

# Give it a moment then check
sleep 2
if systemctl is-active --quiet firewall-manager; then
    echo ""
    echo "firewall-manager is running"
    systemctl status firewall-manager --no-pager -l
else
    echo ""
    echo "Error: service failed to start. Check logs:"
    echo "  journalctl -u firewall-manager -n 50 --no-pager"
    exit 1
fi
