#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

if ! systemctl is-active --quiet firewall-manager; then
    echo "firewall-manager is not running"
    exit 0
fi

echo "Stopping firewall-manager..."
systemctl stop firewall-manager

# Wait until fully stopped (systemd already waits, this is a safety check)
for i in $(seq 1 10); do
    if ! systemctl is-active --quiet firewall-manager; then
        echo "firewall-manager stopped"
        exit 0
    fi
    sleep 1
done

echo "Warning: service did not stop within 10s — check: systemctl status firewall-manager"
exit 1
