#!/bin/bash

set -e

echo "Building Firewall Manager..."

# Initialize go modules if needed
if [ ! -f "go.sum" ]; then
    echo "Initializing Go modules..."
    go mod tidy
fi

# Download dependencies
echo "Downloading dependencies..."
go mod download

# Build the main binary with CGO enabled
echo "Compiling main binary..."
CGO_ENABLED=1 go build -o firewall-manager main.go

# Build the init-db tool with CGO enabled
echo "Compiling init-db tool..."
CGO_ENABLED=1 go build -o init-db init-db.go

echo ""
echo "✓ Build complete!"
echo "  - firewall-manager (main binary)"
echo "  - init-db (database initialization tool)"
echo ""
echo "To install, run:"
echo "  sudo ./install.sh"