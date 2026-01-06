#!/bin/bash

set -e

echo "Building Firewall Manager..."

# Use full path to Go (works even if not in PATH)
GO_BIN="/usr/local/go/bin/go"

# Check if Go exists
if [ ! -f "$GO_BIN" ]; then
    echo "Error: Go not found at $GO_BIN"
    echo "Please run: sudo ./prerequisites.sh"
    exit 1
fi

# Initialize go modules if needed
if [ ! -f "go.sum" ]; then
    echo "Initializing Go modules..."
    $GO_BIN mod tidy
fi

# Download dependencies
echo "Downloading dependencies..."
$GO_BIN mod download

# Build the main binary with CGO enabled
echo "Compiling main binary..."
CGO_ENABLED=1 $GO_BIN build -o firewall-manager main.go

# Build the init-db tool with CGO enabled
echo "Compiling init-db tool..."
CGO_ENABLED=1 $GO_BIN build -o init-db init-db.go

echo ""
echo "✓ Build complete!"
echo "  - firewall-manager (main binary)"
echo "  - init-db (database initialization tool)"
echo ""

# Make install.sh executable if it exists
if [ -f "install.sh" ]; then
    chmod +x install.sh
    echo "✓ install.sh is now executable"
    echo ""
fi

echo "To install, run:"
echo "  sudo ./install.sh"