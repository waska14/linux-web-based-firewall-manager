#!/bin/bash

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Firewall Manager Prerequisites${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS. /etc/os-release not found.${NC}"
    exit 1
fi

echo -e "${YELLOW}Detected OS: $OS $OS_VERSION${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get latest Go version from official site
get_latest_go_version() {
    # Try to fetch from Go's official version API
    if command_exists curl; then
        LATEST_GO=$(curl -sL 'https://go.dev/VERSION?m=text' | head -n1 | awk '{print $1}')
    elif command_exists wget; then
        LATEST_GO=$(wget -qO- 'https://go.dev/VERSION?m=text' | head -n1 | awk '{print $1}')
    else
        echo -e "${YELLOW}Cannot fetch latest version. Using Go 1.23 as fallback.${NC}"
        LATEST_GO="go1.23.0"
    fi

    # Return just the version
    echo "$LATEST_GO"
}

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        GO_ARCH="amd64"
        ;;
    aarch64|arm64)
        GO_ARCH="arm64"
        ;;
    armv7l|armv6l)
        GO_ARCH="armv6l"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${YELLOW}Architecture: $ARCH (Go: $GO_ARCH)${NC}"
echo ""

# Install build essentials based on distro
install_build_tools() {
    echo -e "${YELLOW}Installing build tools...${NC}"

    case $OS in
        ubuntu|debian|linuxmint|pop)
            apt-get update
            apt-get install -y build-essential curl wget git sqlite3
            ;;
        centos|rhel|rocky|almalinux)
            if command_exists dnf; then
                dnf groupinstall -y "Development Tools"
                dnf install -y curl wget git sqlite
            else
                yum groupinstall -y "Development Tools"
                yum install -y curl wget git sqlite
            fi
            ;;
        fedora)
            dnf groupinstall -y "Development Tools" "C Development Tools and Libraries"
            dnf install -y curl wget git sqlite
            ;;
        arch|manjaro)
            pacman -S --noconfirm --needed base-devel curl wget git sqlite
            ;;
        opensuse*|sles)
            zypper install -y -t pattern devel_basis
            zypper install -y curl wget git sqlite3
            ;;
        alpine)
            apk add --no-cache build-base curl wget git sqlite
            ;;
        *)
            echo -e "${RED}Unsupported distribution: $OS${NC}"
            echo -e "${YELLOW}Please install build tools manually:${NC}"
            echo -e "  - gcc/g++ compiler"
            echo -e "  - make"
            echo -e "  - curl or wget"
            echo -e "  - git"
            echo -e "  - sqlite3"
            exit 1
            ;;
    esac

    echo -e "${GREEN}✓ Build tools installed${NC}"
}

# Install or update Go
install_go() {
    local GO_VERSION=$1
    local GO_TAR="${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    local GO_URL="https://go.dev/dl/${GO_TAR}"

    echo -e "${YELLOW}Installing Go ${GO_VERSION}...${NC}"

    # Download Go
    cd /tmp
    if command_exists curl; then
        curl -LO "$GO_URL"
    elif command_exists wget; then
        wget "$GO_URL"
    else
        echo -e "${RED}Neither curl nor wget is available!${NC}"
        exit 1
    fi

    # Remove old Go installation
    echo -e "${YELLOW}Removing old Go installation...${NC}"
    rm -rf /usr/local/go

    # Extract
    echo -e "${YELLOW}Extracting Go...${NC}"
    tar -C /usr/local -xzf "$GO_TAR"
    rm "$GO_TAR"

    # Add to PATH if not already there
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi

    # Add to current session
    export PATH=$PATH:/usr/local/go/bin

    # Also add to common shell configs for users
    for profile in /root/.bashrc /root/.profile; do
        if [ -f "$profile" ]; then
            if ! grep -q "/usr/local/go/bin" "$profile"; then
                echo 'export PATH=$PATH:/usr/local/go/bin' >> "$profile"
            fi
        fi
    done

    # Source the files to make Go available immediately
    if [ -f /etc/profile ]; then
        . /etc/profile
    fi
    if [ -f /root/.bashrc ]; then
        . /root/.bashrc
    fi

    echo -e "${GREEN}✓ Go ${GO_VERSION} installed and available${NC}"
}

# Main installation flow
echo -e "${BLUE}Step 1: Installing build tools${NC}"
install_build_tools
echo ""

# Make sure Go is in PATH before checking
export PATH=$PATH:/usr/local/go/bin

echo -e "${BLUE}Step 2: Checking Go installation${NC}"
if command_exists go; then
    CURRENT_GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}Go is already installed: $CURRENT_GO_VERSION${NC}"
    echo ""

    echo -e "${YELLOW}Fetching latest Go version...${NC}"
    LATEST_GO=$(get_latest_go_version)
    echo -e "${GREEN}Latest Go version available: $LATEST_GO${NC}"
    echo ""

    # Compare versions
    if [ "$CURRENT_GO_VERSION" = "$LATEST_GO" ]; then
        echo -e "${GREEN}✓ You already have the latest version!${NC}"
        echo -e "${YELLOW}Skipping Go installation.${NC}"
    else
        echo -e "${YELLOW}A newer version is available.${NC}"
        echo -e "${RED}⚠️  WARNING: Upgrading Go may affect other applications using it!${NC}"
        read -p "Do you want to upgrade from $CURRENT_GO_VERSION to $LATEST_GO? (y/n): " UPGRADE_GO

        if [[ $UPGRADE_GO == "y" || $UPGRADE_GO == "Y" ]]; then
            install_go "$LATEST_GO"
        else
            echo -e "${GREEN}✓ Keeping existing Go installation${NC}"
            echo -e "${YELLOW}Note: The current version ($CURRENT_GO_VERSION) will work fine for this project.${NC}"
        fi
    fi
else
    echo -e "${YELLOW}Go is not installed${NC}"
    echo -e "${YELLOW}Fetching latest Go version...${NC}"
    LATEST_GO=$(get_latest_go_version)
    echo -e "${GREEN}Latest Go version: $LATEST_GO${NC}"
    install_go "$LATEST_GO"
fi
echo ""

# Verify installation
echo -e "${BLUE}Verifying installation...${NC}"
echo ""

# Make sure PATH is set for verification
export PATH=$PATH:/usr/local/go/bin

if command_exists go; then
    GO_VERSION=$(go version)
    echo -e "${GREEN}✓ Go: $GO_VERSION${NC}"
else
    echo -e "${RED}✗ Go installation failed${NC}"
    echo -e "${YELLOW}Trying to source profile files...${NC}"
    [ -f /etc/profile ] && . /etc/profile
    [ -f ~/.bashrc ] && . ~/.bashrc

    if command_exists go; then
        GO_VERSION=$(go version)
        echo -e "${GREEN}✓ Go: $GO_VERSION (after sourcing)${NC}"
    else
        echo -e "${RED}✗ Go still not found${NC}"
        exit 1
    fi
fi

if command_exists gcc; then
    GCC_VERSION=$(gcc --version | head -n1)
    echo -e "${GREEN}✓ GCC: $GCC_VERSION${NC}"
else
    echo -e "${RED}✗ GCC not found${NC}"
fi

if command_exists make; then
    MAKE_VERSION=$(make --version | head -n1)
    echo -e "${GREEN}✓ Make: $MAKE_VERSION${NC}"
else
    echo -e "${RED}✗ Make not found${NC}"
fi

if command_exists git; then
    GIT_VERSION=$(git --version)
    echo -e "${GREEN}✓ Git: $GIT_VERSION${NC}"
else
    echo -e "${YELLOW}⚠ Git not found (optional)${NC}"
fi

if command_exists sqlite3; then
    SQLITE_VERSION=$(sqlite3 --version | awk '{print $1}')
    echo -e "${GREEN}✓ SQLite: $SQLITE_VERSION${NC}"
else
    echo -e "${YELLOW}⚠ SQLite3 not found (optional for debugging)${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Prerequisites Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Make build.sh and install.sh executable if they exist
if [ -f "build.sh" ]; then
    chmod +x build.sh
    echo -e "${GREEN}✓ build.sh is now executable${NC}"
fi

if [ -f "install.sh" ]; then
    chmod +x install.sh
    echo -e "${GREEN}✓ install.sh is now executable${NC}"
fi

echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "  1. Run: ${GREEN}./build.sh${NC}"
echo -e "  2. Run: ${GREEN}sudo ./install.sh${NC}"
echo ""