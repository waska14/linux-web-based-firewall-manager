#!/bin/bash

set -e

SERVER_IP="$(curl -4 -fsS https://ifconfig.me/ip)"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Firewall Manager Installation${NC}"
echo -e "${GREEN}========================================${NC}"
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
    VER=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS. /etc/os-release not found.${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Detected OS: $OS $VER${NC}"

# Check for UFW
echo ""
echo -e "${YELLOW}Checking for UFW...${NC}"
if ! command -v ufw &> /dev/null; then
    echo -e "${YELLOW}UFW is not installed.${NC}"
    read -p "Would you like to install UFW? (y/n): " install_ufw
    if [[ $install_ufw != "y" && $install_ufw != "Y" ]]; then
        echo -e "${RED}UFW is required. Installation aborted.${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Installing UFW...${NC}"
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        apt-get update
        apt-get install -y ufw
    elif [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "fedora" ]]; then
        yum install -y ufw || dnf install -y ufw
    elif [[ "$OS" == "arch" ]]; then
        pacman -S --noconfirm ufw
    else
        echo -e "${RED}Automatic installation not supported for $OS. Please install UFW manually.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ UFW installed${NC}"
else
    echo -e "${GREEN}✓ UFW is already installed${NC}"
fi

# Get safe IPs
echo ""
echo -e "${YELLOW}Safe IP Configuration${NC}"
echo -e "Enter the IP address(es) that should ALWAYS have access to SSH (port 22) and the management interface."
echo -e "You can enter multiple IPs separated by commas."
echo -e "Example: 91.98.234.244 or 91.98.234.244, 192.168.1.100"
read -p "Safe IP(s): " SAFE_IPS

# Remove spaces and validate
SAFE_IPS=$(echo "$SAFE_IPS" | tr -d ' ')
if [ -z "$SAFE_IPS" ]; then
    echo -e "${RED}Safe IP is required. Installation aborted.${NC}"
    exit 1
fi

# Get management port
echo ""
read -p "Enter the port for Firewall Manager web interface (default: 8080): " FW_PORT
FW_PORT=${FW_PORT:-8080}

echo ""
echo -e "${GREEN}Configuration:${NC}"
echo -e "  Safe IP(s): ${GREEN}$SAFE_IPS${NC}"
echo -e "  Management Port: ${GREEN}$FW_PORT${NC}"
echo -e "  These IPs will have access to SSH (port 22) and management port ($FW_PORT)"

# Get admin credentials only if creating new database
if [[ $KEEP_DATA == "y" || $KEEP_DATA == "Y" ]] && [ -f "/var/lib/firewall-manager/firewall.db" ]; then
    echo ""
    echo -e "${GREEN}Using existing admin credentials from database${NC}"
    SKIP_DB_INIT="yes"
else
    # Get admin credentials
    echo ""
    echo -e "${YELLOW}Setup administrator account${NC}"
    read -p "Enter admin username (default: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}

    while true; do
        read -s -p "Enter admin password: " ADMIN_PASS
        echo ""
        read -s -p "Confirm admin password: " ADMIN_PASS2
        echo ""
        if [ "$ADMIN_PASS" == "$ADMIN_PASS2" ]; then
            break
        else
            echo -e "${RED}Passwords do not match. Please try again.${NC}"
        fi
    done
    SKIP_DB_INIT="no"
fi

# Create application directory
echo ""
echo -e "${YELLOW}Creating application directory...${NC}"

KEEP_DATA="n"

# Check if already installed
if [ -d "/opt/firewall-manager" ] || [ -f "/var/lib/firewall-manager/firewall.db" ]; then
    echo -e "${YELLOW}Existing installation detected.${NC}"
    read -p "Keep existing database and settings? (y/n): " keep_data
    KEEP_DATA=$keep_data

    # Stop service if it exists
    if systemctl is-active --quiet firewall-manager; then
        echo -e "${YELLOW}Stopping existing firewall-manager service...${NC}"
        systemctl stop firewall-manager
    fi

    # Remove old files
    if [ -d "/opt/firewall-manager" ]; then
        echo -e "${YELLOW}Removing old installation files...${NC}"
        rm -rf /opt/firewall-manager
    fi

    # Remove database if user chose not to keep it
    if [[ $keep_data != "y" && $keep_data != "Y" ]]; then
        echo -e "${YELLOW}Removing existing database...${NC}"
        rm -rf /var/lib/firewall-manager
    else
        echo -e "${GREEN}✓ Keeping existing database and settings${NC}"
    fi
fi

# Stop service if running (in case directory was deleted but service exists)
if systemctl is-active --quiet firewall-manager 2>/dev/null; then
    systemctl stop firewall-manager 2>/dev/null || true
fi

mkdir -p /opt/firewall-manager
mkdir -p /var/lib/firewall-manager
mkdir -p /opt/firewall-manager/templates

# Copy files
echo -e "${YELLOW}Copying application files...${NC}"
cp firewall-manager /opt/firewall-manager/
cp init-db /opt/firewall-manager/
chmod +x /opt/firewall-manager/firewall-manager
chmod +x /opt/firewall-manager/init-db
cp templates/*.html /opt/firewall-manager/templates/

# Initialize database and create admin user
if [ "$SKIP_DB_INIT" == "yes" ]; then
    echo -e "${GREEN}✓ Using existing database${NC}"
else
    echo -e "${YELLOW}Initializing database...${NC}"
    /opt/firewall-manager/init-db "$ADMIN_USER" "$ADMIN_PASS" "$SAFE_IPS" "$FW_PORT"
fi

# Configure UFW with safe rules
echo ""
echo -e "${YELLOW}Configuring UFW...${NC}"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Add safe IP rules for each IP
IFS=',' read -ra IP_ARRAY <<< "$SAFE_IPS"
for ip in "${IP_ARRAY[@]}"; do
    ip=$(echo "$ip" | xargs)  # trim whitespace
    if [ ! -z "$ip" ]; then
        ufw allow from $ip to any port 22
        ufw allow from $ip to any port $FW_PORT
        echo -e "${GREEN}✓ Added rules for $ip (SSH port 22 and management port $FW_PORT)${NC}"
    fi
done

# Create systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > /etc/systemd/system/firewall-manager.service << EOF
[Unit]
Description=Firewall Manager Web Interface
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/firewall-manager
Environment="FW_MANAGER_PORT=$FW_PORT"
ExecStart=/opt/firewall-manager/firewall-manager
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
echo -e "${YELLOW}Enabling and starting service...${NC}"
systemctl daemon-reload
systemctl enable firewall-manager
systemctl start firewall-manager

# Enable UFW
echo -e "${YELLOW}Enabling UFW...${NC}"
ufw --force enable

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Access the Firewall Manager at:"
echo -e "${GREEN}  http://$SERVER_IP:$FW_PORT${NC}"
echo ""
echo -e "Login credentials:"
echo -e "  Username: ${GREEN}$ADMIN_USER${NC}"
echo -e "  Password: ${GREEN}[the password you entered]${NC}"
echo ""
echo -e "Service commands:"
echo -e "  Status:  ${YELLOW}systemctl status firewall-manager${NC}"
echo -e "  Stop:    ${YELLOW}systemctl stop firewall-manager${NC}"
echo -e "  Start:   ${YELLOW}systemctl start firewall-manager${NC}"
echo -e "  Restart: ${YELLOW}systemctl restart firewall-manager${NC}"
echo -e "  Logs:    ${YELLOW}journalctl -u firewall-manager -f${NC}"
echo ""
echo -e "${YELLOW}Note: The IPs in $SAFE_IPS will always have access to${NC}"
echo -e "${YELLOW}SSH (port 22) and management port ($FW_PORT),${NC}"
echo -e "${YELLOW}even if you reset the firewall from the dashboard.${NC}"
echo ""