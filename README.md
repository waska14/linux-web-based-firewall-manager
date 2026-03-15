# Firewall Manager

A lightweight, web-based management interface for UFW (Uncomplicated Firewall) on Linux servers.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-00ADD8.svg)

## Why This Tool?

- 🖥️ **Manage UFW from your browser** instead of SSH/terminal
- 👥 **Multiple admin accounts** with individual logins (no more sharing root)
- 🛡️ **Lockout protection** - safe IPs always keep SSH and web UI accessible
- 📁 **Organized rules** - group related rules together (e.g., "Web Servers", "VPN Access")
- 🔄 **Import/Export** - copy your full config between servers in two clicks
- 🎯 **Zero external dependencies** - runs locally, talks directly to UFW

Perfect if you're already using UFW and want a simple, self-hosted management UI.

---

## Features

### 🔐 User Management
- Multiple admin accounts with bcrypt-hashed passwords
- Self-service password changes
- Session-based authentication (24h expiry)

### 🔥 Firewall Rule Groups
Group rules by purpose (e.g., "Allow HTTPS to web servers"):
- **Group settings**: Action (Allow/Deny), Protocol (TCP/UDP/Any), Destination IP/Port
- **Multiple sources per group**: Each with IP/CIDR, optional port, and description
- **Duplicate** any group with one click to use it as a starting point
- Example: One group "Web Traffic" → Multiple office/home IPs can access port 443

### 🚨 Safe IP Protection
- Configure IPs that **always** have access to SSH (22) and management interface
- Persists across firewall resets
- Editable from the web UI
- Your current IP is displayed to prevent accidental lockout

### ⚡ Quick Actions
- View firewall status (active/inactive)
- Enable/disable with one click — enabling re-applies all rules from the database
- Reset to safe defaults (preserves safe IPs)

### 📋 Rules Page
- View all active UFW rules in one human-readable list
- **Import/Export modal** with two tabs:
  - **Whitelist** — copy safe IPs config between servers as JSON
  - **Groups** — copy all rule groups between servers as JSON
  - Paste from another server and save to replicate the full config

---

## Quick Start

### Prerequisites
- Linux server (Ubuntu/Debian/CentOS/Fedora/Arch)
- Root/sudo access
- Port for web UI (default: 8080)

### Installation

```bash
# 1. Install dependencies (Go, build tools, UFW)
sudo ./prerequisites.sh

# 2. Build the application
./build.sh

# 3. Run interactive installer
sudo ./install.sh
```

The installer will:
1. Check/install UFW if needed
2. Ask for your safe IP(s) (comma-separated)
3. Set the web UI port (default: 8080)
4. Create admin credentials
5. Start the service automatically

### Access

Open `http://YOUR_SERVER_IP:PORT` and login with your admin credentials.

---

## Usage

### Managing Firewall Rules

**Create a rule group:**
1. Click "Add Rule Group" (next to the Rule Groups heading)
2. Set destination (e.g., Allow TCP port 443)
3. Add sources (e.g., office IP, home IP, partner IP)
4. Each source can have its own description

**Duplicate a group:**
- Click "Duplicate" on any group to open a pre-filled copy (name prefixed with "Copy Of")
- Adjust what you need and save

**Example group:**
- Name: "Allow HTTPS to Web Server"
- Destination: TCP port 443 on 10.0.0.5
- Sources:
    - 192.168.1.0/24 (Office network)
    - 91.98.234.244 (Admin home)
    - 203.0.113.0/24 (Partner company)

### Copying Config Between Servers

1. Go to the **Rules** page on the source server
2. Click **Import / Export**
3. Copy the JSON from the **Whitelist** and/or **Groups** tab
4. On the target server, open the same modal, paste into the relevant tab, click **Save**

### Managing Safe IPs

Click "Manage Safe IPs" on the Firewall page:
- Add/remove/edit safe IPs
- Each IP gets SSH (22) + web UI port access
- Changes take effect immediately

### Managing Users

On the Users page:
- Add new admin accounts
- Delete users
- Change your own password

---

## Updating to a New Version

Two scripts handle smooth production updates with zero manual steps:

```bash
# On the server:
sudo ./stop.sh       # gracefully stop the service

git pull             # get new code (or however you update)

sudo ./deploy.sh     # build, install binary, start service
```

`deploy.sh` will also stop the service itself if you skip `stop.sh`, so you can always just run `sudo ./deploy.sh` for a one-step update.

---

## Architecture

```
┌─────────────────┐
│   Browser UI    │
└────────┬────────┘
         │ HTTP (port 8080)
         │
┌────────▼────────┐      ┌──────────┐
│   Go Web App    │─────►│  SQLite  │
│  (main.go)      │      │ Database │
└────────┬────────┘      └──────────┘
         │
         │ syncUFWRules() — diff-based sync
         │
┌────────▼────────┐
│      UFW        │
│   (iptables)    │
└─────────────────┘
```

**Rule sync:** Every change saves to the database first, then `syncUFWRules()` reads the full desired state from DB, compares it to what UFW currently has (`ufw show added`), adds missing rules, and removes extra ones. New rules are always added before old ones are removed — no traffic gap. A mutex ensures only one sync runs at a time.

**Files:**
- `main.go` — HTTP server, handlers, UFW sync logic
- `schema.go` — single source of truth for DB schema (compiled into both binaries)
- `init-db.go` — one-time setup tool (admin user, safe IPs seed)
- Installed binaries: `/opt/firewall-manager/`
- Database: `/var/lib/firewall-manager/firewall.db`
- Service: `/etc/systemd/system/firewall-manager.service`

---

## Service Management

```bash
# Check status
sudo systemctl status firewall-manager

# Start/stop/restart
sudo systemctl start firewall-manager
sudo systemctl stop firewall-manager
sudo systemctl restart firewall-manager

# View logs
sudo journalctl -u firewall-manager -f
```

---

## Security Notes

✅ **What we do:**
- Bcrypt password hashing
- Secure session tokens (64-char random hex)
- HttpOnly, SameSite cookies
- Safe IP protection against lockouts
- Atomic DB transactions for rule/whitelist changes

⚠️ **Production recommendations:**
- Use HTTPS (put behind Nginx/Caddy reverse proxy)
- Restrict access to trusted admin IPs only
- The app runs as root (required for UFW) — only expose to trusted admins

---

## Uninstallation

```bash
sudo systemctl stop firewall-manager
sudo systemctl disable firewall-manager
sudo rm /etc/systemd/system/firewall-manager.service
sudo rm -rf /opt/firewall-manager
sudo rm -rf /var/lib/firewall-manager
sudo systemctl daemon-reload
```

**Note:** UFW rules are not automatically removed. Manage them with `ufw` directly or reset via `ufw --force reset`.

---

## Troubleshooting

### Can't access the web UI
- Check firewall status: `sudo ufw status`
- Check service: `sudo systemctl status firewall-manager`
- View logs: `sudo journalctl -u firewall-manager -n 50`

### Locked out after firewall reset
- SSH in from a safe IP (you configured these during install)
- Check safe IPs are configured: `sqlite3 /var/lib/firewall-manager/firewall.db "SELECT * FROM safe_ips"`

### Service won't start
- Check logs: `sudo journalctl -u firewall-manager -xe`
- Verify database exists: `ls -la /var/lib/firewall-manager/`
- Check port isn't in use: `sudo netstat -tulpn | grep 8080`

---

## Contributing

Contributions welcome! Please:
1. Open an issue to discuss the change
2. Fork the repository
3. Create a feature branch
4. Submit a pull request

---

## License

MIT License - see LICENSE file for details.

---

## Acknowledgments

Built with:
- [Go](https://golang.org/) - Backend language
- [UFW](https://help.ubuntu.com/community/UFW) - Firewall frontend for iptables
- [SQLite](https://www.sqlite.org/) - Embedded database
