## Firewall Manager

Firewall Manager is a **web-based management UI for UFW** (Uncomplicated Firewall) on Linux.

It lets you:
- Manage firewall rules from a browser instead of the terminal
- Organize rules into logical groups
- Safely grant and preserve access for administrator IPs
- Delegate firewall management to other admins without SSH access

Everything runs **locally on your server**, talking directly to `ufw` and a small SQLite database.

---

## Why would I use this?

- **You prefer a GUI over CLI** for day-to-day firewall administration.
- **Multiple admins** manage the same server and you want named accounts instead of sharing root.
- **You care about lockouts** and want “safe IPs” that always keep SSH and the web UI reachable.
- **You like structure**: rule groups (e.g. “Web Servers”, “VPN clients”) instead of a long flat list.

If you’re already using UFW on a Linux server and want a small, self-hosted firewall UI, this is for you.

---

## Main features

- **Modern web UI**
    - Dark, responsive interface
    - Two main screens: `Firewall` and `Users`

- **User accounts**
    - Create/delete users with usernames and optional display names
    - Passwords stored using **bcrypt** (no plaintext)
    - Users can change their own password
    - All users are currently full admins (no roles/permissions yet)

- **Firewall rule groups**
    - Group related rules under a **named group** with a description
    - Per-group settings:
        - Action: **Allow** or **Deny**
        - Protocol: **TCP / UDP / Any**
        - Destination IP/CIDR (optional)
        - Destination port (required; supports single port or range)
    - Per-source settings (multiple per group):
        - Source IP/CIDR (e.g. `192.168.1.0/24`)
        - Optional source port / port range
        - Per-source description
    - Edit or delete groups at any time; underlying UFW rules are updated automatically

- **Safe IPs (lockout protection)**
    - Configure one or more **safe IPs** that:
        - Always have access to SSH (port `22`)
        - Always have access to the management port (e.g. `8080`)
    - Safe IPs are:
        - Set during installation
        - Viewable and editable from the `Firewall` page
        - **Preserved across firewall resets**

- **Quick firewall actions**
    - View current UFW status (`active` / `inactive`)
    - Enable or disable UFW with one click
    - Reset UFW to a safe default policy:
        - `deny incoming`, `allow outgoing`
        - Re-apply safe IP rules
        - Clear all custom rule groups from the database

- **System integration**
    - Runs as a **systemd service**
    - Uses **SQLite** for configuration and session storage
    - Talks directly to `ufw` using the official CLI

---

## Architecture overview

- **Language / runtime**
    - Go 1.21+

- **Core components**
    - `main.go`:
        - HTTP server
        - Session handling (cookie-based, stored in SQLite)
        - HTML template rendering (`login`, `firewall`, `users`)
        - REST-like JSON APIs for users, groups, safe IPs, and firewall actions
    - `init-db.go`:
        - One-time (or repeatable) database initialization tool
        - Creates tables (users, sessions, rule groups, rule sources, config, safe_ips)
        - Creates the first admin user and initial safe IP entries
    - `install.sh`:
        - Interactive installer
        - Installs UFW (if missing)
        - Builds and installs binaries into `/opt/firewall-manager`
        - Creates/initializes the SQLite database in `/var/lib/firewall-manager`
        - Configures UFW defaults and safe rules
        - Sets up and starts the `firewall-manager` systemd service

- **Data storage**
    - SQLite database at `/var/lib/firewall-manager/firewall.db`
    - Tables:
        - `users` – login accounts
        - `sessions` – active login sessions
        - `rule_groups` – high-level firewall groups
        - `rule_sources` – per-group source details
        - `config` – misc configuration (`safe_port`, etc.)
        - `safe_ips` – IPs that are always allowed (SSH + management port)

- **Firewall interaction**
    - All firewall changes are applied via the `ufw` CLI:
        - Enable/disable/reset firewall
        - Add/delete allow/deny rules per group and source
        - Add/delete rules for safe IPs and management port

---

## Requirements

- **Operating system**
    - Linux (tested on **Ubuntu**; should also work on Debian, CentOS, Fedora, Arch)

- **Privileges**
    - Root access (or `sudo`) is required for:
        - Installation
        - Running the `firewall-manager` service (it calls `ufw`)

- **Software**
    - `ufw` (Uncomplicated Firewall)
    - Go **1.21+** (for building from source)

---

## Installation

You can either:
- Build from source and run the provided installer (recommended), or
- Integrate it into your own deployment flow (system packages, containers, etc.)

### 1. Build the binaries

From the project root:

```bash
go mod download
go build -o firewall-manager main.go
go build -o init-db init-db.go
```

Alternatively, you can use the helper script:

```bash
chmod +x build.sh
./build.sh
```

### 2. Run the interactive installer

```bash
sudo chmod +x install.sh
sudo ./install.sh
```

The installer will:
- Check for `ufw` and offer to install it if missing
- Detect your server IP (for convenience in the final message)
- Ask you for:
    - **Safe IP(s)**: IPs that always keep SSH + web UI access
    - **Web UI port**: default is `8080`
    - **Admin username and password** (if creating a new DB)
- Initialize or reuse the SQLite database
- Configure UFW defaults and safe rules
- Install and start the `firewall-manager` systemd service

### 3. Access the web interface

Once the service is running, open:

```text
http://YOUR_SERVER_IP:PORT
```

Use the credentials you set during installation.

---

## Using the application

### Login

- Navigate to the URL shown at the end of the installer.
- Log in with your **admin username** and **password**.
- Sessions are stored in the database and expire automatically after a period of time.

### Users page

On the `Users` page you can:
- **List users**: see all existing login accounts
- **Add user**:
    - Username
    - Optional display name
    - Password (hashed with bcrypt)
- **Delete user**:
    - Removes the user account from the database
- **Change your own password**:
    - Requires your current password
    - Updates your stored bcrypt hash

> Note: There is currently no “read-only” role – all users have full access.

### Firewall page

The `Firewall` page is where you manage:
- UFW status and quick actions
- Safe IPs
- Rule groups

#### Firewall status & quick actions

- View whether UFW is **active** or **inactive**.
- **Enable / Disable** with a single button.
- **Reset to defaults**:
    - `ufw --force reset`
    - `ufw default deny incoming`
    - `ufw default allow outgoing`
    - Re-apply safe IP rules (SSH + management port)
    - Clear stored groups and rules in the database

#### Safe IPs

- See all configured safe IPs and their descriptions.
- Open the Safe IPs modal to:
    - Add new IPs
    - Edit descriptions
    - Remove IPs
- Saving will:
    - Update the `safe_ips` table
    - Remove old safe IP rules from UFW
    - Add new ones **for SSH (22) and the management port**

These IPs are also used when you **reset** the firewall so you don’t lock yourself out.

#### Rule groups

Rule groups are the core way you manage firewall rules.

For each **group** you define:
- **Name** (e.g. “Web servers 80/443 from internet”)
- **Description** (optional notes)
- **Action**: Allow or Deny
- **Protocol**: TCP / UDP / Any
- **Destination IP/CIDR** (optional; `any` if empty)
- **Destination port** (required; may be a single port or range, as understood by UFW)

Then you add one or more **sources**:
- Source IP/CIDR (or leave empty for “any”)
- Optional source port / range
- Optional description per source

The app will:
- Write the rules into `rule_groups` and `rule_sources`
- Translate each source into a UFW rule:
    - Matching action/protocol/source/dest combination
- When you edit a group:
    - Old UFW rules for that group are removed
    - New rules are added based on the updated settings
- When you delete a group:
    - Its UFW rules are removed
    - The group and its sources are removed from the database

---

## Service management

The installer creates a `systemd` unit named `firewall-manager`.

Common commands:

```bash
# Status
sudo systemctl status firewall-manager

# Start / Stop / Restart
sudo systemctl start firewall-manager
sudo systemctl stop firewall-manager
sudo systemctl restart firewall-manager

# View logs (live)
sudo journalctl -u firewall-manager -f
```

---

## File locations (defaults)

- **Application binaries**: `/opt/firewall-manager/`
    - `firewall-manager`
    - `init-db`
- **HTML templates**: `/opt/firewall-manager/templates/`
- **Database**: `/var/lib/firewall-manager/firewall.db`
- **Systemd service**: `/etc/systemd/system/firewall-manager.service`

---

## Security considerations

- **Passwords**
    - Stored as bcrypt hashes (no plaintext)
    - Changeable by users via the UI

- **Sessions**
    - Stored in SQLite with creation and expiration times
    - Validated on each request; expired sessions are cleaned up

- **Safe IPs**
    - Used to always allow SSH + management port access
    - Re-applied on firewall reset to avoid accidental lockout

- **Network access**
    - The web UI listens on a configurable port (default `8080`)
    - For production, you should:
        - Put it behind an HTTPS-terminating reverse proxy (e.g. Nginx, Caddy)
        - Restrict access to known admin IPs using UFW and/or your reverse proxy

> Important: This tool runs as root (to manage UFW). Only expose it to trusted admins on trusted networks.

---

## Uninstallation

To remove Firewall Manager:

```bash
sudo systemctl stop firewall-manager
sudo systemctl disable firewall-manager
sudo rm /etc/systemd/system/firewall-manager.service
sudo rm -rf /opt/firewall-manager
sudo rm -rf /var/lib/firewall-manager
sudo systemctl daemon-reload
```

This will remove the service, binaries, and SQLite database. Any UFW rules previously created will not be automatically removed, but you can manage or reset them via UFW directly.

---

## Contributing

Contributions, bug reports, and feature requests are welcome.

If you plan to contribute:
- Open an issue describing the problem or feature
- Keep changes focused and reasonably small
- Avoid adding large dependencies unless necessary

---

## License

This project is licensed under the **MIT License**. You are free to use, modify, and distribute it, including in commercial environments.
