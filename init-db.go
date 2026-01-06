package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatal("Usage: init-db <username> <password> <safe_ips> <safe_port>")
	}

	username := os.Args[1]
	password := os.Args[2]
	safeIPs := os.Args[3]  // comma-separated
	safePort := os.Args[4]

	db, err := sql.Open("sqlite3", "/var/lib/firewall-manager/firewall.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create tables
	db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		display_name TEXT,
		password TEXT NOT NULL
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS rule_groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		action TEXT NOT NULL,
		protocol TEXT NOT NULL,
		dest_ip TEXT,
		dest_port TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS rule_sources (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		group_id INTEGER,
		source_ip TEXT,
		source_port TEXT,
		description TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (group_id) REFERENCES rule_groups(id) ON DELETE CASCADE
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS safe_ips (
		ip TEXT PRIMARY KEY,
		description TEXT
	)`)

	// Insert admin user
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec("INSERT OR REPLACE INTO users (username, display_name, password) VALUES (?, ?, ?)",
		username, username, string(hashedPassword))
	if err != nil {
		log.Fatal("Failed to create user:", err)
	}

	fmt.Println("Created admin user:", username)

	// Store safe IPs and port
	ips := strings.Split(safeIPs, ",")
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			db.Exec("INSERT OR REPLACE INTO safe_ips (ip, description) VALUES (?, ?)", ip, "")
		}
	}
	db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('safe_port', ?)", safePort)

	fmt.Println("Database initialized successfully")
}
