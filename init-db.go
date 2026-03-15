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

	applySchema(db)

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
