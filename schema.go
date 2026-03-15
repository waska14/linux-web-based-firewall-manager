package main

import (
	"database/sql"
	"log"
)

var dbSchema = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		display_name TEXT,
		password TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS rule_groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		action TEXT NOT NULL,
		protocol TEXT NOT NULL,
		dest_ip TEXT,
		dest_port TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS rule_sources (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		group_id INTEGER,
		source_ip TEXT,
		source_port TEXT,
		description TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (group_id) REFERENCES rule_groups(id) ON DELETE CASCADE
	)`,
	`CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS safe_ips (
		ip TEXT PRIMARY KEY,
		description TEXT
	)`,
}

func applySchema(db *sql.DB) {
	for _, query := range dbSchema {
		if _, err := db.Exec(query); err != nil {
			log.Fatal("Failed to apply schema:", err)
		}
	}
}
