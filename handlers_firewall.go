package main

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
)

func firewallHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session")
	var username string
	db.QueryRow("SELECT username FROM sessions WHERE token = ?", cookie.Value).Scan(&username)
	clientIP := getClientIP(r)
	templates.ExecuteTemplate(w, "firewall.html", map[string]string{"Username": username, "ClientIP": clientIP})
}

func apiFirewallStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	output, err := exec.Command("ufw", "status").CombinedOutput()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "output": string(output)})
		return
	}

	status := "inactive"
	if strings.Contains(string(output), "Status: active") {
		status = "active"
	}

	json.NewEncoder(w).Encode(map[string]string{"status": status, "output": string(output)})
}

func apiFirewallToggleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

	switch data["action"] {
	case "enable":
		// Generate and preflight the desired files before enabling UFW. Enabling
		// first could apply a stale or malformed file and lock out remote access.
		if err := prepareUFWRules(); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "Firewall was not enabled because rule validation failed: " + err.Error()})
			return
		}
		output, err := exec.Command("ufw", "--force", "enable").CombinedOutput()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": string(output)})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"success": "Firewall enabled"})
		return
	case "disable":
		output, err := exec.Command("ufw", "disable").CombinedOutput()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": string(output)})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"success": "Firewall disabled"})
		return
	default:
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid action: must be enable or disable"})
		return
	}
}

func apiFirewallResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	tx, err := db.Begin()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if _, err := tx.Exec("DELETE FROM rule_sources"); err != nil {
		tx.Rollback()
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if _, err := tx.Exec("DELETE FROM rule_groups"); err != nil {
		tx.Rollback()
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if err := syncUFWRules(); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to sync firewall rules: " + err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"success": "Firewall reset complete"})
}
