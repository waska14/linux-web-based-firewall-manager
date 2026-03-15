package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func apiSafeIPsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		rows, err := db.Query("SELECT ip, description FROM safe_ips")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var safeIPs []SafeIP
		for rows.Next() {
			var ip SafeIP
			rows.Scan(&ip.IP, &ip.Description)
			safeIPs = append(safeIPs, ip)
		}

		json.NewEncoder(w).Encode(safeIPs)
	}
}

func apiUpdateSafeIPsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var data struct {
		SafeIPs []SafeIP `json:"safe_ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to start transaction: " + err.Error()})
		return
	}

	if _, err := tx.Exec("DELETE FROM safe_ips"); err != nil {
		tx.Rollback()
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to clear safe IPs: " + err.Error()})
		return
	}

	for _, safeIP := range data.SafeIPs {
		ip := strings.TrimSpace(safeIP.IP)
		if ip == "" {
			continue
		}
		if !isValidIP(ip) {
			tx.Rollback()
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid IP address: " + ip})
			return
		}
		if _, err := tx.Exec("INSERT INTO safe_ips (ip, description) VALUES (?, ?)", ip, safeIP.Description); err != nil {
			tx.Rollback()
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to insert safe IP: " + err.Error()})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to commit transaction: " + err.Error()})
		return
	}

	if err := syncUFWRules(); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to sync firewall rules: " + err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"success": "Safe IPs updated"})
}
