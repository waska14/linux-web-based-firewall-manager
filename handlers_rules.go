package main

import (
	"encoding/json"
	"net/http"
	"sort"
)

func rulesHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session")
	var username string
	db.QueryRow("SELECT username FROM sessions WHERE token = ?", cookie.Value).Scan(&username)
	templates.ExecuteTemplate(w, "rules.html", map[string]string{"Username": username})
}

func apiUFWRulesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rules, err := getCurrentUFWRules()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	list := make([]string, 0, len(rules))
	for rule := range rules {
		list = append(list, rule)
	}
	sort.Strings(list)
	json.NewEncoder(w).Encode(list)
}

func apiExportGroupsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	groupRows, err := db.Query(`SELECT id, name, description, action, protocol, dest_ip, dest_port FROM rule_groups ORDER BY id ASC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer groupRows.Close()

	var groups []exportGroup
	for groupRows.Next() {
		var groupID int
		var g exportGroup
		groupRows.Scan(&groupID, &g.Name, &g.Description, &g.Action, &g.Protocol, &g.DestIP, &g.DestPort)

		srcRows, _ := db.Query(`SELECT source_ip, source_port, description FROM rule_sources WHERE group_id = ?`, groupID)
		for srcRows.Next() {
			var s exportSource
			srcRows.Scan(&s.SourceIP, &s.SourcePort, &s.Description)
			g.Sources = append(g.Sources, s)
		}
		srcRows.Close()

		groups = append(groups, g)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(groups)
}

func apiImportGroupsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var groups []exportGroup
	if err := json.NewDecoder(r.Body).Decode(&groups); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

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

	for _, g := range groups {
		if !isValidAction(g.Action) {
			tx.Rollback()
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid action in group \"" + g.Name + "\": must be allow or deny"})
			return
		}
		if !isValidProtocol(g.Protocol) {
			tx.Rollback()
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid protocol in group \"" + g.Name + "\": must be tcp, udp, or any"})
			return
		}
		if !isValidIP(g.DestIP) {
			tx.Rollback()
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid destination IP in group \"" + g.Name + "\": " + g.DestIP})
			return
		}
		if !isValidPort(g.DestPort) {
			tx.Rollback()
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid destination port in group \"" + g.Name + "\": " + g.DestPort})
			return
		}
		for _, s := range g.Sources {
			if !isValidIP(s.SourceIP) {
				tx.Rollback()
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid source IP in group \"" + g.Name + "\": " + s.SourceIP})
				return
			}
			if !isValidPort(s.SourcePort) {
				tx.Rollback()
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid source port in group \"" + g.Name + "\": " + s.SourcePort})
				return
			}
		}
		result, err := tx.Exec(`INSERT INTO rule_groups (name, description, action, protocol, dest_ip, dest_port) VALUES (?, ?, ?, ?, ?, ?)`,
			g.Name, g.Description, g.Action, g.Protocol, g.DestIP, g.DestPort)
		if err != nil {
			tx.Rollback()
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		groupID, _ := result.LastInsertId()
		for _, s := range g.Sources {
			if _, err := tx.Exec(`INSERT INTO rule_sources (group_id, source_ip, source_port, description) VALUES (?, ?, ?, ?)`,
				groupID, s.SourceIP, s.SourcePort, s.Description); err != nil {
				tx.Rollback()
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		}
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if err := syncUFWRules(); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Imported but failed to sync: " + err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"success": "Groups imported"})
}
