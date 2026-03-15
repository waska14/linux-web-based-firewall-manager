package main

import (
	"encoding/json"
	"net/http"
)

func apiGroupsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		groupRows, err := db.Query(`SELECT id, name, description, action, protocol, dest_ip, dest_port, created_at
			FROM rule_groups ORDER BY id DESC`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer groupRows.Close()

		var groups []map[string]interface{}
		for groupRows.Next() {
			var group FirewallRuleGroup
			groupRows.Scan(&group.ID, &group.Name, &group.Description, &group.Action, &group.Protocol,
				&group.DestIP, &group.DestPort, &group.CreatedAt)

			sourceRows, _ := db.Query(`SELECT id, source_ip, source_port, description, created_at
				FROM rule_sources WHERE group_id = ?`, group.ID)

			var sources []FirewallRuleSource
			for sourceRows.Next() {
				var source FirewallRuleSource
				sourceRows.Scan(&source.ID, &source.SourceIP, &source.SourcePort, &source.Description, &source.CreatedAt)
				source.GroupID = group.ID
				sources = append(sources, source)
			}
			sourceRows.Close()

			groups = append(groups, map[string]interface{}{
				"id":          group.ID,
				"name":        group.Name,
				"description": group.Description,
				"action":      group.Action,
				"protocol":    group.Protocol,
				"dest_ip":     group.DestIP,
				"dest_port":   group.DestPort,
				"created_at":  group.CreatedAt,
				"sources":     sources,
			})
		}

		json.NewEncoder(w).Encode(groups)
		return
	}

	if r.Method == "POST" {
		var data struct {
			Name        string               `json:"name"`
			Description string               `json:"description"`
			Action      string               `json:"action"`
			Protocol    string               `json:"protocol"`
			DestIP      string               `json:"dest_ip"`
			DestPort    string               `json:"dest_port"`
			Sources     []FirewallRuleSource `json:"sources"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
			return
		}
		if !isValidAction(data.Action) {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid action: must be allow or deny"})
			return
		}
		if !isValidProtocol(data.Protocol) {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid protocol: must be tcp, udp, or any"})
			return
		}
		if !isValidIP(data.DestIP) {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid destination IP: " + data.DestIP})
			return
		}
		if !isValidPort(data.DestPort) {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid destination port: " + data.DestPort})
			return
		}
		for _, source := range data.Sources {
			if !isValidIP(source.SourceIP) {
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid source IP: " + source.SourceIP})
				return
			}
			if !isValidPort(source.SourcePort) {
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid source port: " + source.SourcePort})
				return
			}
		}

		tx, err := db.Begin()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		result, err := tx.Exec(`INSERT INTO rule_groups (name, description, action, protocol, dest_ip, dest_port)
			VALUES (?, ?, ?, ?, ?, ?)`,
			data.Name, data.Description, data.Action, data.Protocol, data.DestIP, data.DestPort)
		if err != nil {
			tx.Rollback()
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		groupID, _ := result.LastInsertId()

		for _, source := range data.Sources {
			if _, err := tx.Exec(`INSERT INTO rule_sources (group_id, source_ip, source_port, description)
				VALUES (?, ?, ?, ?)`,
				groupID, source.SourceIP, source.SourcePort, source.Description); err != nil {
				tx.Rollback()
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
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

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  "Group created",
			"group_id": groupID,
		})
		return
	}

	if r.Method == "PUT" {
		var data struct {
			ID          int                  `json:"id"`
			Name        string               `json:"name"`
			Description string               `json:"description"`
			Action      string               `json:"action"`
			Protocol    string               `json:"protocol"`
			DestIP      string               `json:"dest_ip"`
			DestPort    string               `json:"dest_port"`
			Sources     []FirewallRuleSource `json:"sources"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
			return
		}
		if !isValidAction(data.Action) {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid action: must be allow or deny"})
			return
		}
		if !isValidProtocol(data.Protocol) {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid protocol: must be tcp, udp, or any"})
			return
		}
		if !isValidIP(data.DestIP) {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid destination IP: " + data.DestIP})
			return
		}
		if !isValidPort(data.DestPort) {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid destination port: " + data.DestPort})
			return
		}
		for _, source := range data.Sources {
			if !isValidIP(source.SourceIP) {
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid source IP: " + source.SourceIP})
				return
			}
			if !isValidPort(source.SourcePort) {
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid source port: " + source.SourcePort})
				return
			}
		}

		tx, err := db.Begin()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		if _, err := tx.Exec(`UPDATE rule_groups SET name = ?, description = ?, action = ?, protocol = ?, dest_ip = ?, dest_port = ?
			WHERE id = ?`,
			data.Name, data.Description, data.Action, data.Protocol, data.DestIP, data.DestPort, data.ID); err != nil {
			tx.Rollback()
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		if _, err := tx.Exec("DELETE FROM rule_sources WHERE group_id = ?", data.ID); err != nil {
			tx.Rollback()
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		for _, source := range data.Sources {
			if _, err := tx.Exec(`INSERT INTO rule_sources (group_id, source_ip, source_port, description)
				VALUES (?, ?, ?, ?)`,
				data.ID, source.SourceIP, source.SourcePort, source.Description); err != nil {
				tx.Rollback()
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
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

		json.NewEncoder(w).Encode(map[string]string{"success": "Group updated"})
	}
}

func apiDeleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var data map[string]int
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

	_, err := db.Exec("DELETE FROM rule_groups WHERE id = ?", data["id"])
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if err := syncUFWRules(); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to sync firewall rules: " + err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"success": "Group deleted"})
}
