package main

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed templates/*
var templatesFS embed.FS

var (
	db        *sql.DB
	templates *template.Template
)

type User struct {
	ID          int
	Username    string
	DisplayName string
	Password    string
}

type SafeIP struct {
	IP          string `json:"ip"`
	Description string `json:"description"`
}

type FirewallRuleGroup struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	DestIP      string `json:"dest_ip"`
	DestPort    string `json:"dest_port"`
	CreatedAt   string `json:"created_at"`
}

type FirewallRuleSource struct {
	ID          int    `json:"id"`
	GroupID     int    `json:"group_id"`
	SourceIP    string `json:"source_ip"`
	SourcePort  string `json:"source_port"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

func main() {
	var err error

	db, err = sql.Open("sqlite3", "/var/lib/firewall-manager/firewall.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	initDB()

	templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

	http.HandleFunc("/", authMiddleware(dashboardHandler))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/users", authMiddleware(usersHandler))
	http.HandleFunc("/firewall", authMiddleware(firewallHandler))

	http.HandleFunc("/api/users", authMiddleware(apiUsersHandler))
	http.HandleFunc("/api/users/delete", authMiddleware(apiDeleteUserHandler))
	http.HandleFunc("/api/users/password", authMiddleware(apiChangePasswordHandler))
	http.HandleFunc("/api/firewall/status", authMiddleware(apiFirewallStatusHandler))
	http.HandleFunc("/api/firewall/toggle", authMiddleware(apiFirewallToggleHandler))
	http.HandleFunc("/api/firewall/reset", authMiddleware(apiFirewallResetHandler))
	http.HandleFunc("/api/safe-ips", authMiddleware(apiSafeIPsHandler))
	http.HandleFunc("/api/safe-ips/update", authMiddleware(apiUpdateSafeIPsHandler))
	http.HandleFunc("/api/groups", authMiddleware(apiGroupsHandler))
	http.HandleFunc("/api/groups/delete", authMiddleware(apiDeleteGroupHandler))

	port := os.Getenv("FW_MANAGER_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting Firewall Manager on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func initDB() {
	queries := []string{
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

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatal("Failed to create table:", err)
		}
	}

	// Clean up expired sessions on startup
	db.Exec("DELETE FROM sessions WHERE expires_at < datetime('now')")
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Validate session token and check expiry in one query
		var username string
		err = db.QueryRow(`SELECT username FROM sessions
			WHERE token = ? AND datetime(expires_at) > datetime('now')`, cookie.Value).
			Scan(&username)

		if err != nil {
			// Invalid or expired token
			db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getClientIP(r *http.Request) string {
    // Check X-Forwarded-For header (if behind proxy/load balancer)
    forwarded := r.Header.Get("X-Forwarded-For")
    if forwarded != "" {
        // X-Forwarded-For can be: "client, proxy1, proxy2"
        // We want the first one (client)
        ips := strings.Split(forwarded, ",")
        return strings.TrimSpace(ips[0])
    }

    // Check X-Real-IP header (some proxies use this)
    realIP := r.Header.Get("X-Real-IP")
    if realIP != "" {
        return realIP
    }

    // Fall back to RemoteAddr
    ip := r.RemoteAddr
    // RemoteAddr includes port, e.g., "192.168.1.5:54321"
    // Remove port
    if idx := strings.LastIndex(ip, ":"); idx != -1 {
        ip = ip[:idx]
    }
    return ip
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		templates.ExecuteTemplate(w, "login.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var user User
	var displayName sql.NullString
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.Password)

	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
		return
	}

	db.QueryRow("SELECT display_name FROM users WHERE username = ?", username).Scan(&displayName)
	if displayName.Valid {
		user.DisplayName = displayName.String
	}

	// Generate secure session token
	sessionToken := generateSessionToken()
	expiresAt := time.Now().Add(24 * time.Hour)

	// Store session in database (SQLite datetime format)
	db.Exec("INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, datetime(?, 'unixepoch'))",
		sessionToken, user.Username, expiresAt.Unix())

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/firewall", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		// Delete session from database
		db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/firewall", http.StatusSeeOther)
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session")
	var username string
	db.QueryRow("SELECT username FROM sessions WHERE token = ?", cookie.Value).Scan(&username)
	templates.ExecuteTemplate(w, "users.html", map[string]string{"Username": username})
}

func firewallHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session")
	var username string
	db.QueryRow("SELECT username FROM sessions WHERE token = ?", cookie.Value).Scan(&username)
	clientIP := getClientIP(r)
	templates.ExecuteTemplate(w, "firewall.html", map[string]string{"Username": username, "ClientIP": clientIP})
}

func apiUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		rows, err := db.Query("SELECT id, username, display_name FROM users")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []map[string]interface{}
		for rows.Next() {
			var id int
			var username, displayName string
			rows.Scan(&id, &username, &displayName)
			users = append(users, map[string]interface{}{
				"id":           id,
				"username":     username,
				"display_name": displayName,
			})
		}

		json.NewEncoder(w).Encode(users)
		return
	}

	if r.Method == "POST" {
		var data map[string]string
		json.NewDecoder(r.Body).Decode(&data)

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), bcrypt.DefaultCost)

		_, err := db.Exec("INSERT INTO users (username, display_name, password) VALUES (?, ?, ?)",
			data["username"], data["display_name"], string(hashedPassword))

		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "Username already exists"})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"success": "User created"})
		return
	}

	if r.Method == "PUT" {
		var data map[string]interface{}
		json.NewDecoder(r.Body).Decode(&data)

		_, err := db.Exec("UPDATE users SET display_name = ? WHERE id = ?",
			data["display_name"], int(data["id"].(float64)))

		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"success": "User updated"})
	}
}

func apiDeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data map[string]int
	json.NewDecoder(r.Body).Decode(&data)

	_, err := db.Exec("DELETE FROM users WHERE id = ?", data["id"])
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"success": "User deleted"})
}

func apiChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, _ := r.Cookie("session")
	var username string
	db.QueryRow("SELECT username FROM sessions WHERE token = ?", cookie.Value).Scan(&username)

	var data map[string]string
	json.NewDecoder(r.Body).Decode(&data)

	var currentHash string
	db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&currentHash)

	if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(data["current_password"])) != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Current password is incorrect"})
		return
	}

	newHash, _ := bcrypt.GenerateFromPassword([]byte(data["new_password"]), bcrypt.DefaultCost)
	db.Exec("UPDATE users SET password = ? WHERE username = ?", string(newHash), username)

	json.NewEncoder(w).Encode(map[string]string{"success": "Password changed"})
}

func apiFirewallStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cmd := exec.Command("ufw", "status")
	output, err := cmd.CombinedOutput()
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

	var data map[string]string
	json.NewDecoder(r.Body).Decode(&data)

	var cmd *exec.Cmd
	if data["action"] == "enable" {
		cmd = exec.Command("ufw", "--force", "enable")
	} else {
		cmd = exec.Command("ufw", "disable")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": string(output)})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"success": "Firewall " + data["action"] + "d"})
}

func apiFirewallResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	exec.Command("ufw", "--force", "reset").Run()
	exec.Command("ufw", "default", "deny", "incoming").Run()
	exec.Command("ufw", "default", "allow", "outgoing").Run()

	var safePort string
	db.QueryRow("SELECT value FROM config WHERE key = 'safe_port'").Scan(&safePort)

	rows, _ := db.Query("SELECT ip FROM safe_ips")
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		exec.Command("ufw", "allow", "from", ip, "to", "any", "port", "22").Run()
		if safePort != "" {
			exec.Command("ufw", "allow", "from", ip, "to", "any", "port", safePort).Run()
		}
	}
	rows.Close()

	db.Exec("DELETE FROM rule_sources")
	db.Exec("DELETE FROM rule_groups")

	exec.Command("ufw", "--force", "enable").Run()

	json.NewEncoder(w).Encode(map[string]string{"success": "Firewall reset complete"})
}

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
		return
	}
}

func apiUpdateSafeIPsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		SafeIPs []SafeIP `json:"safe_ips"`
	}
	json.NewDecoder(r.Body).Decode(&data)

	rows, _ := db.Query("SELECT ip FROM safe_ips")
	var oldIPs []string
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		oldIPs = append(oldIPs, ip)
	}
	rows.Close()

	var safePort string
	db.QueryRow("SELECT value FROM config WHERE key = 'safe_port'").Scan(&safePort)

	for _, ip := range oldIPs {
		exec.Command("ufw", "delete", "allow", "from", ip, "to", "any", "port", "22").Run()
		if safePort != "" {
			exec.Command("ufw", "delete", "allow", "from", ip, "to", "any", "port", safePort).Run()
		}
	}

	db.Exec("DELETE FROM safe_ips")

	for _, safeIP := range data.SafeIPs {
		ip := strings.TrimSpace(safeIP.IP)
		if ip != "" {
			db.Exec("INSERT INTO safe_ips (ip, description) VALUES (?, ?)", ip, safeIP.Description)
			exec.Command("ufw", "allow", "from", ip, "to", "any", "port", "22").Run()
			if safePort != "" {
				exec.Command("ufw", "allow", "from", ip, "to", "any", "port", safePort).Run()
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]string{"success": "Safe IPs updated"})
}

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
			Name        string                `json:"name"`
			Description string                `json:"description"`
			Action      string                `json:"action"`
			Protocol    string                `json:"protocol"`
			DestIP      string                `json:"dest_ip"`
			DestPort    string                `json:"dest_port"`
			Sources     []FirewallRuleSource `json:"sources"`
		}
		json.NewDecoder(r.Body).Decode(&data)

		result, err := db.Exec(`INSERT INTO rule_groups (name, description, action, protocol, dest_ip, dest_port)
			VALUES (?, ?, ?, ?, ?, ?)`,
			data.Name, data.Description, data.Action, data.Protocol, data.DestIP, data.DestPort)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		groupID, _ := result.LastInsertId()

		for _, source := range data.Sources {
			_, err := db.Exec(`INSERT INTO rule_sources (group_id, source_ip, source_port, description)
				VALUES (?, ?, ?, ?)`,
				groupID, source.SourceIP, source.SourcePort, source.Description)

			if err != nil {
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}

			if err := applyUFWRuleForSource(data.Action, data.Protocol, source.SourceIP, source.SourcePort,
				data.DestIP, data.DestPort); err != nil {
				json.NewEncoder(w).Encode(map[string]string{"error": "Failed to apply rule: " + err.Error()})
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  "Group created",
			"group_id": groupID,
		})
		return
	}

	if r.Method == "PUT" {
		var data struct {
			ID          int                   `json:"id"`
			Name        string                `json:"name"`
			Description string                `json:"description"`
			Action      string                `json:"action"`
			Protocol    string                `json:"protocol"`
			DestIP      string                `json:"dest_ip"`
			DestPort    string                `json:"dest_port"`
			Sources     []FirewallRuleSource `json:"sources"`
		}
		json.NewDecoder(r.Body).Decode(&data)

		rows, _ := db.Query(`SELECT rs.source_ip, rs.source_port, rg.action, rg.protocol, rg.dest_ip, rg.dest_port
			FROM rule_sources rs
			JOIN rule_groups rg ON rs.group_id = rg.id
			WHERE rs.group_id = ?`, data.ID)

		for rows.Next() {
			var srcIP, srcPort, action, protocol, destIP, destPort string
			rows.Scan(&srcIP, &srcPort, &action, &protocol, &destIP, &destPort)
			deleteUFWRuleForSource(action, protocol, srcIP, srcPort, destIP, destPort)
		}
		rows.Close()

		db.Exec(`UPDATE rule_groups SET name = ?, description = ?, action = ?, protocol = ?, dest_ip = ?, dest_port = ?
			WHERE id = ?`,
			data.Name, data.Description, data.Action, data.Protocol, data.DestIP, data.DestPort, data.ID)

		db.Exec("DELETE FROM rule_sources WHERE group_id = ?", data.ID)

		for _, source := range data.Sources {
			db.Exec(`INSERT INTO rule_sources (group_id, source_ip, source_port, description)
				VALUES (?, ?, ?, ?)`,
				data.ID, source.SourceIP, source.SourcePort, source.Description)

			applyUFWRuleForSource(data.Action, data.Protocol, source.SourceIP, source.SourcePort,
				data.DestIP, data.DestPort)
		}

		json.NewEncoder(w).Encode(map[string]string{"success": "Group updated"})
	}
}

func apiDeleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data map[string]int
	json.NewDecoder(r.Body).Decode(&data)

	rows, _ := db.Query(`SELECT rs.source_ip, rs.source_port, rg.action, rg.protocol, rg.dest_ip, rg.dest_port
		FROM rule_sources rs
		JOIN rule_groups rg ON rs.group_id = rg.id
		WHERE rg.id = ?`, data["id"])

	for rows.Next() {
		var srcIP, srcPort, action, protocol, destIP, destPort string
		rows.Scan(&srcIP, &srcPort, &action, &protocol, &destIP, &destPort)
		deleteUFWRuleForSource(action, protocol, srcIP, srcPort, destIP, destPort)
	}
	rows.Close()

	_, err := db.Exec("DELETE FROM rule_groups WHERE id = ?", data["id"])
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"success": "Group deleted"})
}

func applyUFWRuleForSource(action, protocol, sourceIP, sourcePort, destIP, destPort string) error {
	var args []string

	if action == "deny" {
		args = append(args, "deny")
	} else {
		args = append(args, "allow")
	}

	if sourceIP != "" {
		args = append(args, "from", sourceIP)
	}

	if sourcePort != "" {
		args = append(args, "port", sourcePort)
	}

	if destIP != "" {
		args = append(args, "to", destIP)
	} else {
		args = append(args, "to", "any")
	}

	if destPort != "" {
		args = append(args, "port", destPort)
	}

	if protocol != "any" && protocol != "" {
		args = append(args, "proto", protocol)
	}

	cmd := exec.Command("ufw", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, output)
	}

	return nil
}

func deleteUFWRuleForSource(action, protocol, sourceIP, sourcePort, destIP, destPort string) error {
	args := []string{"delete"}

	if action == "deny" {
		args = append(args, "deny")
	} else {
		args = append(args, "allow")
	}

	if sourceIP != "" {
		args = append(args, "from", sourceIP)
	}

	if sourcePort != "" {
		args = append(args, "port", sourcePort)
	}

	if destIP != "" {
		args = append(args, "to", destIP)
	} else {
		args = append(args, "to", "any")
	}

	if destPort != "" {
		args = append(args, "port", destPort)
	}

	if protocol != "any" && protocol != "" {
		args = append(args, "proto", protocol)
	}

	cmd := exec.Command("ufw", args...)
	cmd.Run()

	return nil
}
