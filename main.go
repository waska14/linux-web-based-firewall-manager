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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed templates/*
var templatesFS embed.FS

var (
	db        *sql.DB
	templates *template.Template
	syncMu    sync.Mutex
)

// dummyHash is used in loginHandler to ensure bcrypt always runs,
// preventing timing-based username enumeration.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)

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
	http.HandleFunc("/rules", authMiddleware(rulesHandler))

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
	http.HandleFunc("/api/ufw-rules", authMiddleware(apiUFWRulesHandler))
	http.HandleFunc("/api/export/groups", authMiddleware(apiExportGroupsHandler))
	http.HandleFunc("/api/import/groups", authMiddleware(apiImportGroupsHandler))

	port := os.Getenv("FW_MANAGER_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting Firewall Manager on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func initDB() {
	applySchema(db)
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
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.Password)

	if err != nil {
		// Always run bcrypt to prevent timing-based username enumeration
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
		return
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
		rows, err := db.Query("SELECT id, username, display_name FROM users ORDER BY id ASC")
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
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data["password"]), bcrypt.DefaultCost)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to hash password"})
			return
		}

		_, err = db.Exec("INSERT INTO users (username, display_name, password) VALUES (?, ?, ?)",
			data["username"], data["display_name"], string(hashedPassword))

		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "Username already exists"})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"success": "User created"})
		return
	}

	if r.Method == "PUT" {
		var data struct {
			ID          float64 `json:"id"`
			DisplayName string  `json:"display_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
			return
		}

		_, err := db.Exec("UPDATE users SET display_name = ? WHERE id = ?",
			data.DisplayName, int(data.ID))

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
	w.Header().Set("Content-Type", "application/json")

	var data map[string]int
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

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
	w.Header().Set("Content-Type", "application/json")

	cookie, _ := r.Cookie("session")
	var username string
	db.QueryRow("SELECT username FROM sessions WHERE token = ?", cookie.Value).Scan(&username)

	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

	var currentHash string
	db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&currentHash)

	if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(data["current_password"])) != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Current password is incorrect"})
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(data["new_password"]), bcrypt.DefaultCost)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to hash password"})
		return
	}
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
	w.Header().Set("Content-Type", "application/json")

	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

	var cmd *exec.Cmd
	switch data["action"] {
	case "enable":
		cmd = exec.Command("ufw", "--force", "enable")
	case "disable":
		cmd = exec.Command("ufw", "disable")
	default:
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid action: must be enable or disable"})
		return
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": string(output)})
		return
	}

	if data["action"] == "enable" {
		if err := syncUFWRules(); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "Firewall enabled but failed to sync rules: " + err.Error()})
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]string{"success": "Firewall " + data["action"] + "d"})
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

func isValidAction(a string) bool {
	return a == "allow" || a == "deny"
}

func isValidProtocol(p string) bool {
	return p == "tcp" || p == "udp" || p == "any"
}

// isValidIP accepts a plain IP, CIDR notation, or empty string (meaning "any").
func isValidIP(ip string) bool {
	if ip == "" {
		return true
	}
	if net.ParseIP(ip) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(ip)
	return err == nil
}

// isValidPort accepts a single port number, a UFW range (e.g. "80:90"), or empty string.
func isValidPort(port string) bool {
	if port == "" {
		return true
	}
	parts := strings.SplitN(port, ":", 2)
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

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

type exportSource struct {
	SourceIP    string `json:"source_ip"`
	SourcePort  string `json:"source_port"`
	Description string `json:"description"`
}

type exportGroup struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Action      string         `json:"action"`
	Protocol    string         `json:"protocol"`
	DestIP      string         `json:"dest_ip"`
	DestPort    string         `json:"dest_port"`
	Sources     []exportSource `json:"sources"`
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

// getCurrentUFWRules parses `ufw show added` and returns the set of currently
// applied rules as canonical strings (e.g. "allow from 1.2.3.4 to any port 22").
func getCurrentUFWRules() (map[string]bool, error) {
	output, err := exec.Command("ufw", "show", "added").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ufw show added: %s", output)
	}
	rules := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ufw ") {
			rules[strings.TrimPrefix(line, "ufw ")] = true
		}
	}
	return rules, nil
}

// ufwRule represents a single firewall rule in our internal format.
type ufwRule struct {
	action   string // "allow" or "deny"
	proto    string // "tcp", "udp", or "any"
	srcIP    string // empty = any
	srcPort  string // empty = any
	destIP   string // empty = any
	destPort string // empty = any
}

// buildRulesFromDB reads the database and returns an ordered list of rules:
// safe IP rules (allows) first, then group allows, then group denies.
func buildRulesFromDB() ([]ufwRule, error) {
	var allows, denies []ufwRule

	var safePort string
	db.QueryRow("SELECT value FROM config WHERE key = 'safe_port'").Scan(&safePort)

	safeRows, err := db.Query("SELECT ip FROM safe_ips")
	if err != nil {
		return nil, err
	}
	for safeRows.Next() {
		var ip string
		safeRows.Scan(&ip)
		allows = append(allows, ufwRule{action: "allow", proto: "any", srcIP: ip, destPort: "22"})
		if safePort != "" {
			allows = append(allows, ufwRule{action: "allow", proto: "any", srcIP: ip, destPort: safePort})
		}
	}
	safeRows.Close()

	groupRows, err := db.Query(`SELECT id, action, protocol, dest_ip, dest_port FROM rule_groups`)
	if err != nil {
		return nil, err
	}
	for groupRows.Next() {
		var groupID int
		var action, protocol, destIP, destPort string
		groupRows.Scan(&groupID, &action, &protocol, &destIP, &destPort)

		srcRows, _ := db.Query(`SELECT source_ip, source_port FROM rule_sources WHERE group_id = ?`, groupID)
		for srcRows.Next() {
			var srcIP, srcPort string
			srcRows.Scan(&srcIP, &srcPort)
			r := ufwRule{action: action, proto: protocol, srcIP: srcIP, srcPort: srcPort, destIP: destIP, destPort: destPort}
			if action == "deny" {
				denies = append(denies, r)
			} else {
				allows = append(allows, r)
			}
		}
		srcRows.Close()
	}
	groupRows.Close()

	return append(allows, denies...), nil
}

// generateRulesSection generates the block that goes between ### RULES ### and ### END RULES ###.
// Each rule produces a UFW tuple comment (used by `ufw show added`) and the corresponding iptables line(s).
// If ipv6 is true, only rules without specific IPs are included (IPv4 addresses don't apply to IPv6 traffic).
func generateRulesSection(rules []ufwRule, ipv6 bool) string {
	anyIP := "0.0.0.0/0"
	chain := "ufw-user-input"
	if ipv6 {
		anyIP = "::/0"
		chain = "ufw6-user-input"
	}

	seen := make(map[string]bool)
	var sb strings.Builder

	for _, r := range rules {
		// IPv6 file only gets rules with no specific IP (IPv4 addresses don't apply to IPv6 traffic).
		if ipv6 && (r.srcIP != "" || r.destIP != "") {
			continue
		}

		dedupeKey := fmt.Sprintf("%s|%s|%s|%s|%s|%s", r.action, r.proto, r.srcIP, r.srcPort, r.destIP, r.destPort)
		if seen[dedupeKey] {
			continue
		}
		seen[dedupeKey] = true

		dstPort := "any"
		if r.destPort != "" {
			dstPort = r.destPort
		}
		srcPort := "any"
		if r.srcPort != "" {
			srcPort = r.srcPort
		}
		dstIP := anyIP
		if r.destIP != "" {
			dstIP = r.destIP
		}
		srcIP := anyIP
		if r.srcIP != "" {
			srcIP = r.srcIP
		}
		target := "ACCEPT"
		if r.action == "deny" {
			target = "DROP"
		}

		// "any" protocol expands to separate tcp and udp iptables rules.
		protos := []string{r.proto}
		if r.proto == "any" {
			protos = []string{"tcp", "udp"}
		}

		for _, proto := range protos {
			// Tuple comment — used by `ufw show added` to reconstruct human-readable output.
			fmt.Fprintf(&sb, "### tuple ### %s %s %s %s %s %s in\n",
				r.action, proto, dstPort, dstIP, srcPort, srcIP)

			// iptables rule
			fmt.Fprintf(&sb, "-A %s", chain)
			if r.srcIP != "" {
				fmt.Fprintf(&sb, " -s %s", r.srcIP)
			}
			if r.destIP != "" {
				fmt.Fprintf(&sb, " -d %s", r.destIP)
			}
			fmt.Fprintf(&sb, " -p %s", proto)
			if r.srcPort != "" {
				fmt.Fprintf(&sb, " --sport %s", r.srcPort)
			}
			if r.destPort != "" {
				fmt.Fprintf(&sb, " --dport %s", r.destPort)
			}
			fmt.Fprintf(&sb, " -j %s\n\n", target)
		}
	}

	return sb.String()
}

// replaceRulesSection replaces everything between ### RULES ### and ### END RULES ### with newRules.
func replaceRulesSection(content, newRules string) (string, error) {
	const startMarker = "### RULES ###"
	const endMarker = "### END RULES ###"

	startIdx := strings.Index(content, startMarker)
	endIdx := strings.Index(content, endMarker)
	if startIdx == -1 || endIdx == -1 {
		return "", fmt.Errorf("could not find RULES markers in UFW rules file")
	}

	before := content[:startIdx+len(startMarker)] + "\n"
	after := content[endIdx:]
	return before + newRules + after, nil
}

// writeFileAtomic writes data to path via a temp file + rename, ensuring no partial writes.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ufw-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// syncUFWRules writes the full desired rule set directly to UFW's rules files and calls
// `ufw reload` once. This is O(1) shell forks regardless of rule count, vs. the old
// approach of one `ufw` invocation per rule (O(n) forks, very slow with many rules).
// On reload failure, original files are restored and a second reload is attempted.
func syncUFWRules() error {
	syncMu.Lock()
	defer syncMu.Unlock()

	const ipv4Path = "/etc/ufw/user.rules"
	const ipv6Path = "/etc/ufw/user6.rules"

	// Read current files so we can restore them if anything goes wrong.
	ipv4Orig, err := os.ReadFile(ipv4Path)
	if err != nil {
		return fmt.Errorf("read %s: %w", ipv4Path, err)
	}
	ipv6Orig, err := os.ReadFile(ipv6Path)
	if err != nil {
		return fmt.Errorf("read %s: %w", ipv6Path, err)
	}

	rules, err := buildRulesFromDB()
	if err != nil {
		return fmt.Errorf("build rules from DB: %w", err)
	}

	ipv4New, err := replaceRulesSection(string(ipv4Orig), generateRulesSection(rules, false))
	if err != nil {
		return fmt.Errorf("replace IPv4 rules: %w", err)
	}
	ipv6New, err := replaceRulesSection(string(ipv6Orig), generateRulesSection(rules, true))
	if err != nil {
		return fmt.Errorf("replace IPv6 rules: %w", err)
	}

	if err := writeFileAtomic(ipv4Path, []byte(ipv4New), 0640); err != nil {
		return fmt.Errorf("write %s: %w", ipv4Path, err)
	}
	if err := writeFileAtomic(ipv6Path, []byte(ipv6New), 0640); err != nil {
		writeFileAtomic(ipv4Path, ipv4Orig, 0640) // restore IPv4
		return fmt.Errorf("write %s: %w", ipv6Path, err)
	}

	if out, err := exec.Command("ufw", "reload").CombinedOutput(); err != nil {
		// Restore original files and reload with them so the firewall stays in a known state.
		writeFileAtomic(ipv4Path, ipv4Orig, 0640)
		writeFileAtomic(ipv6Path, ipv6Orig, 0640)
		exec.Command("ufw", "reload").Run()
		return fmt.Errorf("ufw reload failed: %s", out)
	}

	return nil
}

