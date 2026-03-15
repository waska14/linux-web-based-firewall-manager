package main

import (
	"database/sql"
	"embed"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"

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

		var username string
		err = db.QueryRow(`SELECT username FROM sessions
			WHERE token = ? AND datetime(expires_at) > datetime('now')`, cookie.Value).
			Scan(&username)

		if err != nil {
			db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}
