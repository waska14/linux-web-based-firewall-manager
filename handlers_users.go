package main

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func usersHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session")
	var username string
	db.QueryRow("SELECT username FROM sessions WHERE token = ?", cookie.Value).Scan(&username)
	templates.ExecuteTemplate(w, "users.html", map[string]string{"Username": username})
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
