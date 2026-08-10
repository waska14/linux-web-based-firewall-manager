package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const cloudflareIPURL = "https://api.cloudflare.com/client/v4/ips"

var (
	cloudflareRefreshInterval = 30 * time.Minute
	cloudflareHTTPClient      = &http.Client{Timeout: 15 * time.Second}
	cloudflareRefreshMu       sync.Mutex
)

type cloudflareAPIResponse struct {
	Result struct {
		IPv4CIDRs []string `json:"ipv4_cidrs"`
		IPv6CIDRs []string `json:"ipv6_cidrs"`
	} `json:"result"`
	Success bool `json:"success"`
}

type cloudflareStatus struct {
	Enabled     bool     `json:"enabled"`
	IPv4Count   int      `json:"ipv4_count"`
	IPv6Count   int      `json:"ipv6_count"`
	LastChecked string   `json:"last_checked,omitempty"`
	LastUpdated string   `json:"last_updated,omitempty"`
	LastError   string   `json:"last_error,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty"`
}

func apiCloudflareHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		status, err := getCloudflareStatus()
		if err != nil {
			http.Error(w, `{"error":"Failed to read Cloudflare status"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(status)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	var err error
	switch request.Action {
	case "enable":
		err = enableCloudflare(r.Context())
	case "disable":
		err = disableCloudflare()
	case "refresh":
		err = refreshCloudflareIPs(r.Context(), true)
	default:
		http.Error(w, `{"error":"Action must be enable, disable, or refresh"}`, http.StatusBadRequest)
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	status, err := getCloudflareStatus()
	if err != nil {
		http.Error(w, `{"error":"Cloudflare changed but status could not be read"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(status)
}

func fetchCloudflareIPs(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudflareIPURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download Cloudflare IPs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download Cloudflare IPs: HTTP %d", resp.StatusCode)
	}
	return parseCloudflareIPs(resp.Body)
}

func parseCloudflareIPs(body io.Reader) ([]string, error) {
	var payload cloudflareAPIResponse
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode Cloudflare IPs: %w", err)
	}
	if !payload.Success || len(payload.Result.IPv4CIDRs) == 0 || len(payload.Result.IPv6CIDRs) == 0 {
		return nil, fmt.Errorf("Cloudflare returned an incomplete IP list")
	}

	cidrs := append(append([]string{}, payload.Result.IPv4CIDRs...), payload.Result.IPv6CIDRs...)
	seen := make(map[string]bool, len(cidrs))
	for _, cidr := range cidrs {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil || ip.String() != network.IP.String() {
			return nil, fmt.Errorf("Cloudflare returned invalid CIDR %q", cidr)
		}
		if seen[cidr] {
			return nil, fmt.Errorf("Cloudflare returned duplicate CIDR %q", cidr)
		}
		seen[cidr] = true
	}
	sort.Strings(cidrs)
	return cidrs, nil
}

func enableCloudflare(ctx context.Context) error {
	cloudflareRefreshMu.Lock()
	defer cloudflareRefreshMu.Unlock()
	previous, err := getCloudflareStatus()
	if err != nil {
		return err
	}
	cidrs, err := fetchCloudflareIPs(ctx)
	if err != nil {
		setCloudflareConfig("cloudflare_last_error", err.Error())
		return err
	}
	if err := replaceCloudflareIPs(cidrs, true); err != nil {
		return err
	}
	if err := syncUFWRules(); err != nil {
		if restoreErr := restoreCloudflareState(previous); restoreErr != nil {
			return fmt.Errorf("sync Cloudflare rules: %v; restore database state: %w", err, restoreErr)
		}
		return err
	}
	return nil
}

func disableCloudflare() error {
	cloudflareRefreshMu.Lock()
	defer cloudflareRefreshMu.Unlock()
	previous, err := getCloudflareStatus()
	if err != nil {
		return err
	}
	if err := setCloudflareConfig("cloudflare_enabled", "0"); err != nil {
		return err
	}
	if err := syncUFWRules(); err != nil {
		if restoreErr := restoreCloudflareState(previous); restoreErr != nil {
			return fmt.Errorf("sync Cloudflare rules: %v; restore database state: %w", err, restoreErr)
		}
		return err
	}
	return nil
}

func refreshCloudflareIPs(ctx context.Context, force bool) error {
	cloudflareRefreshMu.Lock()
	defer cloudflareRefreshMu.Unlock()
	status, err := getCloudflareStatus()
	if err != nil || (!status.Enabled && !force) {
		return err
	}
	cidrs, err := fetchCloudflareIPs(ctx)
	checked := time.Now().UTC().Format(time.RFC3339)
	setCloudflareConfig("cloudflare_last_checked", checked)
	if err != nil {
		setCloudflareConfig("cloudflare_last_error", err.Error())
		return err
	}
	if equalStrings(cidrs, status.CIDRs) {
		setCloudflareConfig("cloudflare_last_error", "")
		return nil
	}
	if err := replaceCloudflareIPs(cidrs, status.Enabled); err != nil {
		return err
	}
	if status.Enabled {
		if err := syncUFWRules(); err != nil {
			if restoreErr := restoreCloudflareState(status); restoreErr != nil {
				return fmt.Errorf("sync Cloudflare rules: %v; restore database state: %w", err, restoreErr)
			}
			setCloudflareConfig("cloudflare_last_error", err.Error())
			return err
		}
	}
	return nil
}

func restoreCloudflareState(status cloudflareStatus) error {
	if err := replaceCloudflareIPs(status.CIDRs, status.Enabled); err != nil {
		return err
	}
	if !status.Enabled {
		return setCloudflareConfig("cloudflare_enabled", "0")
	}
	return nil
}

func replaceCloudflareIPs(cidrs []string, enable bool) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM cloudflare_ips"); err != nil {
		return err
	}
	for _, cidr := range cidrs {
		family := 6
		if strings.Contains(cidr, ".") {
			family = 4
		}
		if _, err = tx.Exec("INSERT INTO cloudflare_ips (cidr, family) VALUES (?, ?)", cidr, family); err != nil {
			return err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	values := map[string]string{"cloudflare_last_checked": now, "cloudflare_last_updated": now, "cloudflare_last_error": ""}
	if enable {
		values["cloudflare_enabled"] = "1"
	}
	for key, value := range values {
		if _, err = tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func getCloudflareStatus() (cloudflareStatus, error) {
	status := cloudflareStatus{CIDRs: []string{}}
	rows, err := db.Query("SELECT cidr, family FROM cloudflare_ips ORDER BY cidr")
	if err != nil {
		return status, err
	}
	defer rows.Close()
	for rows.Next() {
		var cidr string
		var family int
		if err := rows.Scan(&cidr, &family); err != nil {
			return status, err
		}
		status.CIDRs = append(status.CIDRs, cidr)
		if family == 4 {
			status.IPv4Count++
		} else {
			status.IPv6Count++
		}
	}
	if err := rows.Err(); err != nil {
		return status, err
	}
	values := map[string]*string{"cloudflare_last_checked": &status.LastChecked, "cloudflare_last_updated": &status.LastUpdated, "cloudflare_last_error": &status.LastError}
	for key, target := range values {
		err := db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(target)
		if err != nil && err != sql.ErrNoRows {
			return status, err
		}
	}
	var enabled string
	err = db.QueryRow("SELECT value FROM config WHERE key = 'cloudflare_enabled'").Scan(&enabled)
	if err != nil && err != sql.ErrNoRows {
		return status, err
	}
	status.Enabled = enabled == "1"
	return status, nil
}

func setCloudflareConfig(key, value string) error {
	_, err := db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, value)
	return err
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func runCloudflareUpdater() {
	if err := refreshCloudflareIPs(context.Background(), false); err != nil {
		log.Printf("Cloudflare IP refresh failed: %v", err)
	}
	ticker := time.NewTicker(cloudflareRefreshInterval)
	defer ticker.Stop()
	for range ticker.C {
		if err := refreshCloudflareIPs(context.Background(), false); err != nil {
			log.Printf("Cloudflare IP refresh failed: %v", err)
		}
	}
}
