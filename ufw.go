package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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

		// One tuple comment per logical rule (using the original proto, which may be "any").
		// ufw show added reads tuple comments — one comment = one displayed line.
		fmt.Fprintf(&sb, "### tuple ### %s %s %s %s %s %s in\n",
			r.action, r.proto, dstPort, dstIP, srcPort, srcIP)

		// "any" protocol expands to both tcp and udp iptables lines under the same tuple.
		protos := []string{r.proto}
		if r.proto == "any" {
			protos = []string{"tcp", "udp"}
		}

		for _, proto := range protos {
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
			fmt.Fprintf(&sb, " -j %s\n", target)
		}
		fmt.Fprintf(&sb, "\n")
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

// logSyncError logs UFW sync errors without returning them to callers that
// don't propagate the error (e.g. deferred cleanup paths).
func logSyncError(err error) {
	if err != nil {
		log.Printf("UFW sync error: %v", err)
	}
}
