package main

import (
	"net"
	"strconv"
	"strings"
)

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

// ipFamily returns 4 or 6 for a valid IP/CIDR and 0 for an empty address
// (meaning "any"). Invalid input returns -1.
func ipFamily(ip string) int {
	if ip == "" {
		return 0
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		var err error
		parsed, _, err = net.ParseCIDR(ip)
		if err != nil {
			return -1
		}
	}

	if parsed.To4() != nil {
		return 4
	}
	return 6
}

// hasCompatibleIPFamilies reports whether a source and destination can belong
// to one firewall rule. An empty address means "any" in the other address's
// family (or both families when both are empty).
func hasCompatibleIPFamilies(sourceIP, destIP string) bool {
	sourceFamily := ipFamily(sourceIP)
	destFamily := ipFamily(destIP)
	if sourceFamily < 0 || destFamily < 0 {
		return false
	}
	return sourceFamily == 0 || destFamily == 0 || sourceFamily == destFamily
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
