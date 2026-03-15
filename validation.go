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
