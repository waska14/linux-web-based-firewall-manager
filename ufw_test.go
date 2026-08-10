package main

import (
	"strings"
	"testing"
)

func TestGenerateRulesSectionSeparatesAddressFamilies(t *testing.T) {
	rules := []ufwRule{
		{action: "allow", proto: "tcp", srcIP: "192.0.2.0/24", destPort: "443"},
		{action: "allow", proto: "tcp", srcIP: "2400:cb00::/32", destPort: "443"},
		{action: "deny", proto: "udp", destPort: "53"},
	}

	ipv4 := generateRulesSection(rules, false)
	ipv6 := generateRulesSection(rules, true)

	if !strings.Contains(ipv4, "192.0.2.0/24") {
		t.Error("IPv4 rules section omitted IPv4 source")
	}
	if strings.Contains(ipv4, "2400:cb00::/32") {
		t.Error("IPv4 rules section contains IPv6 source")
	}
	if !strings.Contains(ipv6, "2400:cb00::/32") {
		t.Error("IPv6 rules section omitted IPv6 source")
	}
	if strings.Contains(ipv6, "192.0.2.0/24") {
		t.Error("IPv6 rules section contains IPv4 source")
	}
	if !strings.Contains(ipv4, "--dport 53") || !strings.Contains(ipv6, "--dport 53") {
		t.Error("address-free rule must be generated for both families")
	}
	if !strings.Contains(ipv6, "-A ufw6-user-input -s 2400:cb00::/32") {
		t.Error("IPv6 source was not emitted on the IPv6 input chain")
	}
}

func TestGenerateRulesSectionSkipsMixedAddressFamilies(t *testing.T) {
	rule := ufwRule{
		action: "allow", proto: "tcp", srcIP: "192.0.2.1",
		destIP: "2001:db8::1", destPort: "443",
	}

	if got := generateRulesSection([]ufwRule{rule}, false); got != "" {
		t.Errorf("mixed-family rule reached IPv4 output: %q", got)
	}
	if got := generateRulesSection([]ufwRule{rule}, true); got != "" {
		t.Errorf("mixed-family rule reached IPv6 output: %q", got)
	}
}

func TestIPFamilyCompatibility(t *testing.T) {
	tests := []struct {
		name       string
		sourceIP   string
		destIP     string
		compatible bool
	}{
		{"both any", "", "", true},
		{"IPv4 source", "192.0.2.1", "", true},
		{"IPv6 CIDR source", "2400:cb00::/32", "", true},
		{"IPv4 pair", "192.0.2.1", "198.51.100.1", true},
		{"IPv6 pair", "2001:db8::1", "2001:db8::2", true},
		{"mixed pair", "192.0.2.1", "2001:db8::1", false},
		{"invalid", "not-an-ip", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasCompatibleIPFamilies(tt.sourceIP, tt.destIP); got != tt.compatible {
				t.Errorf("hasCompatibleIPFamilies(%q, %q) = %v, want %v", tt.sourceIP, tt.destIP, got, tt.compatible)
			}
		})
	}
}
