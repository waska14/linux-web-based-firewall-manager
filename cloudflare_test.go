package main

import (
	"strings"
	"testing"
)

func TestParseCloudflareIPs(t *testing.T) {
	body := `{"success":true,"result":{"ipv4_cidrs":["203.0.113.0/24"],"ipv6_cidrs":["2001:db8::/32"]}}`
	cidrs, err := parseCloudflareIPs(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseCloudflareIPs returned error: %v", err)
	}
	if len(cidrs) != 2 || cidrs[0] != "2001:db8::/32" || cidrs[1] != "203.0.113.0/24" {
		t.Fatalf("unexpected CIDRs: %#v", cidrs)
	}
}

func TestParseCloudflareIPsRejectsUnsafeResponses(t *testing.T) {
	tests := map[string]string{
		"unsuccessful": `{"success":false,"result":{"ipv4_cidrs":["203.0.113.0/24"],"ipv6_cidrs":["2001:db8::/32"]}}`,
		"missing IPv6": `{"success":true,"result":{"ipv4_cidrs":["203.0.113.0/24"]}}`,
		"host bits":    `{"success":true,"result":{"ipv4_cidrs":["203.0.113.1/24"],"ipv6_cidrs":["2001:db8::/32"]}}`,
		"duplicate":    `{"success":true,"result":{"ipv4_cidrs":["203.0.113.0/24","203.0.113.0/24"],"ipv6_cidrs":["2001:db8::/32"]}}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCloudflareIPs(strings.NewReader(body)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestCloudflareRulesAreTCPOnlyForWebPorts(t *testing.T) {
	rules := []ufwRule{
		{action: "allow", proto: "tcp", srcIP: "203.0.113.0/24", destPort: "80"},
		{action: "allow", proto: "tcp", srcIP: "203.0.113.0/24", destPort: "443"},
	}
	output := generateRulesSection(rules, false)
	if !strings.Contains(output, "--dport 80") || !strings.Contains(output, "--dport 443") {
		t.Fatalf("missing web-port rules: %s", output)
	}
	if strings.Contains(output, "-p udp") {
		t.Fatalf("Cloudflare web access unexpectedly permits UDP: %s", output)
	}
}
