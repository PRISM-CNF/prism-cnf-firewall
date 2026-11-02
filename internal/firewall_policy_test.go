package internal

import "testing"

func TestParseFirewallPolicyAllowlistTCP(t *testing.T) {
	t.Parallel()

	policy, err := ParseFirewallPolicy([]byte(`
mode: allowlist
rules:
  - name: client-server
    left_cidrs:
      - 10.0.0.1/32
    right_cidrs:
      - 10.0.0.2
    protocol: tcp
    dst_ports:
      - 8080
      - 5201
`))
	if err != nil {
		t.Fatalf("ParseFirewallPolicy() error = %v", err)
	}

	if policy.Mode != FirewallModeAllowlist {
		t.Fatalf("policy.Mode = %q, want %q", policy.Mode, FirewallModeAllowlist)
	}
	if len(policy.Rules) != 1 {
		t.Fatalf("len(policy.Rules) = %d, want 1", len(policy.Rules))
	}

	rule := policy.Rules[0]
	if rule.Name != "client-server" {
		t.Fatalf("rule.Name = %q, want client-server", rule.Name)
	}
	if got := rule.LeftCIDRs[0].String(); got != "10.0.0.1/32" {
		t.Fatalf("left CIDR = %q, want 10.0.0.1/32", got)
	}
	if got := rule.RightCIDRs[0].String(); got != "10.0.0.2/32" {
		t.Fatalf("right CIDR = %q, want 10.0.0.2/32", got)
	}
	if rule.Protocol != FirewallProtocolTCP {
		t.Fatalf("rule.Protocol = %q, want %q", rule.Protocol, FirewallProtocolTCP)
	}
	if len(rule.DestinationPorts) != 2 {
		t.Fatalf("len(rule.DestinationPorts) = %d, want 2", len(rule.DestinationPorts))
	}
	if got := rule.DestinationPorts[0]; got != 8080 {
		t.Fatalf("rule.DestinationPorts[0] = %d, want 8080", got)
	}
}

func TestParseFirewallPolicyAllowlistICMP(t *testing.T) {
	t.Parallel()

	policy, err := ParseFirewallPolicy([]byte(`
mode: allowlist
rules:
  - left_cidrs:
      - 10.0.0.1/32
    right_cidrs:
      - 10.0.0.2/32
    protocol: icmp
`))
	if err != nil {
		t.Fatalf("ParseFirewallPolicy() error = %v", err)
	}

	if got := policy.Rules[0].Protocol; got != FirewallProtocolICMP {
		t.Fatalf("rule.Protocol = %q, want %q", got, FirewallProtocolICMP)
	}
	if len(policy.Rules[0].DestinationPorts) != 0 {
		t.Fatalf("len(rule.DestinationPorts) = %d, want 0", len(policy.Rules[0].DestinationPorts))
	}
}

func TestParseFirewallPolicyAllowsEmptyRules(t *testing.T) {
	t.Parallel()

	policy, err := ParseFirewallPolicy([]byte("mode: denylist\nrules: []\n"))
	if err != nil {
		t.Fatalf("ParseFirewallPolicy() error = %v", err)
	}

	if policy.Mode != FirewallModeDenylist {
		t.Fatalf("policy.Mode = %q, want %q", policy.Mode, FirewallModeDenylist)
	}
	if len(policy.Rules) != 0 {
		t.Fatalf("len(policy.Rules) = %d, want 0", len(policy.Rules))
	}
}

func TestParseFirewallPolicyRejectsIPv6(t *testing.T) {
	t.Parallel()

	_, err := ParseFirewallPolicy([]byte(`
mode: allowlist
rules:
  - left_cidrs:
      - 2001:db8::/64
    right_cidrs:
      - 10.0.0.2/32
`))
	if err == nil {
		t.Fatal("ParseFirewallPolicy() error = nil, want IPv6 validation error")
	}
}

func TestParseFirewallPolicyRejectsMissingMode(t *testing.T) {
	t.Parallel()

	_, err := ParseFirewallPolicy([]byte(`
rules:
  - left_cidrs:
      - 10.0.0.1/32
    right_cidrs:
      - 10.0.0.2/32
`))
	if err == nil {
		t.Fatal("ParseFirewallPolicy() error = nil, want missing mode validation error")
	}
}

func TestParseFirewallPolicyRejectsMissingProtocol(t *testing.T) {
	t.Parallel()

	_, err := ParseFirewallPolicy([]byte(`
mode: allowlist
rules:
  - left_cidrs:
      - 10.0.0.1/32
    right_cidrs:
      - 10.0.0.2/32
`))
	if err == nil {
		t.Fatal("ParseFirewallPolicy() error = nil, want missing protocol validation error")
	}
}

func TestParseFirewallPolicyRejectsICMPPorts(t *testing.T) {
	t.Parallel()

	_, err := ParseFirewallPolicy([]byte(`
mode: allowlist
rules:
  - left_cidrs:
      - 10.0.0.1/32
    right_cidrs:
      - 10.0.0.2/32
    protocol: icmp
    dst_ports:
      - 8
`))
	if err == nil {
		t.Fatal("ParseFirewallPolicy() error = nil, want ICMP port validation error")
	}
}

func TestParseFirewallPolicyRejectsMissingPortsForTCP(t *testing.T) {
	t.Parallel()

	_, err := ParseFirewallPolicy([]byte(`
mode: allowlist
rules:
  - left_cidrs:
      - 10.0.0.1/32
    right_cidrs:
      - 10.0.0.2/32
    protocol: tcp
`))
	if err == nil {
		t.Fatal("ParseFirewallPolicy() error = nil, want TCP port validation error")
	}
}

func TestParseFirewallPolicyRejectsInvalidPort(t *testing.T) {
	t.Parallel()

	_, err := ParseFirewallPolicy([]byte(`
mode: allowlist
rules:
  - left_cidrs:
      - 10.0.0.1/32
    right_cidrs:
      - 10.0.0.2/32
    protocol: udp
    dst_ports:
      - 70000
`))
	if err == nil {
		t.Fatal("ParseFirewallPolicy() error = nil, want invalid port validation error")
	}
}
