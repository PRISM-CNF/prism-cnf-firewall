package internal

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type FirewallMode string

const (
	FirewallModeAllowlist FirewallMode = "allowlist"
	FirewallModeDenylist  FirewallMode = "denylist"
)

type FirewallPolicy struct {
	Mode  FirewallMode
	Rules []FirewallRule
}

type FirewallProtocol string

const (
	FirewallProtocolTCP  FirewallProtocol = "tcp"
	FirewallProtocolUDP  FirewallProtocol = "udp"
	FirewallProtocolICMP FirewallProtocol = "icmp"
)

type FirewallRule struct {
	Name             string
	LeftCIDRs        []netip.Prefix
	RightCIDRs       []netip.Prefix
	Protocol         FirewallProtocol
	DestinationPorts []uint16
}

type rawFirewallPolicy struct {
	Mode  string            `yaml:"mode"`
	Rules []rawFirewallRule `yaml:"rules"`
}

type rawFirewallRule struct {
	Name       string   `yaml:"name"`
	Protocol   string   `yaml:"protocol"`
	LeftCIDRs  []string `yaml:"left_cidrs"`
	RightCIDRs []string `yaml:"right_cidrs"`
	DstPorts   []int    `yaml:"dst_ports"`
}

func LoadFirewallPolicyFromFile(path string) (*FirewallPolicy, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("firewall rules path is required")
	}

	rawData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read firewall rules file: %w", err)
	}

	return ParseFirewallPolicy(rawData)
}

func ParseFirewallPolicy(rawData []byte) (*FirewallPolicy, error) {
	var raw rawFirewallPolicy
	if err := yaml.Unmarshal(rawData, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal firewall rules YAML: %w", err)
	}

	mode, err := normalizeFirewallMode(raw.Mode)
	if err != nil {
		return nil, err
	}

	policy := &FirewallPolicy{
		Mode:  mode,
		Rules: make([]FirewallRule, 0, len(raw.Rules)),
	}

	for index, rule := range raw.Rules {
		leftCIDRs, err := parseFirewallPrefixes(rule.LeftCIDRs, "left_cidrs")
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", index+1, err)
		}

		rightCIDRs, err := parseFirewallPrefixes(rule.RightCIDRs, "right_cidrs")
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", index+1, err)
		}

		name := strings.TrimSpace(rule.Name)
		if name == "" {
			name = fmt.Sprintf("rule-%d", index+1)
		}

		protocol, err := normalizeFirewallProtocol(rule.Protocol)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", index+1, err)
		}

		destinationPorts, err := parseFirewallDestinationPorts(protocol, rule.DstPorts)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", index+1, err)
		}

		policy.Rules = append(policy.Rules, FirewallRule{
			Name:             name,
			LeftCIDRs:        leftCIDRs,
			RightCIDRs:       rightCIDRs,
			Protocol:         protocol,
			DestinationPorts: destinationPorts,
		})
	}

	return policy, nil
}

func normalizeFirewallMode(value string) (FirewallMode, error) {
	switch FirewallMode(strings.ToLower(strings.TrimSpace(value))) {
	case FirewallModeAllowlist:
		return FirewallModeAllowlist, nil
	case FirewallModeDenylist:
		return FirewallModeDenylist, nil
	default:
		return "", fmt.Errorf("invalid firewall mode %q", value)
	}
}

func normalizeFirewallProtocol(value string) (FirewallProtocol, error) {
	switch FirewallProtocol(strings.ToLower(strings.TrimSpace(value))) {
	case FirewallProtocolTCP:
		return FirewallProtocolTCP, nil
	case FirewallProtocolUDP:
		return FirewallProtocolUDP, nil
	case FirewallProtocolICMP:
		return FirewallProtocolICMP, nil
	default:
		return "", fmt.Errorf("invalid firewall protocol %q", value)
	}
}

func parseFirewallPrefixes(rawCIDRs []string, fieldName string) ([]netip.Prefix, error) {
	if len(rawCIDRs) == 0 {
		return nil, fmt.Errorf("%s must not be empty", fieldName)
	}

	prefixes := make([]netip.Prefix, 0, len(rawCIDRs))
	for _, rawCIDR := range rawCIDRs {
		prefix, err := parseFirewallPrefix(rawCIDR)
		if err != nil {
			return nil, fmt.Errorf("parse %s entry %q: %w", fieldName, rawCIDR, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseFirewallPrefix(rawCIDR string) (netip.Prefix, error) {
	value := strings.TrimSpace(rawCIDR)
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("CIDR is empty")
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		addr, addrErr := netip.ParseAddr(value)
		if addrErr != nil {
			return netip.Prefix{}, err
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("only IPv4 CIDRs are supported")
	}

	return prefix, nil
}

func parseFirewallDestinationPorts(protocol FirewallProtocol, rawPorts []int) ([]uint16, error) {
	switch protocol {
	case FirewallProtocolTCP, FirewallProtocolUDP:
		if len(rawPorts) == 0 {
			return nil, fmt.Errorf("dst_ports must not be empty for protocol %q", protocol)
		}
	case FirewallProtocolICMP:
		if len(rawPorts) != 0 {
			return nil, fmt.Errorf("dst_ports are not supported for protocol %q", protocol)
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported firewall protocol %q", protocol)
	}

	ports := make([]uint16, 0, len(rawPorts))
	for _, rawPort := range rawPorts {
		if rawPort < 1 || rawPort > 65535 {
			return nil, fmt.Errorf("dst_ports entry %d is out of range", rawPort)
		}
		ports = append(ports, uint16(rawPort))
	}
	return ports, nil
}
