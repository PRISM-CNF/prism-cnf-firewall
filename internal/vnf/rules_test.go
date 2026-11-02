package vnf

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"nse-ovs-firewall/internal"
	"nse-ovs-firewall/internal/processor"
)

func TestRenderInstallScriptAllowlist(t *testing.T) {
	t.Parallel()

	sessionCtx := mustSessionContext(t)
	policy := &internal.FirewallPolicy{
		Mode: internal.FirewallModeAllowlist,
		Rules: []internal.FirewallRule{
			{
				Name:             "allow-http-alt",
				LeftCIDRs:        []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
				RightCIDRs:       []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
				Protocol:         internal.FirewallProtocolTCP,
				DestinationPorts: []uint16{8080},
			},
			{
				Name:             "allow-udp-iperf",
				LeftCIDRs:        []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
				RightCIDRs:       []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
				Protocol:         internal.FirewallProtocolUDP,
				DestinationPorts: []uint16{5201},
			},
			{
				Name:       "allow-icmp",
				LeftCIDRs:  []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
				RightCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
				Protocol:   internal.FirewallProtocolICMP,
			},
		},
	}

	script, err := renderInstallScript(sessionCtx, policy, "nsmfwtest")
	if err != nil {
		t.Fatalf("renderInstallScript() error = %v", err)
	}

	expectedSnippets := []string{
		"add table bridge nsmfwtest",
		`add rule bridge nsmfwtest forward iifname "if-in" oifname "if-out" ether type arp accept`,
		`add rule bridge nsmfwtest forward iifname "if-in" oifname "if-out" ether type ip ip saddr 10.0.0.1/32 ip daddr 10.0.0.2/32 ip protocol tcp tcp dport 8080 accept`,
		`add rule bridge nsmfwtest forward iifname "if-out" oifname "if-in" ether type ip ip saddr 10.0.0.2/32 ip daddr 10.0.0.1/32 ip protocol tcp tcp sport 8080 accept`,
		`add rule bridge nsmfwtest forward iifname "if-in" oifname "if-out" ether type ip ip saddr 10.0.0.1/32 ip daddr 10.0.0.2/32 ip protocol udp udp dport 5201 accept`,
		`add rule bridge nsmfwtest forward iifname "if-out" oifname "if-in" ether type ip ip saddr 10.0.0.2/32 ip daddr 10.0.0.1/32 ip protocol udp udp sport 5201 accept`,
		`add rule bridge nsmfwtest forward iifname "if-in" oifname "if-out" ether type ip ip saddr 10.0.0.1/32 ip daddr 10.0.0.2/32 ip protocol icmp accept`,
		`add rule bridge nsmfwtest forward iifname "if-out" oifname "if-in" ether type ip ip saddr 10.0.0.2/32 ip daddr 10.0.0.1/32 ip protocol icmp accept`,
		`add rule bridge nsmfwtest forward iifname "if-in" oifname "if-out" ether type ip drop`,
		`add rule bridge nsmfwtest forward iifname "if-out" oifname "if-in" ether type ip drop`,
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(script, snippet) {
			t.Fatalf("rendered script missing %q\n%s", snippet, script)
		}
	}
}

func TestInstallTrafficRulesLifecycle(t *testing.T) {
	t.Parallel()

	sessionCtx := mustSessionContext(t)
	policy := &internal.FirewallPolicy{
		Mode: internal.FirewallModeDenylist,
		Rules: []internal.FirewallRule{
			{
				Name:             "deny-demo",
				LeftCIDRs:        []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
				RightCIDRs:       []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
				Protocol:         internal.FirewallProtocolTCP,
				DestinationPorts: []uint16{80},
			},
		},
	}
	runner := &recordingNFTRunner{}

	session, err := installTrafficRules(context.Background(), sessionCtx, policy, runner)
	if err != nil {
		t.Fatalf("installTrafficRules() error = %v", err)
	}

	if len(runner.scripts) != 2 {
		t.Fatalf("runner script count after install = %d, want 2", len(runner.scripts))
	}
	if !strings.Contains(runner.scripts[0], "delete table bridge") {
		t.Fatalf("install pre-clean script missing delete table command\n%s", runner.scripts[0])
	}
	if !strings.Contains(runner.scripts[1], "ether type ip accept") {
		t.Fatalf("denylist install script missing catch-all accept rule\n%s", runner.scripts[1])
	}

	if got, ok := sessionCtx.State().Load(StateKeyFirewallMode); !ok || got != string(internal.FirewallModeDenylist) {
		t.Fatalf("state firewall mode = %v, %v; want %q, true", got, ok, internal.FirewallModeDenylist)
	}
	if got, ok := sessionCtx.State().Load(StateKeyFirewallRules); !ok || got != 1 {
		t.Fatalf("state firewall rules = %v, %v; want 1, true", got, ok)
	}
	if _, ok := sessionCtx.State().Load(StateKeyFirewallTable); !ok {
		t.Fatal("state firewall table missing")
	}

	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("session.Close() error = %v", err)
	}
	if len(runner.scripts) != 3 {
		t.Fatalf("runner script count after cleanup = %d, want 3", len(runner.scripts))
	}
	if !strings.Contains(runner.scripts[2], "delete table bridge") {
		t.Fatalf("cleanup script missing delete table command\n%s", runner.scripts[2])
	}
}

type recordingNFTRunner struct {
	scripts []string
}

func (r *recordingNFTRunner) Run(_ context.Context, script string) error {
	r.scripts = append(r.scripts, script)
	return nil
}

func mustSessionContext(t *testing.T) *SessionContext {
	t.Helper()

	sessionCtx, err := newSessionContext(&processor.Runtime{
		Flow: &processor.Flow{
			ConnectionID:     "conn-1",
			IngressInterface: "if-in",
			EgressInterface:  "if-out",
		},
	})
	if err != nil {
		t.Fatalf("newSessionContext() error = %v", err)
	}
	return sessionCtx
}
