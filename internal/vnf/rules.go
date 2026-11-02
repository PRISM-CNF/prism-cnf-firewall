package vnf

import (
	"context"
	"fmt"
	"hash/fnv"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/networkservicemesh/sdk/pkg/tools/log"

	"nse-ovs-firewall/internal"
	"nse-ovs-firewall/internal/processor"
)

const policyPollInterval = 2 * time.Second

type nftRunner interface {
	Run(ctx context.Context, script string) error
}

type execNFTRunner struct {
	binary string
}

func NewNoopRuleInstaller() RuleInstaller {
	return RuleInstallerFunc(func(_ context.Context, _ *SessionContext) (processor.Session, error) {
		return processor.CloseFunc(func(context.Context) error {
			return nil
		}), nil
	})
}

func DefaultRuleInstaller(rulesPath string) RuleInstaller {
	if strings.TrimSpace(rulesPath) == "" {
		return NewNoopRuleInstaller()
	}

	return RuleInstallerFunc(func(ctx context.Context, sessionCtx *SessionContext) (processor.Session, error) {
		return installTrafficRulesFromPath(ctx, sessionCtx, rulesPath, &execNFTRunner{binary: "nft"})
	})
}

func installTrafficRules(ctx context.Context, sessionCtx *SessionContext, policy *internal.FirewallPolicy, runner nftRunner) (processor.Session, error) {
	if sessionCtx == nil {
		return nil, fmt.Errorf("session context is required")
	}
	if policy == nil {
		return nil, fmt.Errorf("firewall policy is required")
	}
	if runner == nil {
		return nil, fmt.Errorf("nft runner is required")
	}

	tableName := firewallTableName(sessionCtx.ConnectionID())
	installScript, err := renderInstallScript(sessionCtx, policy, tableName)
	if err != nil {
		return nil, err
	}
	if err := applyInstallScript(ctx, runner, tableName, installScript); err != nil {
		return nil, err
	}

	log.FromContext(ctx).Infof(
		"installed firewall nftables rules table=%s mode=%s rules=%d ingress=%s egress=%s",
		tableName,
		policy.Mode,
		len(policy.Rules),
		sessionCtx.IngressInterface(),
		sessionCtx.EgressInterface(),
	)

	if state := sessionCtx.State(); state != nil {
		state.Store(StateKeyFirewallMode, string(policy.Mode))
		state.Store(StateKeyFirewallRules, len(policy.Rules))
		state.Store(StateKeyFirewallTable, tableName)
	}

	return processor.CloseFunc(func(closeCtx context.Context) error {
		err := runner.Run(closeCtx, renderDeleteScript(tableName))
		if isMissingNFTObjectError(err) {
			return nil
		}
		return err
	}), nil
}

func installTrafficRulesFromPath(ctx context.Context, sessionCtx *SessionContext, rulesPath string, runner nftRunner) (processor.Session, error) {
	if sessionCtx == nil {
		return nil, fmt.Errorf("session context is required")
	}
	if strings.TrimSpace(rulesPath) == "" {
		return nil, fmt.Errorf("firewall rules path is required")
	}
	if runner == nil {
		return nil, fmt.Errorf("nft runner is required")
	}

	tableName := firewallTableName(sessionCtx.ConnectionID())
	logCtx := log.WithLog(context.Background(), log.FromContext(ctx))
	session := &watchedRuleSession{
		runner:    runner,
		rulesPath: rulesPath,
		tableName: tableName,
		flow:      sessionCtx.Flow(),
		state:     sessionCtx.State(),
		logCtx:    logCtx,
		closeCh:   make(chan struct{}),
		doneCh:    make(chan struct{}),
	}

	policy, installScript, err := session.loadInstallScript()
	if err != nil {
		return nil, err
	}
	if err := session.applyPolicy(ctx, policy, installScript); err != nil {
		return nil, err
	}

	log.FromContext(ctx).Infof(
		"installed firewall nftables rules table=%s mode=%s rules=%d ingress=%s egress=%s",
		tableName,
		policy.Mode,
		len(policy.Rules),
		session.flow.IngressInterface,
		session.flow.EgressInterface,
	)

	go session.watchPolicy()
	return session, nil
}

func renderInstallScript(sessionCtx *SessionContext, policy *internal.FirewallPolicy, tableName string) (string, error) {
	if sessionCtx == nil {
		return "", fmt.Errorf("session context is required")
	}
	return renderInstallScriptForFlow(sessionCtx.Flow(), policy, tableName)
}

func renderInstallScriptForFlow(flow FlowInfo, policy *internal.FirewallPolicy, tableName string) (string, error) {
	if policy == nil {
		return "", fmt.Errorf("firewall policy is required")
	}
	if flow.IngressInterface == "" || flow.EgressInterface == "" {
		return "", fmt.Errorf("both ingress and egress interfaces are required")
	}
	if tableName == "" {
		return "", fmt.Errorf("table name is required")
	}

	var builder strings.Builder
	writeNFTLine(&builder, "add table bridge %s", tableName)
	writeNFTLine(
		&builder,
		"add chain bridge %s forward { type filter hook forward priority 0; policy accept; }",
		tableName,
	)

	writeARPAllowRules(&builder, tableName, flow.IngressInterface, flow.EgressInterface)

	verdict := "accept"
	if policy.Mode == internal.FirewallModeDenylist {
		verdict = "drop"
	}

	for _, rule := range policy.Rules {
		for _, leftCIDR := range rule.LeftCIDRs {
			for _, rightCIDR := range rule.RightCIDRs {
				if err := writeFirewallPairRules(
					&builder,
					tableName,
					flow.IngressInterface,
					flow.EgressInterface,
					rule,
					leftCIDR.String(),
					rightCIDR.String(),
					verdict,
				); err != nil {
					return "", err
				}
			}
		}
	}

	catchAllVerdict := "drop"
	if policy.Mode == internal.FirewallModeDenylist {
		catchAllVerdict = "accept"
	}
	writeIPv4CatchAllRules(&builder, tableName, flow.IngressInterface, flow.EgressInterface, catchAllVerdict)

	return builder.String(), nil
}

type watchedRuleSession struct {
	runner        nftRunner
	rulesPath     string
	tableName     string
	flow          FlowInfo
	state         *SessionState
	logCtx        context.Context
	closeCh       chan struct{}
	doneCh        chan struct{}
	closeOnce     sync.Once
	installScript string
	mu            sync.Mutex
}

func (s *watchedRuleSession) loadInstallScript() (*internal.FirewallPolicy, string, error) {
	policy, err := internal.LoadFirewallPolicyFromFile(s.rulesPath)
	if err != nil {
		return nil, "", fmt.Errorf("load firewall rules from %s: %w", s.rulesPath, err)
	}

	installScript, err := renderInstallScriptForFlow(s.flow, policy, s.tableName)
	if err != nil {
		return nil, "", err
	}
	return policy, installScript, nil
}

func (s *watchedRuleSession) applyPolicy(ctx context.Context, policy *internal.FirewallPolicy, installScript string) error {
	if policy == nil {
		return fmt.Errorf("firewall policy is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := applyInstallScript(ctx, s.runner, s.tableName, installScript); err != nil {
		return err
	}

	s.installScript = installScript
	if s.state != nil {
		s.state.Store(StateKeyFirewallMode, string(policy.Mode))
		s.state.Store(StateKeyFirewallRules, len(policy.Rules))
		s.state.Store(StateKeyFirewallTable, s.tableName)
	}
	return nil
}

func (s *watchedRuleSession) watchPolicy() {
	ticker := time.NewTicker(policyPollInterval)
	defer ticker.Stop()
	defer close(s.doneCh)

	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
		}

		policy, installScript, err := s.loadInstallScript()
		if err != nil {
			log.FromContext(s.logCtx).Errorf("reload firewall rules failed for table=%s: %v", s.tableName, err)
			continue
		}

		s.mu.Lock()
		unchanged := installScript == s.installScript
		s.mu.Unlock()
		if unchanged {
			continue
		}

		applyCtx, cancel := context.WithTimeout(s.logCtx, 10*time.Second)
		err = s.applyPolicy(applyCtx, policy, installScript)
		cancel()
		if err != nil {
			log.FromContext(s.logCtx).Errorf("apply reloaded firewall rules failed for table=%s: %v", s.tableName, err)
			continue
		}

		log.FromContext(s.logCtx).Infof(
			"reloaded firewall nftables rules table=%s mode=%s rules=%d ingress=%s egress=%s",
			s.tableName,
			policy.Mode,
			len(policy.Rules),
			s.flow.IngressInterface,
			s.flow.EgressInterface,
		)
	}
}

func (s *watchedRuleSession) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
	<-s.doneCh

	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.runner.Run(ctx, renderDeleteScript(s.tableName))
	if isMissingNFTObjectError(err) {
		return nil
	}
	return err
}

func renderDeleteScript(tableName string) string {
	var builder strings.Builder
	writeNFTLine(&builder, "delete table bridge %s", tableName)
	return builder.String()
}

func applyInstallScript(ctx context.Context, runner nftRunner, tableName string, installScript string) error {
	if err := runner.Run(ctx, renderDeleteScript(tableName)); err != nil && !isMissingNFTObjectError(err) {
		return err
	}
	if err := runner.Run(ctx, installScript); err != nil {
		_ = runner.Run(ctx, renderDeleteScript(tableName))
		return err
	}
	return nil
}

func writeARPAllowRules(builder *strings.Builder, tableName string, ingress string, egress string) {
	writeNFTLine(
		builder,
		"add rule bridge %s forward iifname %q oifname %q ether type arp accept",
		tableName,
		ingress,
		egress,
	)
	writeNFTLine(
		builder,
		"add rule bridge %s forward iifname %q oifname %q ether type arp accept",
		tableName,
		egress,
		ingress,
	)
}

func writeFirewallPairRules(builder *strings.Builder, tableName string, ingress string, egress string, rule internal.FirewallRule, leftCIDR string, rightCIDR string, verdict string) error {
	switch rule.Protocol {
	case internal.FirewallProtocolICMP:
		match := "ip protocol icmp"
		writeForwardProtocolRule(
			builder,
			tableName,
			ingress,
			egress,
			leftCIDR,
			rightCIDR,
			match,
			verdict,
		)
		writeReverseProtocolRule(
			builder,
			tableName,
			ingress,
			egress,
			leftCIDR,
			rightCIDR,
			match,
			verdict,
		)
		return nil
	case internal.FirewallProtocolTCP, internal.FirewallProtocolUDP:
		protocol := string(rule.Protocol)
		for _, dstPort := range rule.DestinationPorts {
			writeForwardProtocolRule(
				builder,
				tableName,
				ingress,
				egress,
				leftCIDR,
				rightCIDR,
				fmt.Sprintf("ip protocol %s %s dport %d", protocol, protocol, dstPort),
				verdict,
			)
			writeReverseProtocolRule(
				builder,
				tableName,
				ingress,
				egress,
				leftCIDR,
				rightCIDR,
				fmt.Sprintf("ip protocol %s %s sport %d", protocol, protocol, dstPort),
				verdict,
			)
		}
		return nil
	default:
		return fmt.Errorf("unsupported firewall protocol %q", rule.Protocol)
	}
}

func writeForwardProtocolRule(builder *strings.Builder, tableName string, ingress string, egress string, leftCIDR string, rightCIDR string, match string, verdict string) {
	writeNFTLine(
		builder,
		"add rule bridge %s forward iifname %q oifname %q ether type ip ip saddr %s ip daddr %s %s %s",
		tableName,
		ingress,
		egress,
		leftCIDR,
		rightCIDR,
		match,
		verdict,
	)
}

func writeReverseProtocolRule(builder *strings.Builder, tableName string, ingress string, egress string, leftCIDR string, rightCIDR string, match string, verdict string) {
	writeNFTLine(
		builder,
		"add rule bridge %s forward iifname %q oifname %q ether type ip ip saddr %s ip daddr %s %s %s",
		tableName,
		egress,
		ingress,
		rightCIDR,
		leftCIDR,
		match,
		verdict,
	)
}

func writeIPv4CatchAllRules(builder *strings.Builder, tableName string, ingress string, egress string, verdict string) {
	writeNFTLine(
		builder,
		"add rule bridge %s forward iifname %q oifname %q ether type ip %s",
		tableName,
		ingress,
		egress,
		verdict,
	)
	writeNFTLine(
		builder,
		"add rule bridge %s forward iifname %q oifname %q ether type ip %s",
		tableName,
		egress,
		ingress,
		verdict,
	)
}

func writeNFTLine(builder *strings.Builder, format string, args ...any) {
	builder.WriteString(fmt.Sprintf(format, args...))
	builder.WriteByte('\n')
}

func firewallTableName(connectionID string) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(connectionID))
	return fmt.Sprintf("nsmfw%x", hasher.Sum64())
}

func (r *execNFTRunner) Run(ctx context.Context, script string) error {
	if r == nil || r.binary == "" {
		return fmt.Errorf("nft binary is required")
	}
	if strings.TrimSpace(script) == "" {
		return fmt.Errorf("nft script is required")
	}

	cmd := exec.CommandContext(ctx, r.binary, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("%s -f -: %w", r.binary, err)
	}
	return fmt.Errorf("%s -f -: %w: %s", r.binary, err, message)
}

func isMissingNFTObjectError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such file or directory")
}
