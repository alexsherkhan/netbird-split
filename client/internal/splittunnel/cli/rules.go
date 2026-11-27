package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path"
	"strings"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

func (r *runner) appCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "app",
		Aliases: []string{"application"},
		Short:   "Manage application rules",
	}
	cmd.AddCommand(r.appListCmd(false))
	cmd.AddCommand(r.appListCmd(true))
	cmd.AddCommand(r.appAddCmd())
	cmd.AddCommand(r.appRemoveCmd())
	return cmd
}

func (r *runner) appListCmd(scan bool) *cobra.Command {
	var jsonOutput bool
	var query string
	use := "list"
	short := "List discovered applications"
	run := func(cmd *cobra.Command) error {
		client, closeFn, err := r.client(cmd)
		if err != nil {
			return err
		}
		defer closeFn()

		resp, err := client.ListApplications(cmd.Context(), &proto.ListSplitTunnelApplicationsRequest{
			ApiVersion: api.APIVersion,
			Query:      query,
		})
		if err != nil {
			return Classify(err)
		}

		output := applicationsOutput{
			Applications:   []applicationOutput{},
			RedactedFields: normalizeStrings(resp.GetRedactedFields()),
		}
		for _, app := range resp.GetApplications() {
			if app == nil {
				continue
			}
			output.Applications = append(output.Applications, applicationOutput{
				DesktopID:   app.GetDesktopId(),
				Name:        app.GetName(),
				IconName:    app.GetIconName(),
				IconPath:    app.GetIconPath(),
				Executable:  app.GetExecutable(),
				InstallType: app.GetInstallType(),
				SourcePath:  app.GetSourcePath(),
				NoDisplay:   app.GetNoDisplay(),
				Unknown:     app.GetUnknown(),
			})
		}
		if jsonOutput {
			return printJSON(cmd, output)
		}

		if len(output.Applications) == 0 {
			cmd.Println("No applications found.")
			return nil
		}
		cmd.Printf("%-32s %-32s %s\n", "DESKTOP ID", "NAME", "EXECUTABLE")
		for _, app := range output.Applications {
			cmd.Printf("%-32s %-32s %s\n", app.DesktopID, app.Name, app.Executable)
		}
		return nil
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd)
		},
	}
	if scan {
		cmd.Use = "scan"
		cmd.Short = "Scan and list discovered applications"
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	cmd.Flags().StringVar(&query, "query", "", "filter by desktop ID or display name substring")
	return cmd
}

func (r *runner) appAddCmd() *cobra.Command {
	var via string
	var name string
	var description string
	var exitNode string
	var priority int
	cmd := &cobra.Command{
		Use:   "add <desktop-id|executable|name>",
		Short: "Add an application rule",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			action, err := requiredAction(via)
			if err != nil {
				return err
			}
			if action == config.ActionExitNode && exitNode == "" {
				return Usagef("--exit-node is required with --via exit_node")
			}
			if action != config.ActionExitNode && exitNode != "" {
				return Usagef("--exit-node is only valid with --via exit_node")
			}

			condition, err := r.resolveApplication(cmd, args[0])
			if err != nil {
				return err
			}
			return r.addConditionRule(cmd, args[0], condition, action, name, description, exitNode, priority)
		},
	}
	cmd.Flags().StringVar(&via, "via", "", "routing action: vpn, direct, block or exit_node")
	cmd.Flags().StringVar(&name, "name", "", "rule name; defaults to the application name")
	cmd.Flags().StringVar(&description, "description", "", "optional rule description")
	cmd.Flags().StringVar(&exitNode, "exit-node", "", "exit node ID for --via exit_node")
	cmd.Flags().IntVar(&priority, "priority", 100, "rule priority; lower values take precedence")
	return cmd
}

func (r *runner) resolveApplication(cmd *cobra.Command, value string) (config.Condition, error) {
	client, closeFn, err := r.client(cmd)
	if err != nil {
		return config.Condition{}, err
	}
	defer closeFn()

	resp, err := client.ListApplications(cmd.Context(), &proto.ListSplitTunnelApplicationsRequest{
		ApiVersion: api.APIVersion,
		Query:      value,
	})
	if err != nil {
		return config.Condition{}, Classify(err)
	}

	var matches []*proto.SplitTunnelApplication
	for _, app := range resp.GetApplications() {
		if app == nil {
			continue
		}
		if app.GetDesktopId() == value || app.GetName() == value || app.GetExecutable() == value ||
			path.Base(app.GetExecutable()) == value {
			matches = append(matches, app)
		}
	}

	switch len(matches) {
	case 0:
		if strings.HasSuffix(value, ".desktop") {
			return config.Condition{Type: config.ConditionDesktopID, DesktopID: config.DesktopID(value)}, nil
		}
		if path.IsAbs(value) {
			return config.Condition{Type: config.ConditionExecutable, Executable: config.Executable(value)}, nil
		}
		return config.Condition{}, Usagef("application %q was not found; run \"netbird split app list\" to see discovered applications", value)
	case 1:
		app := matches[0]
		if app.GetDesktopId() != "" {
			return config.Condition{Type: config.ConditionDesktopID, DesktopID: config.DesktopID(app.GetDesktopId())}, nil
		}
		if path.IsAbs(app.GetExecutable()) {
			return config.Condition{Type: config.ConditionExecutable, Executable: config.Executable(app.GetExecutable())}, nil
		}
		return config.Condition{}, Usagef("application %q has no desktop ID or executable path to match", value)
	default:
		ids := make([]string, 0, len(matches))
		for _, app := range matches {
			ids = append(ids, app.GetDesktopId())
		}
		return config.Condition{}, Usagef("application %q matches multiple entries (%s); use a desktop ID", value, strings.Join(ids, ", "))
	}
}

func (r *runner) appRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <desktop-id|executable|rule-id>",
		Short: "Remove an application rule",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			value := args[0]
			return r.removeRule(cmd, func(rule *config.Rule) bool {
				if string(rule.ID) == value || rule.Name == value {
					return true
				}
				return anyCondition(rule, func(condition *config.Condition) bool {
					switch condition.Type {
					case config.ConditionDesktopID:
						return string(condition.DesktopID) == value
					case config.ConditionExecutable:
						return string(condition.Executable) == value || path.Base(string(condition.Executable)) == value
					}
					return false
				})
			}, fmt.Sprintf("application or rule %q was not found", value))
		},
	}
	return cmd
}

func (r *runner) domainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Manage domain rules",
	}
	cmd.AddCommand(r.domainListCmd())
	cmd.AddCommand(r.domainAddCmd())
	cmd.AddCommand(r.domainRemoveCmd())
	return cmd
}

func (r *runner) domainListCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List domain rules",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			rules, err := client.ListRules(cmd.Context(), &proto.ListSplitTunnelRulesRequest{ApiVersion: api.APIVersion})
			if err != nil {
				return Classify(err)
			}

			output := domainListOutput{Revision: rules.GetRevision(), Domains: []domainOutput{}}
			for _, rule := range rules.GetRules() {
				if rule == nil {
					continue
				}
				collectDomainConditions(rule, func(typ, value string) {
					output.Domains = append(output.Domains, domainOutput{
						RuleID:   rule.GetId(),
						RuleName: rule.GetName(),
						Pattern:  value,
						Type:     typ,
						Action:   rule.GetAction(),
						Enabled:  rule.GetEnabled(),
						Priority: int(rule.GetPriority()),
					})
				})
			}
			if jsonOutput {
				return printJSON(cmd, output)
			}
			if len(output.Domains) == 0 {
				cmd.Println("No domain rules.")
				return nil
			}
			cmd.Printf("%-20s %-32s %-16s %s\n", "RULE", "PATTERN", "ACTION", "TYPE")
			for _, domain := range output.Domains {
				cmd.Printf("%-20s %-32s %-16s %s\n", domain.RuleID, domain.Pattern, domain.Action, domain.Type)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func (r *runner) domainAddCmd() *cobra.Command {
	var via string
	var name string
	var description string
	var exitNode string
	var priority int
	cmd := &cobra.Command{
		Use:   "add <domain|*.wildcard>",
		Short: "Add a domain rule",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			action, err := requiredAction(via)
			if err != nil {
				return err
			}
			if action == config.ActionExitNode && exitNode == "" {
				return Usagef("--exit-node is required with --via exit_node")
			}
			if action != config.ActionExitNode && exitNode != "" {
				return Usagef("--exit-node is only valid with --via exit_node")
			}

			condition, err := parseDomainCondition(args[0])
			if err != nil {
				return err
			}
			return r.addConditionRule(cmd, args[0], condition, action, name, description, exitNode, priority)
		},
	}
	cmd.Flags().StringVar(&via, "via", "", "routing action: vpn, direct, block or exit_node")
	cmd.Flags().StringVar(&name, "name", "", "rule name; defaults to the domain")
	cmd.Flags().StringVar(&description, "description", "", "optional rule description")
	cmd.Flags().StringVar(&exitNode, "exit-node", "", "exit node ID for --via exit_node")
	cmd.Flags().IntVar(&priority, "priority", 100, "rule priority; lower values take precedence")
	return cmd
}

func (r *runner) domainRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <domain|*.wildcard|rule-id>",
		Short: "Remove a domain rule",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			value := args[0]
			normalized, err := parseDomainCondition(value)
			if err != nil {
				normalized = config.Condition{}
			}
			return r.removeRule(cmd, func(rule *config.Rule) bool {
				if string(rule.ID) == value || rule.Name == value {
					return true
				}
				return anyCondition(rule, func(condition *config.Condition) bool {
					if normalized.Type == "" {
						return false
					}
					return condition.Type == normalized.Type && conditionKey(*condition) == conditionKey(normalized)
				})
			}, fmt.Sprintf("domain or rule %q was not found", value))
		},
	}
	return cmd
}

func (r *runner) ipCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ip",
		Short: "Manage single-IP rules",
	}
	cmd.AddCommand(r.ipListCmd())
	cmd.AddCommand(r.ipAddCmd())
	cmd.AddCommand(r.ipRemoveCmd())
	return cmd
}

func (r *runner) ipListCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List single-IP rules",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			rules, err := client.ListRules(cmd.Context(), &proto.ListSplitTunnelRulesRequest{ApiVersion: api.APIVersion})
			if err != nil {
				return Classify(err)
			}

			output := ipListOutput{Revision: rules.GetRevision(), IPs: []ipOutput{}}
			for _, rule := range rules.GetRules() {
				if rule == nil {
					continue
				}
				collectCIDRConditions(rule, func(prefix netip.Prefix) {
					if prefix.Bits() != prefix.Addr().BitLen() {
						return
					}
					output.IPs = append(output.IPs, ipOutput{
						RuleID:   rule.GetId(),
						RuleName: rule.GetName(),
						Address:  prefix.Addr().String(),
						Action:   rule.GetAction(),
						Enabled:  rule.GetEnabled(),
						Priority: int(rule.GetPriority()),
					})
				})
			}
			if jsonOutput {
				return printJSON(cmd, output)
			}
			if len(output.IPs) == 0 {
				cmd.Println("No IP rules.")
				return nil
			}
			cmd.Printf("%-20s %-24s %-16s\n", "RULE", "ADDRESS", "ACTION")
			for _, ip := range output.IPs {
				cmd.Printf("%-20s %-24s %-16s\n", ip.RuleID, ip.Address, ip.Action)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func (r *runner) ipAddCmd() *cobra.Command {
	var via string
	var name string
	var description string
	var exitNode string
	var priority int
	cmd := &cobra.Command{
		Use:   "add <ip>",
		Short: "Add a single-IP rule",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			action, err := requiredAction(via)
			if err != nil {
				return err
			}
			if action == config.ActionExitNode && exitNode == "" {
				return Usagef("--exit-node is required with --via exit_node")
			}
			if action != config.ActionExitNode && exitNode != "" {
				return Usagef("--exit-node is only valid with --via exit_node")
			}

			condition, err := parseIPCondition(args[0])
			if err != nil {
				return err
			}
			return r.addConditionRule(cmd, args[0], condition, action, name, description, exitNode, priority)
		},
	}
	cmd.Flags().StringVar(&via, "via", "", "routing action: vpn, direct, block or exit_node")
	cmd.Flags().StringVar(&name, "name", "", "rule name; defaults to the IP address")
	cmd.Flags().StringVar(&description, "description", "", "optional rule description")
	cmd.Flags().StringVar(&exitNode, "exit-node", "", "exit node ID for --via exit_node")
	cmd.Flags().IntVar(&priority, "priority", 100, "rule priority; lower values take precedence")
	return cmd
}

func (r *runner) ipRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <ip|rule-id>",
		Short: "Remove a single-IP rule",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			value := args[0]
			normalized, err := parseIPCondition(value)
			if err != nil {
				normalized = config.Condition{}
			}
			return r.removeRule(cmd, func(rule *config.Rule) bool {
				if string(rule.ID) == value || rule.Name == value {
					return true
				}
				return anyCondition(rule, func(condition *config.Condition) bool {
					if normalized.Type == "" {
						return false
					}
					return condition.Type == config.ConditionCIDR &&
						condition.Prefix == normalized.Prefix
				})
			}, fmt.Sprintf("IP or rule %q was not found", value))
		},
	}
	return cmd
}

func (r *runner) cidrCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cidr",
		Short: "Manage CIDR rules",
	}
	cmd.AddCommand(r.cidrListCmd())
	cmd.AddCommand(r.cidrAddCmd())
	cmd.AddCommand(r.cidrRemoveCmd())
	return cmd
}

func (r *runner) cidrListCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List CIDR rules",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			rules, err := client.ListRules(cmd.Context(), &proto.ListSplitTunnelRulesRequest{ApiVersion: api.APIVersion})
			if err != nil {
				return Classify(err)
			}

			output := cidrListOutput{Revision: rules.GetRevision(), CIDRs: []cidrOutput{}}
			for _, rule := range rules.GetRules() {
				if rule == nil {
					continue
				}
				collectCIDRConditions(rule, func(prefix netip.Prefix) {
					if prefix.Bits() == prefix.Addr().BitLen() {
						return
					}
					output.CIDRs = append(output.CIDRs, cidrOutput{
						RuleID:   rule.GetId(),
						RuleName: rule.GetName(),
						Prefix:   prefix.String(),
						Action:   rule.GetAction(),
						Enabled:  rule.GetEnabled(),
						Priority: int(rule.GetPriority()),
					})
				})
			}
			if jsonOutput {
				return printJSON(cmd, output)
			}
			if len(output.CIDRs) == 0 {
				cmd.Println("No CIDR rules.")
				return nil
			}
			cmd.Printf("%-20s %-24s %-16s\n", "RULE", "PREFIX", "ACTION")
			for _, cidr := range output.CIDRs {
				cmd.Printf("%-20s %-24s %-16s\n", cidr.RuleID, cidr.Prefix, cidr.Action)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func (r *runner) cidrAddCmd() *cobra.Command {
	var via string
	var name string
	var description string
	var exitNode string
	var priority int
	cmd := &cobra.Command{
		Use:   "add <cidr>",
		Short: "Add a CIDR rule",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			action, err := requiredAction(via)
			if err != nil {
				return err
			}
			if action == config.ActionExitNode && exitNode == "" {
				return Usagef("--exit-node is required with --via exit_node")
			}
			if action != config.ActionExitNode && exitNode != "" {
				return Usagef("--exit-node is only valid with --via exit_node")
			}

			condition, err := parseCIDRCondition(args[0])
			if err != nil {
				return err
			}
			return r.addConditionRule(cmd, args[0], condition, action, name, description, exitNode, priority)
		},
	}
	cmd.Flags().StringVar(&via, "via", "", "routing action: vpn, direct, block or exit_node")
	cmd.Flags().StringVar(&name, "name", "", "rule name; defaults to the CIDR")
	cmd.Flags().StringVar(&description, "description", "", "optional rule description")
	cmd.Flags().StringVar(&exitNode, "exit-node", "", "exit node ID for --via exit_node")
	cmd.Flags().IntVar(&priority, "priority", 100, "rule priority; lower values take precedence")
	return cmd
}

func (r *runner) cidrRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <cidr|rule-id>",
		Short: "Remove a CIDR rule",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			value := args[0]
			normalized, err := parseCIDRCondition(value)
			if err != nil {
				normalized = config.Condition{}
			}
			return r.removeRule(cmd, func(rule *config.Rule) bool {
				if string(rule.ID) == value || rule.Name == value {
					return true
				}
				return anyCondition(rule, func(condition *config.Condition) bool {
					if normalized.Type == "" {
						return false
					}
					return condition.Type == config.ConditionCIDR &&
						condition.Prefix == normalized.Prefix
				})
			}, fmt.Sprintf("CIDR or rule %q was not found", value))
		},
	}
	return cmd
}

func requiredAction(value string) (config.Action, error) {
	if strings.TrimSpace(value) == "" {
		return "", Usagef("--via is required; use vpn, direct, block or exit_node")
	}
	return parseAction(value)
}

func parseDomainCondition(value string) (config.Condition, error) {
	if strings.HasPrefix(value, "*.") {
		wildcard, err := config.NormalizeWildcardDomain(value)
		if err != nil {
			return config.Condition{}, Usagef("invalid domain %q: %v", value, err)
		}
		return config.Condition{Type: config.ConditionWildcardDomain, Wildcard: wildcard}, nil
	}
	domain, err := config.NormalizeDomain(value)
	if err != nil {
		return config.Condition{}, Usagef("invalid domain %q: %v", value, err)
	}
	return config.Condition{Type: config.ConditionDomain, Domain: domain}, nil
}

func parseIPCondition(value string) (config.Condition, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return config.Condition{}, Usagef("invalid IP address %q: %v", value, err)
	}
	addr = addr.Unmap()
	if addr.Zone() != "" {
		return config.Condition{}, Usagef("IP address %q must not contain a zone", value)
	}
	return config.Condition{Type: config.ConditionCIDR, Prefix: netip.PrefixFrom(addr, addr.BitLen())}, nil
}

func parseCIDRCondition(value string) (config.Condition, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return config.Condition{}, Usagef("invalid CIDR %q: %v", value, err)
	}
	if prefix.Addr().Zone() != "" {
		return config.Condition{}, Usagef("CIDR %q must not contain a zone", value)
	}
	if prefix.Addr().Is4In6() {
		return config.Condition{}, Usagef("CIDR %q must use a plain IPv4 address", value)
	}
	if prefix.Masked() != prefix {
		return config.Condition{}, Usagef("CIDR %q has host bits set; use the network address", value)
	}
	return config.Condition{Type: config.ConditionCIDR, Prefix: prefix}, nil
}

func (r *runner) addConditionRule(cmd *cobra.Command, value string, condition config.Condition, action config.Action, name, description, exitNode string, priority int) error {
	if name == "" {
		name = value
	}
	ruleName := name
	_, revision, err := r.mutateConfig(cmd, func(cfg *config.Config) error {
		if cfg.SplitTunnel.Mode == config.ModeStandard {
			return Usagef("standard mode does not evaluate rules; set a mode first with \"netbird split mode include\", \"exclude\" or \"custom\"")
		}
		for i := range cfg.SplitTunnel.Rules {
			rule := &cfg.SplitTunnel.Rules[i]
			if anyCondition(rule, func(existing *config.Condition) bool {
				return conditionKey(*existing) == conditionKey(condition)
			}) {
				return Usagef("%q is already covered by rule %q", value, rule.ID)
			}
		}
		cfg.SplitTunnel.Rules = append(cfg.SplitTunnel.Rules, config.Rule{
			ID:          nextRuleID(condition, cfg.SplitTunnel.Rules),
			Name:        ruleName,
			Enabled:     true,
			Priority:    priority,
			MatchMode:   config.MatchAll,
			Conditions:  []config.Condition{condition},
			Action:      action,
			ExitNodeID:  config.ExitNodeID(exitNode),
			Description: description,
		})
		return nil
	})
	if err != nil {
		return err
	}
	cmd.Printf("Added rule %q at revision %d.\n", ruleName, revision)
	return nil
}

func (r *runner) removeRule(cmd *cobra.Command, match func(*config.Rule) bool, notFound string) error {
	removed := ""
	_, revision, err := r.mutateConfig(cmd, func(cfg *config.Config) error {
		matches := make([]int, 0, 1)
		for i := range cfg.SplitTunnel.Rules {
			if match(&cfg.SplitTunnel.Rules[i]) {
				matches = append(matches, i)
			}
		}
		switch len(matches) {
		case 0:
			return Usagef("%s", notFound)
		case 1:
			removed = string(cfg.SplitTunnel.Rules[matches[0]].ID)
			cfg.SplitTunnel.Rules = append(cfg.SplitTunnel.Rules[:matches[0]], cfg.SplitTunnel.Rules[matches[0]+1:]...)
			return nil
		default:
			ids := make([]string, 0, len(matches))
			for _, index := range matches {
				ids = append(ids, string(cfg.SplitTunnel.Rules[index].ID))
			}
			return Usagef("%s matches multiple rules (%s); remove one by rule ID", notFound, strings.Join(ids, ", "))
		}
	})
	if err != nil {
		return err
	}
	cmd.Printf("Removed rule %s at revision %d.\n", removed, revision)
	return nil
}

func nextRuleID(condition config.Condition, rules []config.Rule) config.RuleID {
	sum := sha256.Sum256([]byte(conditionKey(condition)))
	base := "cli-" + hex.EncodeToString(sum[:4])
	existing := make(map[config.RuleID]struct{}, len(rules))
	for i := range rules {
		existing[rules[i].ID] = struct{}{}
	}
	id := config.RuleID(base)
	for suffix := 2; ; suffix++ {
		if _, ok := existing[id]; !ok {
			return id
		}
		id = config.RuleID(fmt.Sprintf("%s-%d", base, suffix))
	}
}

func conditionKey(condition config.Condition) string {
	return protoConditionKey(conditionToProto(&condition))
}

func protoConditionKey(condition *proto.SplitTunnelCondition) string {
	if condition == nil {
		return ""
	}
	if len(condition.GetChildren()) == 0 {
		return condition.GetType() + ":" + condition.GetValue()
	}
	parts := make([]string, 0, len(condition.GetChildren()))
	for _, child := range condition.GetChildren() {
		parts = append(parts, protoConditionKey(child))
	}
	return condition.GetType() + ":[" + strings.Join(parts, ",") + "]"
}

func anyCondition(rule *config.Rule, match func(*config.Condition) bool) bool {
	for i := range rule.Conditions {
		if matchCondition(&rule.Conditions[i], match) {
			return true
		}
	}
	return false
}

func matchCondition(condition *config.Condition, match func(*config.Condition) bool) bool {
	if match(condition) {
		return true
	}
	for i := range condition.Children {
		if matchCondition(&condition.Children[i], match) {
			return true
		}
	}
	return false
}

func collectDomainConditions(rule *proto.SplitTunnelRule, collect func(typ, value string)) {
	for _, condition := range rule.GetConditions() {
		collectDomainCondition(condition, collect)
	}
}

func collectDomainCondition(condition *proto.SplitTunnelCondition, collect func(typ, value string)) {
	if condition == nil {
		return
	}
	switch condition.GetType() {
	case string(config.ConditionDomain), string(config.ConditionWildcardDomain):
		collect(condition.GetType(), condition.GetValue())
		return
	}
	for _, child := range condition.GetChildren() {
		collectDomainCondition(child, collect)
	}
}

func collectCIDRConditions(rule *proto.SplitTunnelRule, collect func(netip.Prefix)) {
	for _, condition := range rule.GetConditions() {
		collectCIDRCondition(condition, collect)
	}
}

func collectCIDRCondition(condition *proto.SplitTunnelCondition, collect func(netip.Prefix)) {
	if condition == nil {
		return
	}
	if condition.GetType() == string(config.ConditionCIDR) {
		prefix, err := netip.ParsePrefix(condition.GetValue())
		if err == nil {
			collect(prefix)
		}
		return
	}
	for _, child := range condition.GetChildren() {
		collectCIDRCondition(child, collect)
	}
}
