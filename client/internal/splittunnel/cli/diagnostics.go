package cli

import (
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

func (r *runner) profileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Inspect and exchange split tunnel configuration profiles",
		Long: "Inspect and exchange the configuration profile.\n\n" +
			"Split tunnel API version 1 stores one implicit configuration profile. Named profile creation " +
			"and activation are not part of this API version; use export and import to move a profile.",
	}
	cmd.AddCommand(r.profileListCmd())
	cmd.AddCommand(r.profileShowCmd())
	cmd.AddCommand(r.profileCreateCmd())
	cmd.AddCommand(r.profileActivateCmd())

	show := r.exportCmd()
	show.Use = "export [file]"
	show.Short = "Export the current profile"
	cmd.AddCommand(show)

	load := r.importCmd()
	load.Use = "import <file>"
	load.Short = "Import a profile"
	cmd.AddCommand(load)
	return cmd
}

func (r *runner) profileListCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List configuration profiles",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			cfg, revision, err := getConfig(cmd.Context(), client)
			if err != nil {
				return err
			}

			output := profileListOutput{Profiles: []profileOutput{{
				Name:     "current",
				Active:   true,
				Revision: revision,
			}}}
			if cfg != nil {
				output.Profiles[0].Mode = string(cfg.SplitTunnel.Mode)
			}
			if jsonOutput {
				return printJSON(cmd, output)
			}
			cmd.Printf("%-16s %-24s %-12s\n", "NAME", "MODE", "REVISION")
			for _, profile := range output.Profiles {
				cmd.Printf("%-16s %-24s %-12d\n", profile.Name, profile.Mode, profile.Revision)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func (r *runner) profileShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the current configuration profile as JSON",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			cfg, _, err := getConfig(cmd.Context(), client)
			if err != nil {
				return err
			}
			return writeConfig(cmd, cfg)
		},
	}
}

func (r *runner) profileCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <name>",
		Short: "Create a named profile",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, _ []string) error {
			return Unavailablef("named profiles are not supported by split tunnel API version 1; use \"netbird split export\" and \"netbird split import\" to move a configuration")
		},
	}
}

func (r *runner) profileActivateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "activate <name>",
		Short: "Activate a named profile",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, _ []string) error {
			return Unavailablef("named profiles are not supported by split tunnel API version 1; use \"netbird split import\" to apply a configuration")
		},
	}
}

func (r *runner) exportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export [file]",
		Short: "Export the current configuration",
		Long:  "Export the current split tunnel configuration as canonical JSON. Without a file, or with \"-\", output is written to stdout.",
		Args:  usageArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			cfg, _, err := getConfig(cmd.Context(), client)
			if err != nil {
				return err
			}
			if cfg == nil {
				return Usagef("no split tunnel configuration exists yet")
			}

			data, err := cfg.Encode()
			if err != nil {
				return Internalf("encode configuration: %v", err)
			}
			if len(args) == 0 || args[0] == "-" {
				_, err := cmd.OutOrStdout().Write(data)
				if err != nil {
					return Internalf("write configuration: %v", err)
				}
				return nil
			}
			if err := os.WriteFile(args[0], data, 0o600); err != nil {
				return Usagef("write %s: %v", args[0], err)
			}
			cmd.Printf("Wrote configuration to %s.\n", args[0])
			return nil
		},
	}
}

func writeConfig(cmd *cobra.Command, cfg *config.Config) error {
	if cfg == nil {
		return Usagef("no split tunnel configuration exists yet")
	}
	data, err := cfg.Encode()
	if err != nil {
		return Internalf("encode configuration: %v", err)
	}
	if _, err := cmd.OutOrStdout().Write(data); err != nil {
		return Internalf("write configuration: %v", err)
	}
	return nil
}

func (r *runner) importCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import a configuration",
		Long:  "Validate a configuration document and apply it as a new revision. Use \"-\" to read stdin.",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readConfigInput(cmd, args[0])
			if err != nil {
				return err
			}
			cfg, err := config.Parse(data)
			if err != nil {
				return Usagef("invalid configuration: %v", err)
			}
			if dryRun {
				cmd.Println("Configuration is valid; no changes were applied.")
				return nil
			}

			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			_, revision, err := getConfig(cmd.Context(), client)
			if err != nil {
				return err
			}
			newRevision, err := setConfig(cmd.Context(), client, cfg, revision)
			if err != nil {
				return err
			}
			cmd.Printf("Configuration imported at revision %d.\n", newRevision)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "validate the configuration without applying it")
	return cmd
}

func readConfigInput(cmd *cobra.Command, name string) ([]byte, error) {
	if name == "-" {
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, Usagef("read stdin: %v", err)
		}
		return data, nil
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, Usagef("read %s: %v", name, err)
	}
	return data, nil
}

func (r *runner) traceCmd() *cobra.Command {
	var sourceIP string
	var destinationIP string
	var domain string
	var app string
	var protocol string
	var sourcePort uint
	var destinationPort uint
	var direction string
	var uid int
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace a packet against the split tunnel policy",
		Long: "Evaluate one packet against the current policy.\n\n" +
			"The API traces packets by address. --domain resolves the name with the local resolver and " +
			"traces the first returned address; --app is not supported by API version 1.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if app != "" {
				return Usagef("--app traces are not supported by split tunnel API version 1; use --domain or --destination-ip")
			}
			if destinationIP == "" && domain == "" {
				return Usagef("one of --destination-ip or --domain is required")
			}

			destination := destinationIP
			if domain != "" {
				addresses, err := net.DefaultResolver.LookupNetIP(cmd.Context(), "ip", domain)
				if err != nil || len(addresses) == 0 {
					return Usagef("resolve %q: %v", domain, err)
				}
				destination = addresses[0].Unmap().String()
			}
			if sourceIP == "" {
				sourceIP = "0.0.0.0"
			}
			if direction == "" {
				direction = "outbound"
			}
			if sourcePort > 65535 || destinationPort > 65535 {
				return Usagef("ports must be between 0 and 65535")
			}
			if uid < -1 || (uid >= 0 && uint64(uid) > math.MaxUint32) {
				return Usagef("--uid must be between 0 and %d", uint64(math.MaxUint32))
			}

			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			request := &proto.TraceSplitTunnelPacketRequest{
				ApiVersion:      api.APIVersion,
				SourceIp:        sourceIP,
				DestinationIp:   destination,
				Protocol:        protocol,
				SourcePort:      uint32(sourcePort),
				DestinationPort: uint32(destinationPort),
				Direction:       direction,
			}
			if uid >= 0 {
				request.Uid = uint32(uid)
				request.HasUid = true
			}
			resp, err := client.TracePacket(cmd.Context(), request)
			if err != nil {
				return Classify(err)
			}

			output := traceOutput{
				APIVersion:     resp.GetApiVersion(),
				FinalAction:    resp.GetFinalAction(),
				Stages:         []stageOutput{},
				Redacted:       resp.GetRedacted(),
				RedactedFields: normalizeStrings(resp.GetRedactedFields()),
			}
			for _, stage := range resp.GetStages() {
				if stage == nil {
					continue
				}
				output.Stages = append(output.Stages, stageOutput{
					Name:              stage.GetName(),
					Message:           stage.GetMessage(),
					Allowed:           stage.GetAllowed(),
					ForwardingDetails: stage.GetForwardingDetails(),
				})
			}
			if jsonOutput {
				return printJSON(cmd, output)
			}
			for _, stage := range output.Stages {
				cmd.Printf("%s: %s (allowed=%t)\n", stage.Name, stage.Message, stage.Allowed)
			}
			cmd.Printf("Final action: %s\n", output.FinalAction)
			return nil
		},
	}
	cmd.Flags().StringVar(&sourceIP, "source-ip", "", "source IP address; defaults to 0.0.0.0")
	cmd.Flags().StringVar(&destinationIP, "destination-ip", "", "destination IP address")
	cmd.Flags().StringVar(&domain, "domain", "", "destination domain to resolve and trace")
	cmd.Flags().StringVar(&app, "app", "", "application to trace (not supported by API version 1)")
	cmd.Flags().StringVar(&protocol, "protocol", "tcp", "IP protocol: tcp or udp")
	cmd.Flags().UintVar(&sourcePort, "source-port", 0, "source port")
	cmd.Flags().UintVar(&destinationPort, "destination-port", 0, "destination port")
	cmd.Flags().StringVar(&direction, "direction", "", "packet direction; defaults to outbound")
	cmd.Flags().IntVar(&uid, "uid", -1, "restrict the trace to one Linux user ID")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func (r *runner) dnsCacheCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "dns-cache",
		Short: "Show the DNS cache",
		Long:  "Show the DNS cache exposed by the daemon. Split tunnel API version 1 does not expose a DNS cache.",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			if _, err := client.GetStatus(cmd.Context(), &proto.GetSplitTunnelStatusRequest{ApiVersion: api.APIVersion}); err != nil {
				return Classify(err)
			}

			output := dnsCacheOutput{
				Available: false,
				Entries:   []string{},
				Message:   "DNS cache is not exposed by split tunnel API version 1.",
			}
			if jsonOutput {
				return printJSON(cmd, output)
			}
			cmd.Println(output.Message)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func (r *runner) statsCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show local split tunnel statistics",
		Long:  "Show the counters the daemon exposes. Split tunnel API version 1 exposes state counts but not packet counters.",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			ctx := cmd.Context()
			status, err := client.GetStatus(ctx, &proto.GetSplitTunnelStatusRequest{ApiVersion: api.APIVersion})
			if err != nil {
				return Classify(err)
			}
			rules, err := client.ListRules(ctx, &proto.ListSplitTunnelRulesRequest{ApiVersion: api.APIVersion})
			if err != nil {
				return Classify(err)
			}

			output := statsOutput{
				Available:         true,
				Revision:          status.GetRevision(),
				Enabled:           status.GetEnabled(),
				Running:           status.GetRunning(),
				Mode:              status.GetMode(),
				Processes:         len(status.GetProcesses()),
				Rules:             len(rules.GetRules()),
				Conflicts:         len(rules.GetConflicts()),
				CountersAvailable: false,
			}
			if jsonOutput {
				return printJSON(cmd, output)
			}
			cmd.Printf("Enabled: %t\n", output.Enabled)
			cmd.Printf("Running: %t\n", output.Running)
			cmd.Printf("Mode: %s\n", output.Mode)
			cmd.Printf("Processes: %d\n", output.Processes)
			cmd.Printf("Rules: %d\n", output.Rules)
			cmd.Printf("Conflicts: %d\n", output.Conflicts)
			cmd.Println("Packet counters: not exposed by split tunnel API version 1.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func (r *runner) doctorCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check split tunnel health",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			ctx := cmd.Context()
			output := doctorOutput{Checks: []checkOutput{}}

			status, err := client.GetStatus(ctx, &proto.GetSplitTunnelStatusRequest{ApiVersion: api.APIVersion})
			if err != nil {
				return Classify(err)
			}
			output.Checks = append(output.Checks, checkOutput{
				Name:    "daemon",
				Status:  "ok",
				Message: "split tunnel service is reachable",
			})

			versionStatus := "ok"
			versionMessage := fmt.Sprintf("server API version %d matches client version %d", status.GetApiVersion(), api.APIVersion)
			if status.GetApiVersion() != api.APIVersion {
				versionStatus = "fail"
				versionMessage = fmt.Sprintf("server API version %d does not match client version %d", status.GetApiVersion(), api.APIVersion)
			}
			output.Checks = append(output.Checks, checkOutput{
				Name:    "api-version",
				Status:  versionStatus,
				Message: versionMessage,
			})

			_, _, configErr := getConfig(ctx, client)
			configStatus := "ok"
			configMessage := "configuration is valid"
			if configErr != nil {
				configStatus = "fail"
				configMessage = configErr.Error()
			}
			output.Checks = append(output.Checks, checkOutput{
				Name:    "configuration",
				Status:  configStatus,
				Message: configMessage,
			})

			rules, err := client.ListRules(ctx, &proto.ListSplitTunnelRulesRequest{ApiVersion: api.APIVersion})
			rulesStatus := "ok"
			rulesMessage := "rules are consistent"
			if err != nil {
				rulesStatus = "fail"
				rulesMessage = Classify(err).Error()
			} else if len(rules.GetConflicts()) > 0 {
				rulesStatus = "warn"
				rulesMessage = strings.Join(rules.GetConflicts(), "; ")
			}
			output.Checks = append(output.Checks, checkOutput{
				Name:    "rules",
				Status:  rulesStatus,
				Message: rulesMessage,
			})

			output.Healthy = true
			failures := 0
			for _, check := range output.Checks {
				if check.Status == "fail" {
					output.Healthy = false
					failures++
				}
			}

			if jsonOutput {
				if err := printJSON(cmd, output); err != nil {
					return err
				}
			} else {
				for _, check := range output.Checks {
					cmd.Printf("%-16s %-6s %s\n", check.Name, check.Status, check.Message)
				}
				if output.Healthy {
					cmd.Println("Healthy.")
				} else {
					cmd.Println("Unhealthy.")
				}
			}
			if !output.Healthy {
				return Internalf("doctor found %d failing check(s)", failures)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func (r *runner) validateCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "validate [file]",
		Short: "Validate a configuration",
		Long:  "Validate a configuration file, or validate the daemon's current configuration when no file is given.",
		Args:  usageArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			output := validateOutput{Valid: true, Errors: []string{}}
			var validationErr error

			if len(args) == 1 {
				output.Source = "file"
				output.Configured = true
				data, err := readConfigInput(cmd, args[0])
				if err != nil {
					output.Valid = false
					output.Errors = []string{err.Error()}
					return reportValidation(cmd, output, jsonOutput, err)
				}
				if _, err := config.Parse(data); err != nil {
					output.Valid = false
					output.Errors = []string{err.Error()}
					validationErr = Usagef("invalid configuration: %v", err)
				}
			} else {
				output.Source = "daemon"
				client, closeFn, err := r.client(cmd)
				if err != nil {
					return err
				}
				defer closeFn()

				cfg, revision, err := getConfig(cmd.Context(), client)
				if err != nil {
					return err
				}
				output.Configured = cfg != nil
				output.Revision = revision
				if cfg != nil {
					if err := cfg.Validate(); err != nil {
						output.Valid = false
						output.Errors = []string{err.Error()}
						validationErr = Usagef("invalid configuration: %v", err)
					}
				}
			}

			return reportValidation(cmd, output, jsonOutput, validationErr)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func reportValidation(cmd *cobra.Command, output validateOutput, jsonOutput bool, validationErr error) error {
	if jsonOutput {
		if err := printJSON(cmd, output); err != nil {
			return err
		}
		if validationErr != nil {
			return validationErr
		}
		return nil
	}
	if output.Valid {
		if output.Configured {
			cmd.Println("Configuration is valid.")
		} else {
			cmd.Println("No configuration is configured; nothing to validate.")
		}
		return nil
	}
	for _, message := range output.Errors {
		cmd.Printf("Invalid: %s\n", message)
	}
	if validationErr != nil {
		return validationErr
	}
	return Usagef("configuration is invalid")
}

func (r *runner) rollbackCmd() *cobra.Command {
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "rollback <revision>",
		Short: "Restore a previous configuration revision",
		Long: "Restore a historical configuration as a new revision.\n\n" +
			"The command asks for confirmation unless --yes is given.",
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil || target == 0 {
				return Usagef("invalid revision %q; use a positive integer", args[0])
			}

			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			ctx := cmd.Context()
			_, current, err := getConfig(ctx, client)
			if err != nil {
				return err
			}
			if target == current {
				return Usagef("revision %d is already current", target)
			}
			if err := confirm(cmd, fmt.Sprintf("Roll back configuration to revision %d? The current revision %d is kept in history.", target, current), assumeYes); err != nil {
				return err
			}

			resp, err := client.RollbackConfig(ctx, &proto.RollbackSplitTunnelConfigRequest{
				ApiVersion:       api.APIVersion,
				ExpectedRevision: current,
				Revision:         target,
			})
			if err != nil {
				return Classify(err)
			}
			cmd.Printf("Configuration rolled back to revision %d; new revision is %d.\n", target, resp.GetRevision())
			return nil
		},
	}
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "apply the change without an interactive confirmation")
	return cmd
}

func (r *runner) resetCmd() *cobra.Command {
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset split tunneling to an empty configuration",
		Long: "Replace the configuration with an empty standard-mode configuration.\n\n" +
			"Reset is destructive and asks for confirmation unless --yes is given.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			ctx := cmd.Context()
			_, revision, err := getConfig(ctx, client)
			if err != nil {
				return err
			}
			if err := confirm(cmd, "Reset split tunneling and remove all rules? This cannot be undone from the CLI.", assumeYes); err != nil {
				return err
			}
			newRevision, err := setConfig(ctx, client, emptyConfig(), revision)
			if err != nil {
				return err
			}
			cmd.Printf("Split tunneling reset at revision %d.\n", newRevision)
			return nil
		},
	}
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "apply the change without an interactive confirmation")
	return cmd
}
