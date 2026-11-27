package cli

import (
	"errors"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

var errNoChange = errors.New("no change")

// NewCommand returns the `netbird split` command tree.
func NewCommand(opts Options) *cobra.Command {
	r := &runner{opts: opts}

	root := &cobra.Command{
		Use:           "split",
		Short:         "Manage split tunneling",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: "Manage split tunneling through the daemon's local gRPC API.\n\n" +
			"Mutations replace the daemon configuration with a new revision; the CLI never writes " +
			"configuration files, kernel state, firewall rules, routes or DNS records directly.\n\n" +
			"Read-only commands accept --json. Exit codes:\n" +
			"  0  success\n" +
			"  1  internal failure or a cancelled confirmation\n" +
			"  2  usage or configuration error\n" +
			"  3  unauthenticated or denied\n" +
			"  4  daemon or split tunnel service unavailable\n" +
			"  5  configuration revision conflict",
	}

	root.AddCommand(r.enableCmd())
	root.AddCommand(r.disableCmd())
	root.AddCommand(r.statusCmd())
	root.AddCommand(r.capabilitiesCmd())
	root.AddCommand(r.modeCmd())
	root.AddCommand(r.appCmd())
	root.AddCommand(r.domainCmd())
	root.AddCommand(r.ipCmd())
	root.AddCommand(r.cidrCmd())
	root.AddCommand(r.profileCmd())
	root.AddCommand(r.exportCmd())
	root.AddCommand(r.importCmd())
	root.AddCommand(r.traceCmd())
	root.AddCommand(r.dnsCacheCmd())
	root.AddCommand(r.statsCmd())
	root.AddCommand(r.doctorCmd())
	root.AddCommand(r.validateCmd())
	root.AddCommand(r.rollbackCmd())
	root.AddCommand(r.resetCmd())

	return root
}

func (r *runner) enableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable",
		Short: "Enable split tunneling",
		Long:  "Enable split tunneling using the daemon's current configuration.",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			alreadyEnabled := false
			cfg, revision, err := r.mutateConfig(cmd, func(cfg *config.Config) error {
				if cfg.SplitTunnel.Enabled {
					alreadyEnabled = true
					return errNoChange
				}
				if cfg.SplitTunnel.Mode == config.ModeStandard {
					return Usagef("standard mode does not run the split tunnel engine; set a mode first with \"netbird split mode include\", \"exclude\" or \"custom\"")
				}
				cfg.SplitTunnel.Enabled = true
				return nil
			})
			if err != nil {
				return err
			}
			if alreadyEnabled {
				cmd.Println("Split tunneling is already enabled.")
				return nil
			}
			cmd.Printf("Split tunneling enabled at revision %d in %s mode.\n", revision, cfg.SplitTunnel.Mode)
			return nil
		},
	}
}

func (r *runner) disableCmd() *cobra.Command {
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable split tunneling",
		Long: "Disable split tunneling.\n\n" +
			"Disabling stops the split tunnel engine. When a kill switch is configured this can remove " +
			"protection, so the command asks for confirmation unless --yes is given.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			ctx := cmd.Context()
			cfg, revision, err := getConfig(ctx, client)
			if err != nil {
				return err
			}
			if cfg == nil || !cfg.SplitTunnel.Enabled {
				cmd.Println("Split tunneling is already disabled.")
				return nil
			}

			prompt := "Disabling split tunneling stops routing and may leave kill switch protection inactive. Continue?"
			if cfg.SplitTunnel.KillSwitch == "" || cfg.SplitTunnel.KillSwitch == config.KillSwitchDisabled {
				prompt = "Disabling split tunneling stops routing and restores the direct connection. Continue?"
			}
			if err := confirm(cmd, prompt, assumeYes); err != nil {
				return err
			}

			cfg.SplitTunnel.Enabled = false
			revision, err = setConfig(ctx, client, cfg, revision)
			if err != nil {
				return err
			}
			cmd.Printf("Split tunneling disabled at revision %d.\n", revision)
			return nil
		},
	}
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "apply the change without an interactive confirmation")
	return cmd
}

func (r *runner) statusCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show split tunneling status",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			resp, err := client.GetStatus(cmd.Context(), &proto.GetSplitTunnelStatusRequest{ApiVersion: api.APIVersion})
			if err != nil {
				return Classify(err)
			}

			output := statusOutput{
				APIVersion:     resp.GetApiVersion(),
				Revision:       resp.GetRevision(),
				Enabled:        resp.GetEnabled(),
				Running:        resp.GetRunning(),
				Mode:           resp.GetMode(),
				Backend:        resp.GetBackend(),
				Processes:      []processOutput{},
				Diagnostics:    normalizeMap(resp.GetDiagnostics()),
				RedactedFields: normalizeStrings(resp.GetRedactedFields()),
			}
			for _, process := range resp.GetProcesses() {
				if process == nil {
					continue
				}
				output.Processes = append(output.Processes, processOutput{
					PID:        process.GetPid(),
					DesktopID:  process.GetDesktopId(),
					Name:       process.GetName(),
					Executable: process.GetExecutable(),
					UID:        process.GetUid(),
					Cgroup:     process.GetCgroup(),
				})
			}
			if jsonOutput {
				return printJSON(cmd, output)
			}

			cmd.Printf("Enabled: %t\n", output.Enabled)
			cmd.Printf("Running: %t\n", output.Running)
			cmd.Printf("Mode: %s\n", output.Mode)
			cmd.Printf("Backend: %s\n", output.Backend)
			cmd.Printf("Revision: %d\n", output.Revision)
			cmd.Printf("Processes: %d\n", len(output.Processes))
			waiting := make([]string, 0, len(output.Diagnostics))
			for key := range output.Diagnostics {
				waiting = append(waiting, key)
			}
			sort.Strings(waiting)
			for _, key := range waiting {
				cmd.Printf("%s: %s\n", key, output.Diagnostics[key])
			}
			if len(output.RedactedFields) > 0 {
				sort.Strings(output.RedactedFields)
				cmd.Printf("Redacted: %s\n", strings.Join(output.RedactedFields, ", "))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func (r *runner) capabilitiesCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "capabilities",
		Short: "Show supported split tunnel capabilities",
		Long:  "Show the split tunnel API version and the modes, actions, condition types and features this client supports.",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			resp, err := client.GetStatus(cmd.Context(), &proto.GetSplitTunnelStatusRequest{ApiVersion: api.APIVersion})
			if err != nil {
				return Classify(err)
			}

			output := capabilitiesOutput{
				ClientAPIVersion: api.APIVersion,
				ServerAPIVersion: resp.GetApiVersion(),
				Modes: []string{
					string(config.ModeStandard),
					string(config.ModeInclude),
					string(config.ModeExclude),
					string(config.ModeCustom),
				},
				Actions: []string{
					string(config.ActionVPN),
					string(config.ActionDirect),
					string(config.ActionBlock),
					string(config.ActionExitNode),
					string(config.ActionDefault),
				},
				ConditionTypes: []string{
					string(config.ConditionDesktopID),
					string(config.ConditionExecutable),
					string(config.ConditionFlatpakID),
					string(config.ConditionSnapID),
					string(config.ConditionDomain),
					string(config.ConditionWildcardDomain),
					string(config.ConditionCIDR),
					string(config.ConditionProtocolPort),
					string(config.ConditionUID),
					string(config.ConditionAll),
					string(config.ConditionAny),
				},
				Features: capabilityFeatures{
					Revisions:            true,
					Rollback:             true,
					Events:               true,
					Trace:                true,
					ApplicationDiscovery: true,
					ConfigExport:         true,
					ConfigImport:         true,
					JSONOutput:           true,
				},
			}
			if jsonOutput {
				return printJSON(cmd, output)
			}

			cmd.Printf("Client API version: %d\n", output.ClientAPIVersion)
			cmd.Printf("Server API version: %d\n", output.ServerAPIVersion)
			cmd.Printf("Modes: %s\n", strings.Join(output.Modes, ", "))
			cmd.Printf("Actions: %s\n", strings.Join(output.Actions, ", "))
			cmd.Printf("Condition types: %s\n", strings.Join(output.ConditionTypes, ", "))
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text")
	return cmd
}

func (r *runner) modeCmd() *cobra.Command {
	var jsonOutput bool
	var defaultAction string
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "mode [standard|include|exclude|custom]",
		Short: "Show or change the split tunneling mode",
		Long: "Show the current split tunneling mode, or change it.\n\n" +
			"Changing to standard mode disables split tunneling and is confirmed interactively unless --yes is given.",
		Args: usageArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return r.showMode(cmd, jsonOutput)
			}

			mode, err := parseMode(args[0])
			if err != nil {
				return err
			}

			client, closeFn, err := r.client(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			ctx := cmd.Context()
			cfg, revision, err := getConfig(ctx, client)
			if err != nil {
				return err
			}
			if cfg == nil {
				cfg = emptyConfig()
			}
			if mode == config.ModeStandard && cfg.SplitTunnel.Enabled {
				if err := confirm(cmd, "Standard mode disables split tunneling and may remove kill switch protection. Continue?", assumeYes); err != nil {
					return err
				}
			}

			if err := applyMode(cfg, mode, defaultAction); err != nil {
				return err
			}
			revision, err = setConfig(ctx, client, cfg, revision)
			if err != nil {
				return err
			}
			cmd.Printf("Split tunneling mode set to %s at revision %d.\n", mode, revision)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print stable JSON instead of text when reading the mode")
	cmd.Flags().StringVar(&defaultAction, "default-action", "", "default action for custom mode: vpn, direct or block")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "apply the change without an interactive confirmation")
	return cmd
}

func (r *runner) showMode(cmd *cobra.Command, jsonOutput bool) error {
	client, closeFn, err := r.client(cmd)
	if err != nil {
		return err
	}
	defer closeFn()

	cfg, revision, err := getConfig(cmd.Context(), client)
	if err != nil {
		return err
	}
	output := modeOutput{Revision: revision}
	if cfg != nil {
		output.Mode = string(cfg.SplitTunnel.Mode)
		output.DefaultAction = string(cfg.SplitTunnel.DefaultAction)
		output.Enabled = cfg.SplitTunnel.Enabled
	} else {
		output.Mode = string(config.ModeStandard)
	}

	if jsonOutput {
		return printJSON(cmd, output)
	}
	cmd.Printf("Mode: %s\n", output.Mode)
	if output.DefaultAction != "" {
		cmd.Printf("Default action: %s\n", output.DefaultAction)
	}
	cmd.Printf("Enabled: %t\n", output.Enabled)
	cmd.Printf("Revision: %d\n", output.Revision)
	return nil
}

func parseMode(value string) (config.Mode, error) {
	mode := config.Mode(strings.ToLower(strings.TrimSpace(value)))
	switch mode {
	case config.ModeStandard, config.ModeInclude, config.ModeExclude, config.ModeCustom:
		return mode, nil
	}
	return "", Usagef("invalid mode %q; use standard, include, exclude or custom", value)
}

func applyMode(cfg *config.Config, mode config.Mode, defaultAction string) error {
	cfg.SplitTunnel.Mode = mode
	switch mode {
	case config.ModeStandard:
		cfg.SplitTunnel.Enabled = false
		cfg.SplitTunnel.DefaultAction = ""
	case config.ModeInclude:
		cfg.SplitTunnel.DefaultAction = config.ActionDirect
	case config.ModeExclude:
		cfg.SplitTunnel.DefaultAction = config.ActionVPN
	case config.ModeCustom:
		if defaultAction != "" {
			action := config.Action(strings.ToLower(strings.TrimSpace(defaultAction)))
			switch action {
			case config.ActionVPN, config.ActionDirect, config.ActionBlock:
				cfg.SplitTunnel.DefaultAction = action
			default:
				return Usagef("invalid --default-action %q; use vpn, direct or block", defaultAction)
			}
		}
		if !validCustomDefault(cfg.SplitTunnel.DefaultAction) {
			return Usagef("custom mode requires --default-action vpn, direct or block")
		}
	}
	return nil
}

func validCustomDefault(action config.Action) bool {
	switch action {
	case config.ActionVPN, config.ActionDirect, config.ActionBlock:
		return true
	}
	return false
}

func usageArgs(validate cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := validate(cmd, args); err != nil {
			return Usagef("%v", err)
		}
		return nil
	}
}
