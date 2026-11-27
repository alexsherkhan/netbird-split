package cli

import (
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

func (r *runner) configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Read or replace the split tunnel configuration",
	}
	cmd.AddCommand(r.configGetCmd())
	cmd.AddCommand(r.configSetCmd())
	return cmd
}

func (r *runner) configGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Print the current configuration as canonical JSON",
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

func (r *runner) configSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <file>",
		Short: "Validate and apply a configuration file",
		Long: "Validate a configuration document and apply it as a new revision. " +
			"Use \"-\" to read stdin.",
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readConfigInput(cmd, args[0])
			if err != nil {
				return err
			}
			cfg, err := config.Parse(data)
			if err != nil {
				return Usagef("invalid configuration: %v", err)
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
			cmd.Printf("Configuration applied at revision %d.\n", newRevision)
			return nil
		},
	}
}
