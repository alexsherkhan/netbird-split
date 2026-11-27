package cli

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

// DialFunc opens a connection to the daemon and returns a SplitTunnelService
// client plus a closer for the connection.
type DialFunc func(context.Context) (proto.SplitTunnelServiceClient, io.Closer, error)

// Options configures the split tunnel command tree.
type Options struct {
	// Dial opens the daemon IPC connection. It is required.
	Dial DialFunc
}

type runner struct {
	opts Options
}

func (r *runner) client(cmd *cobra.Command) (proto.SplitTunnelServiceClient, func(), error) {
	if r.opts.Dial == nil {
		return nil, nil, Internalf("split tunnel daemon dialer is not configured")
	}
	client, closer, err := r.opts.Dial(cmd.Context())
	if err != nil {
		return nil, nil, Classify(err)
	}
	closeFn := func() {
		if closer != nil {
			_ = closer.Close()
		}
	}
	return client, closeFn, nil
}

func getConfig(ctx context.Context, client proto.SplitTunnelServiceClient) (*config.Config, uint64, error) {
	resp, err := client.GetConfig(ctx, &proto.GetSplitTunnelConfigRequest{ApiVersion: api.APIVersion})
	if err != nil {
		return nil, 0, Classify(err)
	}
	if resp.GetConfig() == nil {
		if resp.GetRevision() == 0 {
			return nil, 0, nil
		}
		return nil, 0, Internalf("daemon returned revision %d without a configuration", resp.GetRevision())
	}
	cfg, err := configFromProto(resp.GetConfig())
	if err != nil {
		return nil, 0, Internalf("daemon returned an invalid configuration: %v", err)
	}
	return cfg, resp.GetRevision(), nil
}

func setConfig(ctx context.Context, client proto.SplitTunnelServiceClient, cfg *config.Config, expectedRevision uint64) (uint64, error) {
	if err := cfg.Validate(); err != nil {
		return 0, Usagef("configuration is invalid: %v", err)
	}
	resp, err := client.SetConfig(ctx, &proto.SetSplitTunnelConfigRequest{
		ApiVersion:       api.APIVersion,
		ExpectedRevision: expectedRevision,
		Config:           configToProto(cfg),
	})
	if err != nil {
		return 0, Classify(err)
	}
	return resp.GetRevision(), nil
}

func (r *runner) mutateConfig(cmd *cobra.Command, mutate func(*config.Config) error) (*config.Config, uint64, error) {
	client, closeFn, err := r.client(cmd)
	if err != nil {
		return nil, 0, err
	}
	defer closeFn()

	ctx := cmd.Context()
	cfg, revision, err := getConfig(ctx, client)
	if err != nil {
		return nil, 0, err
	}
	if cfg == nil {
		return nil, 0, Usagef("no split tunnel configuration exists yet; set a mode first with \"netbird split mode include\", \"exclude\" or \"custom\"")
	}
	if err := mutate(cfg); err != nil {
		if errors.Is(err, errNoChange) {
			return cfg, revision, nil
		}
		return nil, 0, err
	}
	newRevision, err := setConfig(ctx, client, cfg, revision)
	if err != nil {
		return nil, 0, err
	}
	return cfg, newRevision, nil
}

func emptyConfig() *config.Config {
	return &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Mode: config.ModeStandard,
		},
	}
}

func parseAction(value string) (config.Action, error) {
	action := config.Action(strings.ToLower(strings.TrimSpace(value)))
	switch action {
	case config.ActionVPN, config.ActionDirect, config.ActionBlock, config.ActionExitNode, config.ActionDefault:
		return action, nil
	}
	return "", Usagef("invalid --via value %q; use vpn, direct, block, exit_node or default", value)
}

func confirm(cmd *cobra.Command, prompt string, assumeYes bool) error {
	if assumeYes {
		return nil
	}

	cmd.Printf("%s [y/N]: ", prompt)
	reader := bufio.NewReader(cmd.InOrStdin())
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return Internalf("read confirmation: %v", err)
	}

	answer := strings.ToLower(strings.TrimSpace(line))
	if answer == "y" || answer == "yes" {
		return nil
	}
	return Internalf("aborted by user; no changes were applied")
}

func normalizeStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func normalizeMap(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	return values
}
