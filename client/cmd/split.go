package cmd

import (
	"context"
	"errors"
	"io"

	"github.com/spf13/cobra"

	spcli "github.com/netbirdio/netbird/client/internal/splittunnel/cli"
	"github.com/netbirdio/netbird/client/proto"
)

var splitCmd = spcli.NewCommand(spcli.Options{Dial: dialSplitTunnel})

func dialSplitTunnel(ctx context.Context) (proto.SplitTunnelServiceClient, io.Closer, error) {
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		if errors.Is(err, errDaemonAccessDenied) {
			return nil, nil, spcli.Deniedf("%v", err)
		}
		return nil, nil, spcli.Unavailablef("connect to daemon: %v", err)
	}
	return proto.NewSplitTunnelServiceClient(conn), conn, nil
}

func isSplitCommand(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Name() == "split" {
			return true
		}
	}
	return false
}
