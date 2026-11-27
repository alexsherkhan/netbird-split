package main

import (
	"os"

	"github.com/netbirdio/netbird/client/cmd"
	spcli "github.com/netbirdio/netbird/client/internal/splittunnel/cli"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(spcli.ExitCode(err))
	}
}
