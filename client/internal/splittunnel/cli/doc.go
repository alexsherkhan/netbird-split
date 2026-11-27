// Package cli implements the `netbird split` command tree.
//
// Every command talks to the daemon's SplitTunnelService over the local IPC
// connection. The package never writes configuration files, kernel state,
// nftables rules, routes or DNS records itself: mutations are expressed as a
// new configuration revision and sent with SetConfig or RollbackConfig.
//
// Read-only commands support --json. The JSON documents have stable field
// names, documented on the output types in output.go:
//
//	status          apiVersion, revision, enabled, running, mode, backend,
//	                processes, diagnostics, redactedFields
//	capabilities    clientApiVersion, serverApiVersion, modes, actions,
//	                conditionTypes, features
//	mode            mode, defaultAction, enabled, revision
//	app list        applications, redactedFields
//	domain list     revision, domains
//	cidr list       revision, cidrs
//	ip list         revision, ips
//	profile list    profiles
//	trace           apiVersion, finalAction, stages, redacted, redactedFields
//	stats           available, revision, enabled, running, mode, processes,
//	                rules, conflicts, countersAvailable
//	dns-cache       available, entries, message
//	doctor          healthy, checks
//	validate        valid, source, configured, revision, errors
//
// Exit codes are defined in exit.go and are part of the command contract.
package cli
