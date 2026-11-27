package cli

import (
	"encoding/json"
	"io"

	"github.com/spf13/cobra"
)

// statusOutput is the stable JSON document for `split status`.
type statusOutput struct {
	APIVersion     uint32            `json:"apiVersion"`
	Revision       uint64            `json:"revision"`
	Enabled        bool              `json:"enabled"`
	Running        bool              `json:"running"`
	Mode           string            `json:"mode"`
	Backend        string            `json:"backend"`
	Processes      []processOutput   `json:"processes"`
	Diagnostics    map[string]string `json:"diagnostics"`
	RedactedFields []string          `json:"redactedFields"`
}

type processOutput struct {
	PID        int32  `json:"pid"`
	DesktopID  string `json:"desktopId"`
	Name       string `json:"name"`
	Executable string `json:"executable"`
	UID        uint32 `json:"uid"`
	Cgroup     string `json:"cgroup"`
}

// capabilitiesOutput is the stable JSON document for `split capabilities`.
type capabilitiesOutput struct {
	ClientAPIVersion uint32             `json:"clientApiVersion"`
	ServerAPIVersion uint32             `json:"serverApiVersion"`
	Modes            []string           `json:"modes"`
	Actions          []string           `json:"actions"`
	ConditionTypes   []string           `json:"conditionTypes"`
	Features         capabilityFeatures `json:"features"`
}

type capabilityFeatures struct {
	Revisions            bool `json:"revisions"`
	Rollback             bool `json:"rollback"`
	Events               bool `json:"events"`
	Trace                bool `json:"trace"`
	ApplicationDiscovery bool `json:"applicationDiscovery"`
	ConfigExport         bool `json:"configExport"`
	ConfigImport         bool `json:"configImport"`
	JSONOutput           bool `json:"jsonOutput"`
}

// modeOutput is the stable JSON document for reading `split mode`.
type modeOutput struct {
	Mode          string `json:"mode"`
	DefaultAction string `json:"defaultAction"`
	Enabled       bool   `json:"enabled"`
	Revision      uint64 `json:"revision"`
}

// applicationsOutput is the stable JSON document for `split app list`.
type applicationsOutput struct {
	Applications   []applicationOutput `json:"applications"`
	RedactedFields []string            `json:"redactedFields"`
}

type applicationOutput struct {
	DesktopID   string `json:"desktopId"`
	Name        string `json:"name"`
	IconName    string `json:"iconName"`
	IconPath    string `json:"iconPath"`
	Executable  string `json:"executable"`
	InstallType string `json:"installType"`
	SourcePath  string `json:"sourcePath"`
	NoDisplay   bool   `json:"noDisplay"`
	Unknown     bool   `json:"unknown"`
}

// domainListOutput is the stable JSON document for `split domain list`.
type domainListOutput struct {
	Revision uint64         `json:"revision"`
	Domains  []domainOutput `json:"domains"`
}

type domainOutput struct {
	RuleID   string `json:"ruleId"`
	RuleName string `json:"ruleName"`
	Pattern  string `json:"pattern"`
	Type     string `json:"type"`
	Action   string `json:"action"`
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"`
}

// cidrListOutput is the stable JSON document for `split cidr list`.
type cidrListOutput struct {
	Revision uint64       `json:"revision"`
	CIDRs    []cidrOutput `json:"cidrs"`
}

type cidrOutput struct {
	RuleID   string `json:"ruleId"`
	RuleName string `json:"ruleName"`
	Prefix   string `json:"prefix"`
	Action   string `json:"action"`
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"`
}

// ipListOutput is the stable JSON document for `split ip list`.
type ipListOutput struct {
	Revision uint64     `json:"revision"`
	IPs      []ipOutput `json:"ips"`
}

type ipOutput struct {
	RuleID   string `json:"ruleId"`
	RuleName string `json:"ruleName"`
	Address  string `json:"address"`
	Action   string `json:"action"`
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"`
}

// profileListOutput is the stable JSON document for `split profile list`.
type profileListOutput struct {
	Profiles []profileOutput `json:"profiles"`
}

type profileOutput struct {
	Name     string `json:"name"`
	Active   bool   `json:"active"`
	Revision uint64 `json:"revision"`
	Mode     string `json:"mode"`
}

// traceOutput is the stable JSON document for `split trace`.
type traceOutput struct {
	APIVersion     uint32        `json:"apiVersion"`
	FinalAction    string        `json:"finalAction"`
	Stages         []stageOutput `json:"stages"`
	Redacted       bool          `json:"redacted"`
	RedactedFields []string      `json:"redactedFields"`
}

type stageOutput struct {
	Name              string `json:"name"`
	Message           string `json:"message"`
	Allowed           bool   `json:"allowed"`
	ForwardingDetails string `json:"forwardingDetails"`
}

// statsOutput is the stable JSON document for `split stats`.
type statsOutput struct {
	Available         bool   `json:"available"`
	Revision          uint64 `json:"revision"`
	Enabled           bool   `json:"enabled"`
	Running           bool   `json:"running"`
	Mode              string `json:"mode"`
	Processes         int    `json:"processes"`
	Rules             int    `json:"rules"`
	Conflicts         int    `json:"conflicts"`
	CountersAvailable bool   `json:"countersAvailable"`
}

// dnsCacheOutput is the stable JSON document for `split dns-cache`.
type dnsCacheOutput struct {
	Available bool     `json:"available"`
	Entries   []string `json:"entries"`
	Message   string   `json:"message"`
}

// doctorOutput is the stable JSON document for `split doctor`.
type doctorOutput struct {
	Healthy bool          `json:"healthy"`
	Checks  []checkOutput `json:"checks"`
}

type checkOutput struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// validateOutput is the stable JSON document for `split validate`.
type validateOutput struct {
	Valid      bool     `json:"valid"`
	Source     string   `json:"source"`
	Configured bool     `json:"configured"`
	Revision   uint64   `json:"revision"`
	Errors     []string `json:"errors"`
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func printJSON(cmd *cobra.Command, value any) error {
	if err := writeJSON(cmd.OutOrStdout(), value); err != nil {
		return Internalf("encode json output: %v", err)
	}
	return nil
}
