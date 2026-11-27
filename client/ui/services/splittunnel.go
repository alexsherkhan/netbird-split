//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

// SplitTunnelConn returns a split tunnel client sharing the daemon channel.
type SplitTunnelConn interface {
	SplitTunnelClient() (proto.SplitTunnelServiceClient, error)
}

// SplitTunnelProcess is one process attributed to the split tunnel engine.
type SplitTunnelProcess struct {
	PID        int32  `json:"pid"`
	DesktopID  string `json:"desktopId"`
	Name       string `json:"name"`
	Executable string `json:"executable"`
	UID        uint32 `json:"uid"`
	Cgroup     string `json:"cgroup"`
}

// SplitTunnelDegradedCheck names one reason the engine is not fully healthy.
// Code is stable so the frontend can localise the headline; Detail carries the
// daemon's own wording when diagnostics are available to this caller.
type SplitTunnelDegradedCheck struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// SplitTunnelStatus is the engine status presented to the frontend. Diagnostics
// and process identity fields are omitted by the daemon for unprivileged
// callers; DiagnosticsRedacted records that so the UI can explain the gap
// instead of treating an empty map as healthy.
type SplitTunnelStatus struct {
	APIVersion          uint32                     `json:"apiVersion"`
	Revision            uint64                     `json:"revision"`
	Enabled             bool                       `json:"enabled"`
	Running             bool                       `json:"running"`
	Mode                string                     `json:"mode"`
	Backend             string                     `json:"backend"`
	Processes           []SplitTunnelProcess       `json:"processes"`
	Diagnostics         map[string]string          `json:"diagnostics,omitempty"`
	DiagnosticsRedacted bool                       `json:"diagnosticsRedacted"`
	RedactedFields      []string                   `json:"redactedFields,omitempty"`
	Degraded            bool                       `json:"degraded"`
	DegradedChecks      []SplitTunnelDegradedCheck `json:"degradedChecks"`
	// RestartRequired reports that the configuration enables the engine while
	// the engine reports it is not running. The daemon exposes no dedicated
	// restart flag, so this is derived from enabled and running.
	RestartRequired bool `json:"restartRequired"`
}

// SplitTunnelRule is one rule as the editor sees it. Conditions are included so
// the editor can round-trip a rule without a second read. Supported is false for
// a rule carrying a construct this build does not understand; such a rule is
// preserved untouched on write and cannot be edited.
type SplitTunnelRule struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Enabled           bool                   `json:"enabled"`
	Priority          int32                  `json:"priority"`
	MatchMode         string                 `json:"matchMode"`
	Action            string                 `json:"action"`
	ExitNodeID        string                 `json:"exitNodeId"`
	Description       string                 `json:"description"`
	ConditionCount    int                    `json:"conditionCount"`
	Conditions        []SplitTunnelCondition `json:"conditions"`
	Supported         bool                   `json:"supported"`
	UnsupportedReason string                 `json:"unsupportedReason"`
}

// SplitTunnelExitNodeRule is one rule that routes traffic through an exit node.
// M14 can change its selected exit node without exposing the rest of the rule.
type SplitTunnelExitNodeRule struct {
	RuleID     string `json:"ruleId"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Priority   int32  `json:"priority"`
	ExitNodeID string `json:"exitNodeId"`
}

// SplitTunnelConfig is the configuration subset the split tunnel screen uses.
type SplitTunnelConfig struct {
	Exists        bool                      `json:"exists"`
	Revision      uint64                    `json:"revision"`
	SchemaVersion uint32                    `json:"schemaVersion"`
	Enabled       bool                      `json:"enabled"`
	Mode          string                    `json:"mode"`
	DefaultAction string                    `json:"defaultAction"`
	KillSwitch    string                    `json:"killSwitch"`
	IPv6          bool                      `json:"ipv6"`
	RuleCount     int                       `json:"ruleCount"`
	Rules         []SplitTunnelRule         `json:"rules"`
	ExitNodeRules []SplitTunnelExitNodeRule `json:"exitNodeRules"`
}

// SplitTunnelExitNodeSelection changes the exit node used by one existing
// exit_node rule.
type SplitTunnelExitNodeSelection struct {
	RuleID     string `json:"ruleId"`
	ExitNodeID string `json:"exitNodeId"`
}

// SplitTunnelApplyParams carries the complete settings the screen can change.
// The expected revision makes a concurrent daemon change a visible conflict
// rather than an overwrite.
type SplitTunnelApplyParams struct {
	ExpectedRevision uint64                         `json:"expectedRevision"`
	Enabled          bool                           `json:"enabled"`
	Mode             string                         `json:"mode"`
	DefaultAction    string                         `json:"defaultAction"`
	KillSwitch       string                         `json:"killSwitch"`
	ExitNodes        []SplitTunnelExitNodeSelection `json:"exitNodes"`
	// RulesChanged replaces every supported rule with Rules. Rules this build
	// does not understand, and rules omitted while RulesChanged is false, are
	// preserved unchanged.
	RulesChanged bool                   `json:"rulesChanged"`
	Rules        []SplitTunnelRuleInput `json:"rules"`
}

// SplitTunnelRevision is the revision produced by a successful apply.
type SplitTunnelRevision struct {
	Revision uint64 `json:"revision"`
}

// SplitTunnel exposes the daemon's split tunnel control plane to the UI. Every
// read and write crosses the daemon IPC boundary; the GUI never touches kernel
// networking, configuration files or firewall state itself.
type SplitTunnel struct {
	conn       SplitTunnelConn
	classifier errorClassifier
}

// NewSplitTunnel wires a SplitTunnel service. translator or prefs may be nil, in
// which case errors fall back to the bare code key.
func NewSplitTunnel(conn SplitTunnelConn, translator ErrorTranslator, prefs LanguagePreference) *SplitTunnel {
	return &SplitTunnel{conn: conn, classifier: errorClassifier{translator: translator, prefs: prefs}}
}

// GetStatus returns the engine status.
func (s *SplitTunnel) GetStatus(ctx context.Context) (SplitTunnelStatus, error) {
	cli, err := s.conn.SplitTunnelClient()
	if err != nil {
		return SplitTunnelStatus{}, s.classify(err)
	}
	resp, err := cli.GetStatus(ctx, &proto.GetSplitTunnelStatusRequest{ApiVersion: api.APIVersion})
	if err != nil {
		return SplitTunnelStatus{}, s.classify(err)
	}
	return splitTunnelStatusFromProto(resp), nil
}

// GetConfig returns the configuration and its revision. Exists is false when
// the daemon has no configuration yet, which is a normal first-run state.
func (s *SplitTunnel) GetConfig(ctx context.Context) (SplitTunnelConfig, error) {
	cli, err := s.conn.SplitTunnelClient()
	if err != nil {
		return SplitTunnelConfig{}, s.classify(err)
	}
	resp, err := cli.GetConfig(ctx, &proto.GetSplitTunnelConfigRequest{ApiVersion: api.APIVersion})
	if err != nil {
		return SplitTunnelConfig{}, s.classify(err)
	}
	if resp.GetConfig() == nil && resp.GetRevision() != 0 {
		return SplitTunnelConfig{}, s.localError("split_tunnel_invalid_response",
			fmt.Sprintf("daemon returned revision %d without a configuration", resp.GetRevision()))
	}
	return configFromProto(resp), nil
}

// Apply changes the settings exposed by the overview in one revision: the
// daemon reads, validates and applies the whole configuration or none of it.
// A stale expected revision is refused before any write is sent.
func (s *SplitTunnel) Apply(ctx context.Context, p SplitTunnelApplyParams) (SplitTunnelRevision, error) {
	cli, err := s.conn.SplitTunnelClient()
	if err != nil {
		return SplitTunnelRevision{}, s.classify(err)
	}

	resp, err := cli.GetConfig(ctx, &proto.GetSplitTunnelConfigRequest{ApiVersion: api.APIVersion})
	if err != nil {
		return SplitTunnelRevision{}, s.classify(err)
	}
	if resp.GetRevision() != p.ExpectedRevision {
		return SplitTunnelRevision{}, s.revisionConflict()
	}

	cfg := resp.GetConfig()
	if cfg == nil {
		cfg = &proto.SplitTunnelConfig{
			SchemaVersion: config.CurrentSchemaVersion,
			SplitTunnel: &proto.SplitTunnelSettings{
				Mode:       string(config.ModeStandard),
				KillSwitch: string(config.KillSwitchDisabled),
			},
		}
	}
	if cfg.SplitTunnel == nil {
		return SplitTunnelRevision{}, s.localError("split_tunnel_invalid_response",
			"daemon returned a configuration without split tunnel settings")
	}

	if err := s.applySettings(cfg, p); err != nil {
		return SplitTunnelRevision{}, err
	}

	setResp, err := cli.SetConfig(ctx, &proto.SetSplitTunnelConfigRequest{
		ApiVersion:       api.APIVersion,
		ExpectedRevision: p.ExpectedRevision,
		Config:           cfg,
	})
	if err != nil {
		return SplitTunnelRevision{}, s.classify(err)
	}
	if setResp.GetRevision() <= p.ExpectedRevision {
		return SplitTunnelRevision{}, s.localError("split_tunnel_revision_conflict",
			"the daemon did not advance the split tunnel configuration revision")
	}
	return SplitTunnelRevision{Revision: setResp.GetRevision()}, nil
}

// applySettings mutates the daemon configuration for the requested change. It
// works on the configuration the daemon just returned so rules the overview
// does not show survive the write unchanged.
func (s *SplitTunnel) applySettings(cfg *proto.SplitTunnelConfig, p SplitTunnelApplyParams) error {
	settings := cfg.SplitTunnel
	mode, err := s.normalizedMode(settings.GetMode(), p.Mode)
	if err != nil {
		return err
	}
	if p.RulesChanged {
		if err := s.applyRules(settings, p.Rules); err != nil {
			return err
		}
	}

	switch mode {
	case config.ModeStandard:
		if p.Enabled {
			return s.localError("split_tunnel_mode_required",
				"choose include, exclude or custom mode before enabling split tunneling")
		}
		settings.Enabled = false
		settings.DefaultAction = ""
		// Standard mode does not evaluate rules, and the daemon rejects a
		// configuration that leaves any enabled. Disabling them here keeps a
		// mode switch valid without discarding the rules themselves.
		for _, rule := range settings.GetRules() {
			rule.Enabled = false
		}
	case config.ModeInclude:
		settings.Enabled = p.Enabled
		settings.DefaultAction = string(config.ActionDirect)
	case config.ModeExclude:
		settings.Enabled = p.Enabled
		settings.DefaultAction = string(config.ActionVPN)
	case config.ModeCustom:
		action, err := s.customDefaultAction(settings.GetDefaultAction(), p.DefaultAction)
		if err != nil {
			return err
		}
		settings.Enabled = p.Enabled
		settings.DefaultAction = action
	default:
		return s.localError("split_tunnel_invalid_mode", fmt.Sprintf("unsupported mode %q", mode))
	}
	settings.Mode = string(mode)

	killSwitch, err := s.normalizedKillSwitch(p.KillSwitch)
	if err != nil {
		return err
	}
	settings.KillSwitch = killSwitch

	return s.applyExitNodes(settings, p.ExitNodes)
}

func (s *SplitTunnel) normalizedMode(current, requested string) (config.Mode, error) {
	value := requested
	if strings.TrimSpace(value) == "" {
		value = current
	}
	mode := config.Mode(strings.ToLower(strings.TrimSpace(value)))
	switch mode {
	case config.ModeStandard, config.ModeInclude, config.ModeExclude, config.ModeCustom:
		return mode, nil
	}
	if strings.TrimSpace(value) == "" {
		return config.ModeStandard, nil
	}
	return "", s.localError("split_tunnel_invalid_mode", fmt.Sprintf("unsupported mode %q", requested))
}

func (s *SplitTunnel) customDefaultAction(current, requested string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(requested))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(current))
	}
	switch config.Action(value) {
	case config.ActionVPN, config.ActionDirect, config.ActionBlock:
		return value, nil
	}
	return "", s.localError("split_tunnel_invalid_default_action",
		fmt.Sprintf("custom mode needs a default action of vpn, direct or block, got %q", value))
}

func (s *SplitTunnel) normalizedKillSwitch(requested string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(requested))
	if value == "" {
		value = string(config.KillSwitchDisabled)
	}
	switch config.KillSwitchMode(value) {
	case config.KillSwitchDisabled, config.KillSwitchSelective,
		config.KillSwitchGlobal, config.KillSwitchStrict:
		return value, nil
	}
	return "", s.localError("split_tunnel_invalid_kill_switch",
		fmt.Sprintf("unsupported kill switch mode %q", requested))
}

func (s *SplitTunnel) applyExitNodes(settings *proto.SplitTunnelSettings, selections []SplitTunnelExitNodeSelection) error {
	for _, selection := range selections {
		exitNodeID := strings.TrimSpace(selection.ExitNodeID)
		if selection.RuleID == "" || exitNodeID == "" {
			return s.localError("split_tunnel_invalid_exit_node",
				"an exit node selection needs a rule and an exit node")
		}
		var matched *proto.SplitTunnelRule
		for _, rule := range settings.GetRules() {
			if rule.GetId() == selection.RuleID {
				matched = rule
				break
			}
		}
		if matched == nil {
			return s.localError("split_tunnel_rule_not_found",
				fmt.Sprintf("split tunnel rule %q no longer exists", selection.RuleID))
		}
		if matched.GetAction() != string(config.ActionExitNode) {
			return s.localError("split_tunnel_invalid_exit_node",
				fmt.Sprintf("split tunnel rule %q does not route through an exit node", selection.RuleID))
		}
		matched.ExitNodeId = exitNodeID
	}
	return nil
}

func splitTunnelStatusFromProto(resp *proto.GetSplitTunnelStatusResponse) SplitTunnelStatus {
	redacted := make(map[string]struct{}, len(resp.GetRedactedFields()))
	for _, field := range resp.GetRedactedFields() {
		redacted[field] = struct{}{}
	}

	out := SplitTunnelStatus{
		APIVersion:          resp.GetApiVersion(),
		Revision:            resp.GetRevision(),
		Enabled:             resp.GetEnabled(),
		Running:             resp.GetRunning(),
		Mode:                resp.GetMode(),
		Backend:             resp.GetBackend(),
		Processes:           make([]SplitTunnelProcess, 0, len(resp.GetProcesses())),
		Diagnostics:         cloneDiagnostics(resp.GetDiagnostics()),
		DiagnosticsRedacted: hasRedactedField(redacted, "diagnostics"),
		RedactedFields:      append([]string(nil), resp.GetRedactedFields()...),
	}
	for _, process := range resp.GetProcesses() {
		out.Processes = append(out.Processes, SplitTunnelProcess{
			PID:        process.GetPid(),
			DesktopID:  process.GetDesktopId(),
			Name:       process.GetName(),
			Executable: process.GetExecutable(),
			UID:        process.GetUid(),
			Cgroup:     process.GetCgroup(),
		})
	}
	out.DegradedChecks = degradedChecks(resp, out.DiagnosticsRedacted)
	out.Degraded = len(out.DegradedChecks) > 0
	out.RestartRequired = out.Enabled && !out.Running
	return out
}

func hasRedactedField(fields map[string]struct{}, name string) bool {
	_, ok := fields[name]
	return ok
}

func cloneDiagnostics(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// degradedChecks derives stable health signals from the daemon's diagnostics.
// An unprivileged caller receives no diagnostics, so only the fields that are
// still present can be judged; the redaction itself is reported separately.
func degradedChecks(resp *proto.GetSplitTunnelStatusResponse, diagnosticsRedacted bool) []SplitTunnelDegradedCheck {
	checks := make([]SplitTunnelDegradedCheck, 0, 8)
	add := func(code, detail string) {
		for _, check := range checks {
			if check.Code == code {
				return
			}
		}
		checks = append(checks, SplitTunnelDegradedCheck{Code: code, Detail: detail})
	}

	diagnostics := resp.GetDiagnostics()
	if resp.GetBackend() == "" {
		add("backend_unavailable", "")
	}
	if resp.GetEnabled() && !resp.GetRunning() {
		add("not_running", "")
	}
	if diagnosticsRedacted {
		return checks
	}

	switch diagnostics["backend.state"] {
	case "degraded":
		add("backend_degraded", diagnostics["backend.state"])
	case "failed", "closed", "uninitialized":
		add("backend_unavailable", diagnostics["backend.state"])
	}
	if diagnostics["backend.error"] != "" {
		add("backend_error", diagnostics["backend.error"])
	}
	if diagnostics["backend.last_error"] != "" {
		add("backend_error", diagnostics["backend.last_error"])
	}
	if diagnostics["config"] == "invalid" {
		add("config_invalid", diagnostics["config.error"])
	}
	if diagnostics["apply.error"] != "" {
		add("apply_failed", diagnostics["apply.error"])
	}
	if diagnostics["reconcile.error"] != "" {
		add("reconcile_failed", diagnostics["reconcile.error"])
	}
	if diagnostics["domain.conflicts"] != "" && diagnostics["domain.conflicts"] != "0" {
		add("domain_conflicts", diagnostics["domain.conflicts"])
	}
	return checks
}

func configFromProto(resp *proto.GetSplitTunnelConfigResponse) SplitTunnelConfig {
	out := SplitTunnelConfig{
		Exists:        resp.GetConfig() != nil,
		Revision:      resp.GetRevision(),
		Rules:         []SplitTunnelRule{},
		ExitNodeRules: []SplitTunnelExitNodeRule{},
	}
	cfg := resp.GetConfig()
	if cfg == nil {
		return out
	}
	settings := cfg.GetSplitTunnel()
	if settings == nil {
		return out
	}
	out.SchemaVersion = cfg.GetSchemaVersion()
	out.Enabled = settings.GetEnabled()
	out.Mode = settings.GetMode()
	out.DefaultAction = settings.GetDefaultAction()
	out.KillSwitch = settings.GetKillSwitch()
	out.IPv6 = settings.GetIpv6()
	out.RuleCount = len(settings.GetRules())

	for _, rule := range settings.GetRules() {
		summary := splitTunnelRule(rule)
		out.Rules = append(out.Rules, summary)
		if rule.GetAction() == string(config.ActionExitNode) {
			out.ExitNodeRules = append(out.ExitNodeRules, SplitTunnelExitNodeRule{
				RuleID:     summary.ID,
				Name:       summary.Name,
				Enabled:    summary.Enabled,
				Priority:   summary.Priority,
				ExitNodeID: summary.ExitNodeID,
			})
		}
	}
	return out
}

func (s *SplitTunnel) revisionConflict() *ClientError {
	return s.localError("split_tunnel_revision_conflict",
		"the split tunnel configuration changed since it was read")
}

func (s *SplitTunnel) localError(code, long string) *ClientError {
	return &ClientError{
		Code:  code,
		Short: s.classifier.translateShort(code),
		Long:  long,
	}
}

// classify maps split tunnel structured errors to their own codes before
// falling back to the shared daemon classifier, so a revision conflict or an
// unimplemented backend is not presented as a generic failure.
func (s *SplitTunnel) classify(err error) *ClientError {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok {
		if info, ok := splitTunnelErrorInfo(st); ok {
			if clientErr := s.classifyReason(st, info); clientErr != nil {
				return clientErr
			}
		}
		switch st.Code() {
		case codes.Unimplemented:
			return s.localError("split_tunnel_unavailable", st.Message())
		case codes.Aborted:
			return s.localError("split_tunnel_revision_conflict", st.Message())
		}
	}
	return s.classifier.classify(err)
}

func splitTunnelErrorInfo(st *status.Status) (*errdetails.ErrorInfo, bool) {
	for _, detail := range st.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok || info.GetDomain() != api.ErrorDomain {
			continue
		}
		return info, true
	}
	return nil, false
}

func (s *SplitTunnel) classifyReason(st *status.Status, info *errdetails.ErrorInfo) *ClientError {
	var code string
	switch info.GetReason() {
	case api.ReasonRevisionConflict:
		code = "split_tunnel_revision_conflict"
	case api.ReasonInvalidConfig:
		code = "split_tunnel_invalid_config"
	case api.ReasonInvalidRequest:
		code = "split_tunnel_invalid_request"
	case api.ReasonUnsupportedVersion:
		code = "split_tunnel_version_unsupported"
	case api.ReasonNotImplemented:
		code = "split_tunnel_unavailable"
	case api.ReasonBackendUnavailable:
		code = "split_tunnel_backend_unavailable"
	case api.ReasonMutationDenied:
		code = "split_tunnel_mutation_denied"
	case api.ReasonUnauthenticated:
		code = "split_tunnel_authentication_required"
	case api.ReasonRateLimited:
		code = "split_tunnel_rate_limited"
	default:
		return nil
	}

	long := st.Message()
	field := info.GetMetadata()["field"]
	if field != "" {
		long = field + ": " + long
	}
	return &ClientError{
		Code:  code,
		Short: s.classifier.translateShort(code),
		Long:  long,
		Field: field,
	}
}
