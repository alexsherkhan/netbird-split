//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

// SplitTunnelApplication is one discovered desktop entry. Executable, icon and
// source paths are redacted by the daemon for callers that are not privileged;
// the Redacted flags record that so the screen can explain the empty fields.
type SplitTunnelApplication struct {
	DesktopID   string `json:"desktopId"`
	Name        string `json:"name"`
	IconName    string `json:"iconName"`
	Executable  string `json:"executable"`
	InstallType string `json:"installType"`
	SourcePath  string `json:"sourcePath"`
	NoDisplay   bool   `json:"noDisplay"`
	Unknown     bool   `json:"unknown"`
}

// SplitTunnelApplications is the application discovery result.
type SplitTunnelApplications struct {
	Applications       []SplitTunnelApplication `json:"applications"`
	RedactedFields     []string                 `json:"redactedFields,omitempty"`
	ExecutableRedacted bool                     `json:"executableRedacted"`
	SourceRedacted     bool                     `json:"sourceRedacted"`
}

// SplitTunnelRules is the evaluated rule set and the structural conflicts the
// daemon found in it.
type SplitTunnelRules struct {
	Revision  uint64            `json:"revision"`
	Rules     []SplitTunnelRule `json:"rules"`
	Conflicts []string          `json:"conflicts"`
}

// SplitTunnelEventParams selects retained events after a sequence.
type SplitTunnelEventParams struct {
	AfterSequence uint64 `json:"afterSequence"`
	Limit         uint32 `json:"limit"`
}

// SplitTunnelEvent is one retained split tunnel control event. Details and the
// timestamp are available only to privileged callers; Redacted records that
// the daemon withheld them.
type SplitTunnelEvent struct {
	Sequence      uint64            `json:"sequence"`
	Type          string            `json:"type"`
	Severity      string            `json:"severity"`
	Message       string            `json:"message"`
	Timestamp     string            `json:"timestamp"`
	Details       map[string]string `json:"details,omitempty"`
	Redacted      bool              `json:"redacted"`
	DroppedEvents uint64            `json:"droppedEvents"`
}

// SplitTunnelEvents is one page of retained events.
type SplitTunnelEvents struct {
	Events       []SplitTunnelEvent `json:"events"`
	NextSequence uint64             `json:"nextSequence"`
}

// SplitTunnelTraceParams is one packet to evaluate against the policy.
type SplitTunnelTraceParams struct {
	SourceIP        string `json:"sourceIp"`
	DestinationIP   string `json:"destinationIp"`
	Protocol        string `json:"protocol"`
	SourcePort      uint32 `json:"sourcePort"`
	DestinationPort uint32 `json:"destinationPort"`
	Direction       string `json:"direction"`
	UID             uint32 `json:"uid"`
	HasUID          bool   `json:"hasUid"`
}

// SplitTunnelTraceStage is one decision step of a packet trace.
type SplitTunnelTraceStage struct {
	Name              string `json:"name"`
	Message           string `json:"message"`
	Allowed           bool   `json:"allowed"`
	ForwardingDetails string `json:"forwardingDetails"`
}

// SplitTunnelTrace is the policy evaluation of a traced packet.
type SplitTunnelTrace struct {
	Stages         []SplitTunnelTraceStage `json:"stages"`
	FinalAction    string                  `json:"finalAction"`
	Redacted       bool                    `json:"redacted"`
	RedactedFields []string                `json:"redactedFields,omitempty"`
}

// SplitTunnelRollbackParams restores a configuration revision as a new
// revision. ExpectedRevision keeps a concurrent daemon change visible.
type SplitTunnelRollbackParams struct {
	ExpectedRevision uint64 `json:"expectedRevision"`
	Revision         uint64 `json:"revision"`
}

// ListApplications returns discovered applications filtered by a case
// insensitive desktop ID or display name substring.
func (s *SplitTunnel) ListApplications(ctx context.Context, query string) (SplitTunnelApplications, error) {
	cli, err := s.conn.SplitTunnelClient()
	if err != nil {
		return SplitTunnelApplications{}, s.classify(err)
	}
	resp, err := cli.ListApplications(ctx, &proto.ListSplitTunnelApplicationsRequest{
		ApiVersion: api.APIVersion,
		Query:      query,
	})
	if err != nil {
		return SplitTunnelApplications{}, s.classify(err)
	}
	redacted := redactedFields(resp.GetRedactedFields())
	out := SplitTunnelApplications{
		Applications:       make([]SplitTunnelApplication, 0, len(resp.GetApplications())),
		RedactedFields:     append([]string(nil), resp.GetRedactedFields()...),
		ExecutableRedacted: hasRedactedField(redacted, "applications.executable"),
		SourceRedacted:     hasRedactedField(redacted, "applications.source_path"),
	}
	for _, app := range resp.GetApplications() {
		out.Applications = append(out.Applications, SplitTunnelApplication{
			DesktopID:   app.GetDesktopId(),
			Name:        app.GetName(),
			IconName:    app.GetIconName(),
			Executable:  app.GetExecutable(),
			InstallType: app.GetInstallType(),
			SourcePath:  app.GetSourcePath(),
			NoDisplay:   app.GetNoDisplay(),
			Unknown:     app.GetUnknown(),
		})
	}
	return out, nil
}

// ListRules returns the full evaluated rule set and its structural conflicts.
func (s *SplitTunnel) ListRules(ctx context.Context) (SplitTunnelRules, error) {
	cli, err := s.conn.SplitTunnelClient()
	if err != nil {
		return SplitTunnelRules{}, s.classify(err)
	}
	resp, err := cli.ListRules(ctx, &proto.ListSplitTunnelRulesRequest{ApiVersion: api.APIVersion})
	if err != nil {
		return SplitTunnelRules{}, s.classify(err)
	}
	out := SplitTunnelRules{
		Revision:  resp.GetRevision(),
		Rules:     make([]SplitTunnelRule, 0, len(resp.GetRules())),
		Conflicts: append([]string(nil), resp.GetConflicts()...),
	}
	for _, rule := range resp.GetRules() {
		out.Rules = append(out.Rules, splitTunnelRule(rule))
	}
	return out, nil
}

// ListEvents returns retained control events after a sequence.
func (s *SplitTunnel) ListEvents(ctx context.Context, params SplitTunnelEventParams) (SplitTunnelEvents, error) {
	cli, err := s.conn.SplitTunnelClient()
	if err != nil {
		return SplitTunnelEvents{}, s.classify(err)
	}
	resp, err := cli.ListEvents(ctx, &proto.ListSplitTunnelEventsRequest{
		ApiVersion:    api.APIVersion,
		AfterSequence: params.AfterSequence,
		Limit:         params.Limit,
	})
	if err != nil {
		return SplitTunnelEvents{}, s.classify(err)
	}
	out := SplitTunnelEvents{
		Events:       make([]SplitTunnelEvent, 0, len(resp.GetEvents())),
		NextSequence: resp.GetNextSequence(),
	}
	for _, event := range resp.GetEvents() {
		converted := SplitTunnelEvent{
			Sequence:      event.GetSequence(),
			Type:          event.GetType(),
			Severity:      event.GetSeverity(),
			Message:       event.GetMessage(),
			Details:       cloneDiagnostics(event.GetDetails()),
			Redacted:      event.GetRedacted(),
			DroppedEvents: event.GetDroppedEvents(),
		}
		if ts := event.GetTimestamp(); ts != nil {
			converted.Timestamp = ts.AsTime().UTC().Format(time.RFC3339Nano)
		}
		out.Events = append(out.Events, converted)
	}
	return out, nil
}

// TracePacket evaluates one packet against the current policy. Forwarding
// details are redacted for callers that are not privileged.
func (s *SplitTunnel) TracePacket(ctx context.Context, params SplitTunnelTraceParams) (SplitTunnelTrace, error) {
	cli, err := s.conn.SplitTunnelClient()
	if err != nil {
		return SplitTunnelTrace{}, s.classify(err)
	}
	if params.SourcePort > math.MaxUint16 || params.DestinationPort > math.MaxUint16 {
		return SplitTunnelTrace{}, s.localError("split_tunnel_invalid_request",
			"trace ports must be between 0 and 65535")
	}
	resp, err := cli.TracePacket(ctx, &proto.TraceSplitTunnelPacketRequest{
		ApiVersion:      api.APIVersion,
		SourceIp:        strings.TrimSpace(params.SourceIP),
		DestinationIp:   strings.TrimSpace(params.DestinationIP),
		Protocol:        strings.ToLower(strings.TrimSpace(params.Protocol)),
		SourcePort:      params.SourcePort,
		DestinationPort: params.DestinationPort,
		Direction:       strings.TrimSpace(params.Direction),
		Uid:             params.UID,
		HasUid:          params.HasUID,
	})
	if err != nil {
		return SplitTunnelTrace{}, s.classify(err)
	}
	out := SplitTunnelTrace{
		Stages:         make([]SplitTunnelTraceStage, 0, len(resp.GetStages())),
		FinalAction:    resp.GetFinalAction(),
		Redacted:       resp.GetRedacted(),
		RedactedFields: append([]string(nil), resp.GetRedactedFields()...),
	}
	for _, stage := range resp.GetStages() {
		out.Stages = append(out.Stages, SplitTunnelTraceStage{
			Name:              stage.GetName(),
			Message:           stage.GetMessage(),
			Allowed:           stage.GetAllowed(),
			ForwardingDetails: stage.GetForwardingDetails(),
		})
	}
	return out, nil
}

// Rollback restores a known configuration revision as a new revision. A stale
// expected revision is refused before any write is sent.
func (s *SplitTunnel) Rollback(ctx context.Context, params SplitTunnelRollbackParams) (SplitTunnelRevision, error) {
	if params.Revision == 0 {
		return SplitTunnelRevision{}, s.localError("split_tunnel_invalid_request",
			"a rollback needs a positive target revision")
	}
	if params.Revision == params.ExpectedRevision {
		return SplitTunnelRevision{}, s.localError("split_tunnel_invalid_request",
			"a rollback must target an older revision")
	}
	cli, err := s.conn.SplitTunnelClient()
	if err != nil {
		return SplitTunnelRevision{}, s.classify(err)
	}
	resp, err := cli.RollbackConfig(ctx, &proto.RollbackSplitTunnelConfigRequest{
		ApiVersion:       api.APIVersion,
		ExpectedRevision: params.ExpectedRevision,
		Revision:         params.Revision,
	})
	if err != nil {
		return SplitTunnelRevision{}, classifyRollbackError(s, err)
	}
	if resp.GetRevision() <= params.ExpectedRevision {
		return SplitTunnelRevision{}, s.localError("split_tunnel_revision_conflict",
			"the daemon did not advance the split tunnel configuration revision")
	}
	return SplitTunnelRevision{Revision: resp.GetRevision()}, nil
}

func classifyRollbackError(s *SplitTunnel, err error) *ClientError {
	if st, ok := status.FromError(err); ok && st.Code() == codes.Internal &&
		strings.Contains(strings.ToLower(st.Message()), "revision not found") {
		return s.localError("split_tunnel_revision_not_found",
			"the requested split tunnel configuration revision is no longer retained")
	}
	return s.classify(err)
}

func redactedFields(fields []string) map[string]struct{} {
	out := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		out[field] = struct{}{}
	}
	return out
}

func splitTunnelRule(rule *proto.SplitTunnelRule) SplitTunnelRule {
	out := SplitTunnelRule{
		ID:             rule.GetId(),
		Name:           rule.GetName(),
		Enabled:        rule.GetEnabled(),
		Priority:       rule.GetPriority(),
		MatchMode:      rule.GetMatchMode(),
		Action:         rule.GetAction(),
		ExitNodeID:     rule.GetExitNodeId(),
		Description:    rule.GetDescription(),
		ConditionCount: len(rule.GetConditions()),
		Conditions:     make([]SplitTunnelCondition, 0, len(rule.GetConditions())),
	}
	for _, condition := range rule.GetConditions() {
		out.Conditions = append(out.Conditions, splitTunnelCondition(condition))
	}
	out.Supported, out.UnsupportedReason = ruleSupported(rule)
	return out
}

func splitTunnelCondition(condition *proto.SplitTunnelCondition) SplitTunnelCondition {
	out := SplitTunnelCondition{
		Type:  condition.GetType(),
		Value: condition.GetValue(),
	}
	if len(condition.GetChildren()) > 0 {
		out.Children = make([]SplitTunnelCondition, 0, len(condition.GetChildren()))
		for _, child := range condition.GetChildren() {
			out.Children = append(out.Children, splitTunnelCondition(child))
		}
	}
	return out
}

func ruleSupported(rule *proto.SplitTunnelRule) (bool, string) {
	if _, ok := supportedRuleActions[rule.GetAction()]; !ok {
		return false, fmt.Sprintf("unsupported action %q", rule.GetAction())
	}
	switch rule.GetMatchMode() {
	case "", string(config.MatchAll), string(config.MatchAny):
	default:
		return false, fmt.Sprintf("unsupported match mode %q", rule.GetMatchMode())
	}
	for _, condition := range rule.GetConditions() {
		if ok, reason := conditionSupported(condition); !ok {
			return false, reason
		}
	}
	return true, ""
}

func conditionSupported(condition *proto.SplitTunnelCondition) (bool, string) {
	typ := config.ConditionType(condition.GetType())
	switch typ {
	case config.ConditionAll, config.ConditionAny:
		if condition.GetValue() != "" {
			return false, fmt.Sprintf("%s condition carries a value", typ)
		}
		for _, child := range condition.GetChildren() {
			if ok, reason := conditionSupported(child); !ok {
				return false, reason
			}
		}
		return true, ""
	case config.ConditionDesktopID, config.ConditionExecutable, config.ConditionFlatpakID,
		config.ConditionSnapID, config.ConditionDomain, config.ConditionWildcardDomain,
		config.ConditionCIDR, config.ConditionProtocolPort, config.ConditionUID:
		return true, ""
	default:
		return false, fmt.Sprintf("unsupported condition type %q", typ)
	}
}
