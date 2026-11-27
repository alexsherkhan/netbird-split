package api

import (
	"context"
	"math"
	"net/netip"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

func checkVersion(requested uint32) error {
	if requested == 0 || requested == APIVersion {
		return nil
	}
	return unsupportedVersion(requested)
}

// GetStatus returns the current engine status.
func (s *Service) GetStatus(ctx context.Context, req *proto.GetSplitTunnelStatusRequest) (*proto.GetSplitTunnelStatusResponse, error) {
	caller, err := s.readIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(req.GetApiVersion()); err != nil {
		return nil, err
	}
	if s.backend == nil {
		return nil, notImplemented("status")
	}
	current, err := s.backend.Status(ctx)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return statusToProto(current, ipcauth.IsPrivilegedCaller(caller)), nil
}

// GetConfig returns the current configuration and revision.
func (s *Service) GetConfig(ctx context.Context, req *proto.GetSplitTunnelConfigRequest) (*proto.GetSplitTunnelConfigResponse, error) {
	if _, err := s.readIdentity(ctx); err != nil {
		return nil, err
	}
	if err := checkVersion(req.GetApiVersion()); err != nil {
		return nil, err
	}
	if s.backend == nil {
		return nil, notImplemented("config read")
	}
	cfg, revision, err := s.backend.Config(ctx)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return &proto.GetSplitTunnelConfigResponse{
		ApiVersion: APIVersion,
		Revision:   revision,
		Config:     configToProto(cfg),
	}, nil
}

// SetConfig validates and applies a configuration.
func (s *Service) SetConfig(ctx context.Context, req *proto.SetSplitTunnelConfigRequest) (*proto.SetSplitTunnelConfigResponse, error) {
	if _, err := s.mutationIdentity(ctx); err != nil {
		return nil, err
	}
	if err := checkVersion(req.GetApiVersion()); err != nil {
		return nil, err
	}
	if s.backend == nil {
		return nil, notImplemented("config mutation")
	}
	cfg, err := configFromProto(req.GetConfig())
	if err != nil {
		return nil, invalidConfig(err)
	}
	revision, err := s.backend.ApplyConfig(ctx, cfg, req.GetExpectedRevision())
	if err != nil {
		return nil, mapBackendError(err)
	}
	if revision <= req.GetExpectedRevision() {
		return nil, errorWithReason(codes.Internal, ReasonInternal,
			"split tunnel configuration revision did not advance", nil)
	}
	return &proto.SetSplitTunnelConfigResponse{
		ApiVersion: APIVersion,
		Revision:   revision,
	}, nil
}

// RollbackConfig restores an earlier configuration as a new revision.
func (s *Service) RollbackConfig(ctx context.Context, req *proto.RollbackSplitTunnelConfigRequest) (*proto.RollbackSplitTunnelConfigResponse, error) {
	if _, err := s.mutationIdentity(ctx); err != nil {
		return nil, err
	}
	if err := checkVersion(req.GetApiVersion()); err != nil {
		return nil, err
	}
	if req.GetRevision() == 0 {
		return nil, invalidRequest("rollback revision must be positive")
	}
	if s.backend == nil {
		return nil, notImplemented("config rollback")
	}
	revision, err := s.backend.RollbackConfig(ctx, req.GetRevision(), req.GetExpectedRevision())
	if err != nil {
		return nil, mapBackendError(err)
	}
	if revision <= req.GetExpectedRevision() {
		return nil, errorWithReason(codes.Internal, ReasonInternal,
			"split tunnel configuration revision did not advance", nil)
	}
	return &proto.RollbackSplitTunnelConfigResponse{
		ApiVersion: APIVersion,
		Revision:   revision,
	}, nil
}

// ListApplications returns discovered applications.
func (s *Service) ListApplications(ctx context.Context, req *proto.ListSplitTunnelApplicationsRequest) (*proto.ListSplitTunnelApplicationsResponse, error) {
	caller, err := s.readIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(req.GetApiVersion()); err != nil {
		return nil, err
	}
	if s.backend == nil {
		return nil, notImplemented("application discovery")
	}
	apps, err := s.backend.Applications(ctx)
	if err != nil {
		return nil, mapBackendError(err)
	}

	privileged := ipcauth.IsPrivilegedCaller(caller)
	response := &proto.ListSplitTunnelApplicationsResponse{
		ApiVersion:   APIVersion,
		Applications: make([]*proto.SplitTunnelApplication, 0, len(apps)),
	}
	for _, app := range apps {
		if !matchesApplication(app, req.GetQuery()) {
			continue
		}
		converted := applicationToProto(app)
		if !privileged {
			converted.Executable = ""
			converted.IconPath = ""
			converted.SourcePath = ""
		}
		response.Applications = append(response.Applications, converted)
	}
	if !privileged && len(response.Applications) > 0 {
		response.RedactedFields = []string{
			redactedApplicationExec,
			redactedApplicationIcon,
			redactedApplicationSource,
		}
	}
	return response, nil
}

// ListRules returns the evaluated rules and structural conflicts.
func (s *Service) ListRules(ctx context.Context, req *proto.ListSplitTunnelRulesRequest) (*proto.ListSplitTunnelRulesResponse, error) {
	if _, err := s.readIdentity(ctx); err != nil {
		return nil, err
	}
	if err := checkVersion(req.GetApiVersion()); err != nil {
		return nil, err
	}
	if s.backend == nil {
		return nil, notImplemented("rule listing")
	}
	rules, err := s.backend.Rules(ctx)
	if err != nil {
		return nil, mapBackendError(err)
	}
	response := &proto.ListSplitTunnelRulesResponse{
		ApiVersion: APIVersion,
		Revision:   rules.Revision,
		Conflicts:  append([]string(nil), rules.Conflicts...),
		Rules:      make([]*proto.SplitTunnelRule, 0, len(rules.Rules)),
	}
	for i := range rules.Rules {
		response.Rules = append(response.Rules, ruleToProto(&rules.Rules[i]))
	}
	return response, nil
}

// TracePacket evaluates a packet against the current policy.
func (s *Service) TracePacket(ctx context.Context, req *proto.TraceSplitTunnelPacketRequest) (*proto.TraceSplitTunnelPacketResponse, error) {
	caller, err := s.readIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(req.GetApiVersion()); err != nil {
		return nil, err
	}
	query, err := traceQueryFromProto(req)
	if err != nil {
		return nil, err
	}
	if s.backend == nil {
		return nil, notImplemented("packet trace")
	}
	result, err := s.backend.Trace(ctx, query)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return traceToProto(result, ipcauth.IsPrivilegedCaller(caller)), nil
}

func traceQueryFromProto(req *proto.TraceSplitTunnelPacketRequest) (TraceQuery, error) {
	source, err := netip.ParseAddr(req.GetSourceIp())
	if err != nil {
		return TraceQuery{}, invalidRequest("source_ip is not a valid IP address")
	}
	destination, err := netip.ParseAddr(req.GetDestinationIp())
	if err != nil {
		return TraceQuery{}, invalidRequest("destination_ip is not a valid IP address")
	}
	if req.GetSourcePort() > math.MaxUint16 {
		return TraceQuery{}, invalidRequest("source_port must be between 0 and 65535")
	}
	if req.GetDestinationPort() > math.MaxUint16 {
		return TraceQuery{}, invalidRequest("destination_port must be between 0 and 65535")
	}
	query := TraceQuery{
		SourceIP:        source.Unmap(),
		DestinationIP:   destination.Unmap(),
		Protocol:        strings.ToLower(req.GetProtocol()),
		SourcePort:      uint16(req.GetSourcePort()),
		DestinationPort: uint16(req.GetDestinationPort()),
		Direction:       req.GetDirection(),
	}
	if req.GetHasUid() {
		uid := config.UID(req.GetUid())
		query.UID = &uid
	}
	return query, nil
}

// ListEvents returns retained events after a sequence number.
func (s *Service) ListEvents(ctx context.Context, req *proto.ListSplitTunnelEventsRequest) (*proto.ListSplitTunnelEventsResponse, error) {
	caller, err := s.readIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(req.GetApiVersion()); err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = DefaultEventLimit
	}
	if limit > MaxEventLimit {
		limit = MaxEventLimit
	}
	events, next := s.events.list(req.GetAfterSequence(), limit)
	privileged := ipcauth.IsPrivilegedCaller(caller)
	response := &proto.ListSplitTunnelEventsResponse{
		ApiVersion:   APIVersion,
		Events:       make([]*proto.SplitTunnelEvent, 0, len(events)),
		NextSequence: next,
	}
	for _, event := range events {
		response.Events = append(response.Events, eventToProto(event, privileged))
	}
	return response, nil
}

// SubscribeEvents streams retained and live events.
func (s *Service) SubscribeEvents(req *proto.SubscribeSplitTunnelEventsRequest, stream proto.SplitTunnelService_SubscribeEventsServer) error {
	ctx := stream.Context()
	caller, err := s.readIdentity(ctx)
	if err != nil {
		return err
	}
	if err := checkVersion(req.GetApiVersion()); err != nil {
		return err
	}

	sub, replay := s.events.subscribe(req.GetAfterSequence(), 0)
	defer s.events.unsubscribe(sub)
	privileged := ipcauth.IsPrivilegedCaller(caller)

	for _, event := range replay {
		if err := stream.Send(eventToProto(event, privileged)); err != nil {
			return err
		}
	}
	for {
		select {
		case delivered, ok := <-sub.ch:
			if !ok {
				return nil
			}
			converted := eventToProto(delivered.event, privileged)
			converted.DroppedEvents = delivered.dropped
			if err := stream.Send(converted); err != nil {
				return err
			}
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		}
	}
}

func statusToProto(current Status, privileged bool) *proto.GetSplitTunnelStatusResponse {
	response := &proto.GetSplitTunnelStatusResponse{
		ApiVersion: APIVersion,
		Revision:   current.Revision,
		Enabled:    current.Enabled,
		Running:    current.Running,
		Mode:       string(current.Mode),
		Backend:    current.Backend,
		Processes:  make([]*proto.SplitTunnelProcess, 0, len(current.Processes)),
	}
	for _, process := range current.Processes {
		response.Processes = append(response.Processes, &proto.SplitTunnelProcess{
			Pid:        process.PID,
			DesktopId:  process.DesktopID,
			Name:       process.Name,
			Executable: process.Executable,
			Uid:        uint32(process.UID),
			Cgroup:     process.Cgroup,
		})
	}
	if privileged {
		response.Diagnostics = cloneStringMap(current.Diagnostics)
		return response
	}
	if len(current.Diagnostics) > 0 {
		response.RedactedFields = append(response.RedactedFields, redactedDiagnostics)
	}
	if len(response.Processes) > 0 {
		for _, process := range response.Processes {
			process.Pid = 0
			process.Executable = ""
			process.Uid = 0
			process.Cgroup = ""
		}
		response.RedactedFields = append(response.RedactedFields,
			redactedProcessPID, redactedProcessExecutable, redactedProcessUID, redactedProcessCgroup)
	}
	return response
}

func traceToProto(result TraceResult, privileged bool) *proto.TraceSplitTunnelPacketResponse {
	response := &proto.TraceSplitTunnelPacketResponse{
		ApiVersion:  APIVersion,
		FinalAction: string(result.FinalAction),
		Stages:      make([]*proto.SplitTunnelTraceStage, 0, len(result.Stages)),
	}
	for _, stage := range result.Stages {
		converted := &proto.SplitTunnelTraceStage{
			Name:    stage.Name,
			Message: stage.Message,
			Allowed: stage.Allowed,
		}
		if privileged {
			converted.ForwardingDetails = stage.ForwardingDetails
		} else if stage.ForwardingDetails != "" {
			response.Redacted = true
		}
		response.Stages = append(response.Stages, converted)
	}
	if response.Redacted {
		response.RedactedFields = []string{redactedTraceDetails}
	}
	return response
}

func eventToProto(event Event, privileged bool) *proto.SplitTunnelEvent {
	converted := &proto.SplitTunnelEvent{
		Sequence: event.Sequence,
		Type:     event.Type,
		Severity: event.Severity,
		Message:  event.Message,
	}
	if !event.Timestamp.IsZero() {
		converted.Timestamp = timestamppb.New(event.Timestamp)
	}
	if privileged {
		converted.Details = cloneStringMap(event.Details)
		return converted
	}
	if len(event.Details) > 0 {
		converted.Redacted = true
	}
	return converted
}
