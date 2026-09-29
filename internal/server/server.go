// Package server implements the ExtMCP gRPC service.
package server

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ably77/extmcp-guardrails/gen/extmcp"
	"github.com/ably77/extmcp-guardrails/internal/authz"
	"github.com/ably77/extmcp-guardrails/internal/policy"
	"github.com/ably77/extmcp-guardrails/internal/redact"
)

type Server struct {
	extmcp.UnimplementedExtMcpServer
	store *policy.Store
	log   *slog.Logger
	delay time.Duration
}

func New(store *policy.Store, log *slog.Logger) *Server {
	return &Server{store: store, log: log}
}

// WithDelay makes every check wait d before deciding, to simulate a slow
// policy server. The wait ends early when the gateway's deadline passes.
func (s *Server) WithDelay(d time.Duration) *Server {
	s.delay = d
	return s
}

func (s *Server) wait(ctx context.Context) error {
	if s.delay <= 0 {
		return nil
	}
	t := time.NewTimer(s.delay)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	}
}

func metaString(s *structpb.Struct, key string) string {
	return s.GetFields()[key].GetStringValue()
}

func (s *Server) logger(phase, method string, md *structpb.Struct, services []string) (*slog.Logger, string) {
	persona := metaString(md, "persona")
	l := s.log.With("phase", phase, "method", method, "persona", persona,
		"sub", metaString(md, "sub"), "services", services)
	l.Debug("metadata_context", "metadata", md.AsMap())
	return l, persona
}

var errCodes = map[authz.Code]extmcp.AuthorizationError_Code{
	authz.CodePermissionDenied:  extmcp.AuthorizationError_PERMISSION_DENIED,
	authz.CodeResourceExhausted: extmcp.AuthorizationError_RESOURCE_EXHAUSTED,
	authz.CodeInvalid:           extmcp.AuthorizationError_INVALID,
}

func toProto(d authz.Decision) *extmcp.AuthorizationError {
	return &extmcp.AuthorizationError{Code: errCodes[d.Code], Reason: d.Reason, McpError: d.MCPError}
}

func (s *Server) CheckRequest(ctx context.Context, req *extmcp.McpRequest) (*extmcp.McpRequestResult, error) {
	if err := s.wait(ctx); err != nil {
		return nil, err
	}
	cfg := s.store.Get()
	log, persona := s.logger("request", req.GetMethod(), req.GetMetadataContext(), req.GetServiceNames())
	if cfg.Mode != policy.ModeAuthz || req.GetMethod() != "tools/call" {
		log.Debug("pass")
		return &extmcp.McpRequestResult{Result: &extmcp.McpRequestResult_Pass{Pass: &extmcp.Pass{}}}, nil
	}
	tool := authz.ToolName(req.GetMcpRequest())
	d := authz.CheckCall(cfg, persona, req.GetMcpRequest())
	if !d.Allow {
		log.Info("deny", "tool", tool, "reason", d.Reason)
		return &extmcp.McpRequestResult{Result: &extmcp.McpRequestResult_Error{Error: toProto(d)}}, nil
	}
	log.Info("allow", "tool", tool)
	md, _ := structpb.NewStruct(map[string]any{"decision": "allow", "persona": persona})
	return &extmcp.McpRequestResult{
		Result:   &extmcp.McpRequestResult_Pass{Pass: &extmcp.Pass{}},
		Metadata: md,
	}, nil
}

func (s *Server) CheckResponse(ctx context.Context, resp *extmcp.McpResponse) (*extmcp.McpResponseResult, error) {
	if err := s.wait(ctx); err != nil {
		return nil, err
	}
	cfg := s.store.Get()
	log, persona := s.logger("response", resp.GetMethod(), resp.GetMetadataContext(), resp.GetServiceNames())
	pass := &extmcp.McpResponseResult{Result: &extmcp.McpResponseResult_Pass{Pass: &extmcp.Pass{}}}

	switch {
	case cfg.Mode == policy.ModeAuthz && resp.GetMethod() == "tools/list":
		p, ok := cfg.Persona(persona)
		if !ok {
			d := authz.Decision{Code: authz.CodePermissionDenied, Reason: "unknown persona \"" + persona + "\""}
			log.Info("deny", "reason", d.Reason)
			return &extmcp.McpResponseResult{Result: &extmcp.McpResponseResult_Error{Error: toProto(d)}}, nil
		}
		out, removed, err := authz.FilterList(cfg, p, resp.GetMcpResponse())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "filter tools/list: %v", err)
		}
		if removed == nil {
			log.Info("pass")
			return pass, nil
		}
		log.Info("filter", "removed", removed)
		return &extmcp.McpResponseResult{Result: &extmcp.McpResponseResult_Mutated{Mutated: out}}, nil

	case cfg.Mode == policy.ModeRedact && resp.GetMethod() == "tools/call":
		out, hits, err := redact.Result(cfg.Patterns, resp.GetMcpResponse())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "redact tools/call: %v", err)
		}
		if len(hits) == 0 {
			log.Info("pass")
			return pass, nil
		}
		log.Info("redact", "hits", hits)
		return &extmcp.McpResponseResult{Result: &extmcp.McpResponseResult_Mutated{Mutated: out}}, nil
	}
	log.Debug("pass")
	return pass, nil
}
