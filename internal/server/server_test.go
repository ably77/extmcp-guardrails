package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ably77/extmcp-guardrails/gen/extmcp"
	"github.com/ably77/extmcp-guardrails/internal/policy"
)

func client(t *testing.T, testdata string) extmcp.ExtMcpClient {
	t.Helper()
	return clientWith(t, testdata, 0)
}

func clientWith(t *testing.T, testdata string, delay time.Duration) extmcp.ExtMcpClient {
	t.Helper()
	b, err := os.ReadFile("../../testdata/" + testdata)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := policy.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	extmcp.RegisterExtMcpServer(gs, New(store, slog.New(slog.NewTextHandler(io.Discard, nil))).WithDelay(delay))
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return extmcp.NewExtMcpClient(conn)
}

func meta(t *testing.T, persona string) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(map[string]any{"persona": persona, "sub": persona + "-user"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRequestOverLimit(t *testing.T) {
	c := client(t, "authz.yaml")
	res, err := c.CheckRequest(context.Background(), &extmcp.McpRequest{
		ServiceNames:    []string{"procurement"},
		Method:          "tools/call",
		MetadataContext: meta(t, "buyer"),
		McpRequest:      []byte(`{"name":"create_purchase_order","arguments":{"supplier":"SUP-001","amount":25000}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	e := res.GetError()
	if e == nil || e.GetCode() != extmcp.AuthorizationError_RESOURCE_EXHAUSTED {
		t.Fatalf("got %v", res)
	}
	if !strings.Contains(string(e.GetMcpError()), `"approval_required":true`) {
		t.Fatalf("mcp_error = %s", e.GetMcpError())
	}
}

func TestRequestAllowCarriesMetadata(t *testing.T) {
	c := client(t, "authz.yaml")
	res, err := c.CheckRequest(context.Background(), &extmcp.McpRequest{
		Method:          "tools/call",
		MetadataContext: meta(t, "buyer"),
		McpRequest:      []byte(`{"name":"get_supplier","arguments":{"id":"SUP-001"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetPass() == nil || res.GetMetadata().GetFields()["decision"].GetStringValue() != "allow" {
		t.Fatalf("got %v", res)
	}
}

func TestRequestNotEntitled(t *testing.T) {
	c := client(t, "authz.yaml")
	res, _ := c.CheckRequest(context.Background(), &extmcp.McpRequest{
		Method:          "tools/call",
		MetadataContext: meta(t, "requester"),
		McpRequest:      []byte(`{"name":"delete_supplier","arguments":{"id":"SUP-001"}}`),
	})
	if res.GetError().GetCode() != extmcp.AuthorizationError_PERMISSION_DENIED {
		t.Fatalf("got %v", res)
	}
}

func TestRequestNoMetadataDenied(t *testing.T) {
	c := client(t, "authz.yaml")
	res, _ := c.CheckRequest(context.Background(), &extmcp.McpRequest{
		Method:     "tools/call",
		McpRequest: []byte(`{"name":"get_supplier","arguments":{}}`),
	})
	if res.GetError().GetCode() != extmcp.AuthorizationError_PERMISSION_DENIED {
		t.Fatalf("got %v", res)
	}
}

func TestUngovernedMethodPasses(t *testing.T) {
	c := client(t, "authz.yaml")
	res, _ := c.CheckRequest(context.Background(), &extmcp.McpRequest{Method: "prompts/get", MetadataContext: meta(t, "requester")})
	if res.GetPass() == nil {
		t.Fatalf("got %v", res)
	}
}

func TestResponseFiltersList(t *testing.T) {
	c := client(t, "authz.yaml")
	res, err := c.CheckResponse(context.Background(), &extmcp.McpResponse{
		Method:          "tools/list",
		MetadataContext: meta(t, "requester"),
		McpResponse:     []byte(`{"tools":[{"name":"get_supplier"},{"name":"delete_supplier"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if m := string(res.GetMutated()); strings.Contains(m, "delete_supplier") || !strings.Contains(m, "get_supplier") {
		t.Fatalf("mutated = %s", m)
	}
}

func TestResponseListUnknownPersonaDenied(t *testing.T) {
	c := client(t, "authz.yaml")
	res, _ := c.CheckResponse(context.Background(), &extmcp.McpResponse{
		Method:      "tools/list",
		McpResponse: []byte(`{"tools":[]}`),
	})
	if res.GetError().GetCode() != extmcp.AuthorizationError_PERMISSION_DENIED {
		t.Fatalf("got %v", res)
	}
}

func TestRedactMode(t *testing.T) {
	c := client(t, "redact.yaml")
	res, err := c.CheckResponse(context.Background(), &extmcp.McpResponse{
		Method:      "tools/call",
		McpResponse: []byte(`{"content":[{"type":"text","text":"acct 004815162342"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if m := string(res.GetMutated()); !strings.Contains(m, "acct <BANK_ACCOUNT>") {
		t.Fatalf("mutated = %s", m)
	}
	res, _ = c.CheckResponse(context.Background(), &extmcp.McpResponse{
		Method:      "tools/call",
		McpResponse: []byte(`{"content":[{"type":"text","text":"nothing here"}]}`),
	})
	if res.GetPass() == nil {
		t.Fatalf("clean result should pass, got %v", res)
	}
}

func TestRedactModeIgnoresRequests(t *testing.T) {
	c := client(t, "redact.yaml")
	res, _ := c.CheckRequest(context.Background(), &extmcp.McpRequest{Method: "tools/call", McpRequest: []byte(`{"name":"x"}`)})
	if res.GetPass() == nil {
		t.Fatalf("got %v", res)
	}
}

func TestSimulatedDelay(t *testing.T) {
	c := clientWith(t, "authz.yaml", 300*time.Millisecond)
	req := &extmcp.McpRequest{Method: "prompts/get", MetadataContext: meta(t, "buyer")}
	start := time.Now()
	if _, err := c.CheckRequest(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 300*time.Millisecond {
		t.Fatalf("returned after %v, want >= 300ms", el)
	}
}

func TestSimulatedDelayHonorsDeadline(t *testing.T) {
	c := clientWith(t, "authz.yaml", 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.CheckResponse(ctx, &extmcp.McpResponse{Method: "tools/list", McpResponse: []byte(`{"tools":[]}`)})
	if err == nil {
		t.Fatal("expected a deadline error")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("waited %v past a 100ms deadline", el)
	}
}
