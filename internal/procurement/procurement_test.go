package procurement

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func session(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	if _, err := NewServer().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func text(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("no content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T", res.Content[0])
	}
	return tc.Text
}

func TestListsFiveTools(t *testing.T) {
	res, err := session(t).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	want := "create_purchase_order,delete_supplier,get_supplier,list_purchase_orders,send_supplier_email"
	if strings.Join(names, ",") != want {
		t.Fatalf("tools = %v", names)
	}
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestGetSupplierReturnsPaymentDetails(t *testing.T) {
	out := text(t, call(t, session(t), "get_supplier", map[string]any{"id": "SUP-001"}))
	for _, want := range []string{"Acme Industrial Supply", "004815162342", "94-3175520"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
}

func TestCreatePurchaseOrder(t *testing.T) {
	out := text(t, call(t, session(t), "create_purchase_order", map[string]any{"supplier": "SUP-002", "amount": 5000}))
	if !strings.Contains(out, `"id":"PO-1004"`) || !strings.Contains(out, `"status":"created"`) {
		t.Fatalf("out = %s", out)
	}
}

func TestCreatePurchaseOrderUnknownSupplier(t *testing.T) {
	res := call(t, session(t), "create_purchase_order", map[string]any{"supplier": "SUP-999", "amount": 5})
	if !res.IsError {
		t.Fatal("expected tool error")
	}
}

func TestSendEmailAndDelete(t *testing.T) {
	cs := session(t)
	if out := text(t, call(t, cs, "send_supplier_email", map[string]any{"to": "ap@try-solo.io", "subject": "s", "body": "b"})); !strings.Contains(out, `"status":"queued"`) {
		t.Fatalf("email out = %s", out)
	}
	if out := text(t, call(t, cs, "delete_supplier", map[string]any{"id": "SUP-003"})); !strings.Contains(out, `"deleted":true`) {
		t.Fatalf("delete out = %s", out)
	}
	if res := call(t, cs, "get_supplier", map[string]any{"id": "SUP-003"}); !res.IsError {
		t.Fatal("deleted supplier still found")
	}
}
