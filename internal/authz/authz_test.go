package authz

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ably77/extmcp-guardrails/internal/policy"
)

func cfg(t *testing.T) *policy.Config {
	t.Helper()
	b, err := os.ReadFile("../../testdata/authz.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func call(tool, args string) []byte {
	return []byte(`{"name":"` + tool + `","arguments":` + args + `}`)
}

func TestCheckCall(t *testing.T) {
	c := cfg(t)
	cases := []struct {
		name, persona, tool, args string
		allow                     bool
		code                      Code
	}{
		{"unknown persona", "intern", "get_supplier", `{"id":"SUP-001"}`, false, CodePermissionDenied},
		{"empty persona", "", "get_supplier", `{"id":"SUP-001"}`, false, CodePermissionDenied},
		{"not entitled", "requester", "delete_supplier", `{"id":"SUP-001"}`, false, CodePermissionDenied},
		{"entitled", "requester", "get_supplier", `{"id":"SUP-001"}`, true, 0},
		{"wildcard", "finance-approver", "delete_supplier", `{"id":"SUP-001"}`, true, 0},
		{"under limit", "buyer", "create_purchase_order", `{"supplier":"SUP-001","amount":5000}`, true, 0},
		{"at limit", "buyer", "create_purchase_order", `{"supplier":"SUP-001","amount":10000}`, true, 0},
		{"over limit", "buyer", "create_purchase_order", `{"supplier":"SUP-001","amount":25000}`, false, CodeResourceExhausted},
		{"approver over buyer limit", "finance-approver", "create_purchase_order", `{"supplier":"SUP-001","amount":25000}`, true, 0},
		{"amount as string", "buyer", "create_purchase_order", `{"supplier":"SUP-001","amount":"25000"}`, false, CodeInvalid},
		{"amount missing", "buyer", "create_purchase_order", `{"supplier":"SUP-001"}`, false, CodeInvalid},
		{"amount zero", "buyer", "create_purchase_order", `{"supplier":"SUP-001","amount":0}`, false, CodeInvalid},
		{"amount negative", "buyer", "create_purchase_order", `{"supplier":"SUP-001","amount":-50}`, false, CodeInvalid},
		{"allowed domain", "buyer", "send_supplier_email", `{"to":"ap@try-solo.io","subject":"s","body":"b"}`, true, 0},
		{"allowed domain upper", "buyer", "send_supplier_email", `{"to":"AP@TRY-SOLO.IO","subject":"s","body":"b"}`, true, 0},
		{"external domain", "buyer", "send_supplier_email", `{"to":"x@gmail.com","subject":"s","body":"b"}`, false, CodePermissionDenied},
		{"suffix trick", "buyer", "send_supplier_email", `{"to":"ap@try-solo.io.evil.com","subject":"s","body":"b"}`, false, CodePermissionDenied},
		{"two recipients", "buyer", "send_supplier_email", `{"to":"x@gmail.com, ap@try-solo.io","subject":"s","body":"b"}`, false, CodePermissionDenied},
		{"display name external", "buyer", "send_supplier_email", `{"to":"\"AP\" <x@gmail.com>","subject":"s","body":"b"}`, false, CodePermissionDenied},
		{"missing recipient", "buyer", "send_supplier_email", `{"subject":"s","body":"b"}`, false, CodeInvalid},
	}
	for _, tc := range cases {
		d := CheckCall(c, tc.persona, call(tc.tool, tc.args))
		if d.Allow != tc.allow || (!tc.allow && d.Code != tc.code) {
			t.Errorf("%s: got allow=%v code=%v reason=%q", tc.name, d.Allow, d.Code, d.Reason)
		}
	}
}

func TestCheckCallMalformedParams(t *testing.T) {
	d := CheckCall(cfg(t), "buyer", []byte(`not json`))
	if d.Allow || d.Code != CodeInvalid {
		t.Fatalf("got %+v", d)
	}
}

func TestOverLimitCarriesApprovalPayload(t *testing.T) {
	d := CheckCall(cfg(t), "buyer", call("create_purchase_order", `{"supplier":"SUP-002","amount":25000}`))
	var p struct {
		ApprovalRequired bool    `json:"approval_required"`
		Limit            float64 `json:"limit"`
		Amount           float64 `json:"amount"`
		ApprovalURL      string  `json:"approval_url"`
	}
	if err := json.Unmarshal(d.MCPError, &p); err != nil {
		t.Fatal(err)
	}
	if !p.ApprovalRequired || p.Limit != 10000 || p.Amount != 25000 {
		t.Fatalf("payload = %+v", p)
	}
	if !strings.HasPrefix(p.ApprovalURL, "https://approvals.try-solo.io/requests?") || !strings.Contains(p.ApprovalURL, "supplier=SUP-002") {
		t.Fatalf("approval_url = %s", p.ApprovalURL)
	}
	if strings.Contains(string(d.MCPError), "\\u0026") || !strings.Contains(string(d.MCPError), "&persona=") {
		t.Fatal("payload must not HTML-escape &")
	}
}

func TestDisabledBeatsWildcard(t *testing.T) {
	c := cfg(t)
	c.DisabledTools = []string{"create_purchase_order"}
	d := CheckCall(c, "finance-approver", call("create_purchase_order", `{"supplier":"SUP-001","amount":5}`))
	if d.Allow || d.Code != CodePermissionDenied || !strings.Contains(d.Reason, "disabled") {
		t.Fatalf("got %+v", d)
	}
}

const listResult = `{"tools":[{"name":"get_supplier","description":"Look up <supplier>"},{"name":"delete_supplier"},{"name":"send_supplier_email"}],"nextCursor":"abc"}`

func TestFilterList(t *testing.T) {
	c := cfg(t)
	req, _ := c.Persona("requester")
	out, removed, err := FilterList(c, req, []byte(listResult))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(removed, ",") != "delete_supplier,send_supplier_email" {
		t.Fatalf("removed = %v", removed)
	}
	s := string(out)
	if !strings.Contains(s, `"nextCursor":"abc"`) || !strings.Contains(s, `Look up <supplier>`) || strings.Contains(s, "delete_supplier") {
		t.Fatalf("out = %s", s)
	}
}

func TestFilterListNoChange(t *testing.T) {
	c := cfg(t)
	fa, _ := c.Persona("finance-approver")
	out, removed, err := FilterList(c, fa, []byte(listResult))
	if err != nil || removed != nil || string(out) != listResult {
		t.Fatalf("out=%s removed=%v err=%v", out, removed, err)
	}
}

func TestFilterListToEmpty(t *testing.T) {
	c := cfg(t)
	out, _, err := FilterList(c, policy.Persona{}, []byte(listResult))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"tools":[]`) {
		t.Fatalf("out = %s", out)
	}
}

func TestFilterListHidesDisabled(t *testing.T) {
	c := cfg(t)
	c.DisabledTools = []string{"get_supplier"}
	fa, _ := c.Persona("finance-approver")
	_, removed, _ := FilterList(c, fa, []byte(listResult))
	if len(removed) != 1 || removed[0] != "get_supplier" {
		t.Fatalf("removed = %v", removed)
	}
}

func TestFilterListBadJSON(t *testing.T) {
	if _, _, err := FilterList(cfg(t), policy.Persona{}, []byte(`[`)); err == nil {
		t.Fatal("expected error")
	}
}

// Go's decoder matches keys case-insensitively and keeps the last duplicate.
// An MCP server in another language reads the exact key, so the policy must
// read the exact key too.
func TestExactKeysOnly(t *testing.T) {
	c := cfg(t)
	cases := []struct {
		name, persona, params string
		code                  Code
	}{
		{"tool name case twin", "requester",
			`{"name":"delete_supplier","NAME":"get_supplier","arguments":{"id":"SUP-001"}}`, CodePermissionDenied},
		{"amount case twin", "buyer",
			`{"name":"create_purchase_order","arguments":{"supplier":"SUP-001","amount":999999,"Amount":10}}`, CodeResourceExhausted},
		{"only a case-variant amount", "buyer",
			`{"name":"create_purchase_order","arguments":{"supplier":"SUP-001","Amount":10}}`, CodeInvalid},
		{"recipient case twin", "buyer",
			`{"name":"send_supplier_email","arguments":{"to":"x@gmail.com","TO":"ap@try-solo.io"}}`, CodePermissionDenied},
	}
	for _, tc := range cases {
		d := CheckCall(c, tc.persona, []byte(tc.params))
		if d.Allow || d.Code != tc.code {
			t.Errorf("%s: got allow=%v code=%v reason=%q", tc.name, d.Allow, d.Code, d.Reason)
		}
	}
	if got := ToolName([]byte(`{"name":"delete_supplier","NAME":"get_supplier"}`)); got != "delete_supplier" {
		t.Errorf("ToolName = %q", got)
	}
}

func TestFilterListExactNameKey(t *testing.T) {
	c := cfg(t)
	req, _ := c.Persona("requester")
	_, removed, err := FilterList(c, req, []byte(`{"tools":[{"name":"delete_supplier","NAME":"get_supplier"}]}`))
	if err != nil || len(removed) != 1 || removed[0] != "delete_supplier" {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
}
