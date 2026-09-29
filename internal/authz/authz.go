// Package authz decides tools/call requests and filters tools/list results.
package authz

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/ably77/extmcp-guardrails/internal/jsonx"
	"github.com/ably77/extmcp-guardrails/internal/policy"
)

type Code int

const (
	CodePermissionDenied Code = iota + 1
	CodeResourceExhausted
	CodeInvalid
)

// Decision is the outcome of one tools/call check. MCPError, when set, is a
// JSON payload the gateway returns to the client alongside the error.
type Decision struct {
	Allow    bool
	Code     Code
	Reason   string
	MCPError []byte
}

func allow() Decision { return Decision{Allow: true} }

func deny(c Code, format string, a ...any) Decision {
	return Decision{Code: c, Reason: fmt.Sprintf(format, a...)}
}

// object decodes a JSON object keeping keys exactly as sent. encoding/json
// matches struct fields case-insensitively, so {"amount":999999,"Amount":10}
// would decode as 10 while an MCP server in another language reads 999999.
func object(raw []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// str reads m[key] as a string. ok is false when the key is absent or not a string.
func str(m map[string]json.RawMessage, key string) (string, bool) {
	var s string
	raw, present := m[key]
	if !present || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// ToolName returns the tool named in tools/call params, or "" if absent.
func ToolName(params []byte) string {
	m, err := object(params)
	if err != nil {
		return ""
	}
	name, _ := str(m, "name")
	return name
}

// CheckCall decides a tools/call request from its raw JSON-RPC params.
func CheckCall(cfg *policy.Config, persona string, params []byte) Decision {
	p, ok := cfg.Persona(persona)
	if !ok {
		return deny(CodePermissionDenied, "unknown persona %q", persona)
	}
	cp, err := object(params)
	name, _ := str(cp, "name")
	if err != nil || name == "" {
		return deny(CodeInvalid, "tools/call params must name a tool")
	}
	if cfg.Disabled(name) {
		return deny(CodePermissionDenied, "tool %s is disabled", name)
	}
	if !p.Allows(name) {
		return deny(CodePermissionDenied, "persona %s may not call %s", persona, name)
	}
	args, err := object(cp["arguments"])
	if err != nil {
		args = nil
	}
	switch name {
	case "create_purchase_order":
		return checkAmount(cfg, persona, p, args)
	case "send_supplier_email":
		return checkRecipient(cfg, args)
	}
	return allow()
}

func money(v float64) string { return "$" + strconv.FormatFloat(v, 'f', -1, 64) }

func checkAmount(cfg *policy.Config, persona string, p policy.Persona, args map[string]json.RawMessage) Decision {
	var amount float64
	raw, present := args["amount"]
	if !present || json.Unmarshal(raw, &amount) != nil {
		return deny(CodeInvalid, "create_purchase_order needs a numeric amount")
	}
	supplier, _ := str(args, "supplier")
	if amount <= 0 {
		return deny(CodeInvalid, "amount must be positive")
	}
	if amount <= p.POLimit {
		return allow()
	}
	q := url.Values{}
	q.Set("persona", persona)
	q.Set("supplier", supplier)
	q.Set("amount", strconv.FormatFloat(amount, 'f', -1, 64))
	payload, _ := jsonx.Marshal(map[string]any{
		"approval_required": true,
		"limit":             p.POLimit,
		"amount":            amount,
		"approval_url":      cfg.Approval.URL + "?" + q.Encode(),
	})
	d := deny(CodeResourceExhausted, "amount %s exceeds the %s limit for %s; approval required",
		money(amount), money(p.POLimit), persona)
	d.MCPError = payload
	return d
}

func checkRecipient(cfg *policy.Config, args map[string]json.RawMessage) Decision {
	to, _ := str(args, "to")
	if to == "" {
		return deny(CodeInvalid, "send_supplier_email needs a recipient")
	}
	addr, err := mail.ParseAddress(to)
	if err != nil {
		return deny(CodePermissionDenied, "recipient %q is not a single valid address", to)
	}
	domain := strings.ToLower(addr.Address[strings.LastIndex(addr.Address, "@")+1:])
	for _, d := range cfg.Email.AllowedDomains {
		if strings.EqualFold(d, domain) {
			return allow()
		}
	}
	return deny(CodePermissionDenied, "recipient domain %s not allowed", domain)
}

// FilterList removes the tools the persona may not use from a tools/list
// result. Other result fields pass through untouched.
func FilterList(cfg *policy.Config, p policy.Persona, result []byte) ([]byte, []string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(result, &top); err != nil {
		return nil, nil, fmt.Errorf("decode tools/list result: %w", err)
	}
	var tools []json.RawMessage
	if raw, ok := top["tools"]; ok {
		if err := json.Unmarshal(raw, &tools); err != nil {
			return nil, nil, fmt.Errorf("decode tools: %w", err)
		}
	}
	kept := make([]json.RawMessage, 0, len(tools))
	var removed []string
	for _, t := range tools {
		m, err := object(t)
		if err != nil {
			return nil, nil, fmt.Errorf("decode tool: %w", err)
		}
		name, _ := str(m, "name")
		if p.Allows(name) && !cfg.Disabled(name) {
			kept = append(kept, t)
		} else {
			removed = append(removed, name)
		}
	}
	if removed == nil {
		return result, nil, nil
	}
	enc, err := jsonx.Marshal(kept)
	if err != nil {
		return nil, nil, err
	}
	top["tools"] = enc
	out, err := jsonx.Marshal(top)
	return out, removed, err
}
