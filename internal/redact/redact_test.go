package redact

import (
	"os"
	"strings"
	"testing"

	"github.com/ably77/extmcp-guardrails/internal/policy"
)

func patterns(t *testing.T) []policy.Pattern {
	t.Helper()
	b, err := os.ReadFile("../../testdata/redact.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return c.Patterns
}

const supplier = `{"content":[{"type":"text","text":"{\"id\":\"SUP-001\",\"bankAccount\":\"004815162342\",\"taxId\":\"94-3175520\"}"}],` +
	`"structuredContent":{"id":"SUP-001","bankAccount":"004815162342","taxId":"94-3175520","nested":[{"acct":12345678}]}}`

func TestRedactsTextAndStructured(t *testing.T) {
	out, hits, err := Result(patterns(t), []byte(supplier))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, leak := range []string{"004815162342", "94-3175520", "12345678"} {
		if strings.Contains(s, leak) {
			t.Errorf("leaked %s: %s", leak, s)
		}
	}
	if !strings.Contains(s, `"bankAccount":"<BANK_ACCOUNT>"`) || !strings.Contains(s, `<TAX_ID>`) {
		t.Fatalf("missing literal mask tokens: %s", s)
	}
	if !strings.Contains(s, `"id":"SUP-001"`) {
		t.Fatalf("non-matching fields must survive: %s", s)
	}
	if hits["BANK_ACCOUNT"] != 3 || hits["TAX_ID"] != 2 {
		t.Fatalf("hits = %v", hits)
	}
}

func TestNoMatchReturnsInputUnchanged(t *testing.T) {
	in := `{"content":[{"type":"text","text":"PO-1001 approved for $4200"}],"structuredContent":{"amount":4200}}`
	out, hits, err := Result(patterns(t), []byte(in))
	if err != nil || len(hits) != 0 || string(out) != in {
		t.Fatalf("out=%s hits=%v err=%v", out, hits, err)
	}
}

func TestLeavesNonTextContentAlone(t *testing.T) {
	in := `{"content":[{"type":"image","data":"004815162342","mimeType":"image/png"}]}`
	out, hits, err := Result(patterns(t), []byte(in))
	if err != nil || len(hits) != 0 || string(out) != in {
		t.Fatalf("out=%s hits=%v err=%v", out, hits, err)
	}
}

func TestBadJSON(t *testing.T) {
	if _, _, err := Result(patterns(t), []byte(`{`)); err == nil {
		t.Fatal("expected error")
	}
}
