package policy

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseAuthz(t *testing.T) {
	c, err := Parse(mustRead(t, "../../testdata/authz.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	buyer, ok := c.Persona("buyer")
	if !ok || buyer.POLimit != 10000 {
		t.Fatalf("buyer = %+v, %v", buyer, ok)
	}
	if !buyer.Allows("send_supplier_email") || buyer.Allows("delete_supplier") {
		t.Fatal("buyer tool list wrong")
	}
	fa, _ := c.Persona("finance-approver")
	if !fa.Allows("delete_supplier") {
		t.Fatal("wildcard persona should allow any tool")
	}
	if _, ok := c.Persona(""); ok {
		t.Fatal("empty persona must not resolve")
	}
}

func TestParseRedactCompilesPatterns(t *testing.T) {
	c, err := Parse(mustRead(t, "../../testdata/redact.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Patterns) != 2 || !c.Patterns[0].Re().MatchString("004815162342") {
		t.Fatalf("patterns = %+v", c.Patterns)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown mode":  "mode: audit\n",
		"unknown field": "mode: authz\npersonas:\n  buyer:\n    polimit: 5\n",
		"no personas":   "mode: authz\n",
		"no patterns":   "mode: redact\n",
		"bad regex":     "mode: redact\npatterns:\n  - name: X\n    regex: '('\n",
		"unnamed":       "mode: redact\npatterns:\n  - regex: 'a'\n",
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDisabledAppliesToWildcard(t *testing.T) {
	c, err := Parse([]byte("mode: authz\npersonas:\n  a:\n    tools: [\"*\"]\ndisabledTools:\n  - delete_supplier\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Disabled("delete_supplier") || c.Disabled("get_supplier") {
		t.Fatal("Disabled wrong")
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestStoreReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, string(mustRead(t, "../../testdata/authz.yaml")))
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	if changed, err := s.Reload(); changed || err != nil {
		t.Fatalf("unchanged file: changed=%v err=%v", changed, err)
	}

	lowered := strings.Replace(string(mustRead(t, "../../testdata/authz.yaml")), "poLimit: 10000", "poLimit: 2500", 1)
	writeFile(t, path, lowered)
	if changed, err := s.Reload(); !changed || err != nil {
		t.Fatalf("edited file: changed=%v err=%v", changed, err)
	}
	if b, _ := s.Get().Persona("buyer"); b.POLimit != 2500 {
		t.Fatalf("buyer limit = %v", b.POLimit)
	}

	writeFile(t, path, "mode: authz\npersonas: [not a map\n")
	if _, err := s.Reload(); err == nil {
		t.Fatal("invalid file must return an error")
	}
	if b, _ := s.Get().Persona("buyer"); b.POLimit != 2500 {
		t.Fatal("invalid file must keep the previous config")
	}
	if changed, err := s.Reload(); changed || err != nil {
		t.Fatalf("same invalid file reported twice: changed=%v err=%v", changed, err)
	}

	writeFile(t, path, string(mustRead(t, "../../testdata/redact.yaml")))
	if _, err := s.Reload(); err == nil || s.Get().Mode != ModeAuthz {
		t.Fatal("mode change must be rejected")
	}
}

func TestWatchSurvivesBadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, string(mustRead(t, "../../testdata/authz.yaml")))
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "garbage: [")
	s.reloadAndLog(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.Get() == nil || s.Get().Mode != ModeAuthz {
		t.Fatal("store lost its config")
	}
}
