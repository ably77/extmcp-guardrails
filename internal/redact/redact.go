// Package redact masks sensitive values in tools/call results.
package redact

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ably77/extmcp-guardrails/internal/jsonx"
	"github.com/ably77/extmcp-guardrails/internal/policy"
)

// Result masks pattern matches in every text content item and in every
// string or number inside structuredContent.
func Result(patterns []policy.Pattern, result []byte) ([]byte, map[string]int, error) {
	dec := json.NewDecoder(bytes.NewReader(result))
	dec.UseNumber()
	var top map[string]any
	if err := dec.Decode(&top); err != nil {
		return nil, nil, fmt.Errorf("decode tools/call result: %w", err)
	}
	hits := map[string]int{}
	if content, ok := top["content"].([]any); ok {
		for _, item := range content {
			m, ok := item.(map[string]any)
			if !ok || m["type"] != "text" {
				continue
			}
			if s, ok := m["text"].(string); ok {
				m["text"] = mask(patterns, s, hits)
			}
		}
	}
	if sc, ok := top["structuredContent"]; ok {
		top["structuredContent"] = walk(patterns, sc, hits)
	}
	if len(hits) == 0 {
		return result, hits, nil
	}
	out, err := jsonx.Marshal(top)
	return out, hits, err
}

func walk(patterns []policy.Pattern, v any, hits map[string]int) any {
	switch x := v.(type) {
	case string:
		return mask(patterns, x, hits)
	case json.Number:
		if m := mask(patterns, x.String(), hits); m != x.String() {
			return m
		}
		return x
	case map[string]any:
		for k, e := range x {
			x[k] = walk(patterns, e, hits)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = walk(patterns, e, hits)
		}
		return x
	}
	return v
}

func mask(patterns []policy.Pattern, s string, hits map[string]int) string {
	for _, p := range patterns {
		n := len(p.Re().FindAllStringIndex(s, -1))
		if n == 0 {
			continue
		}
		hits[p.Name] += n
		s = p.Re().ReplaceAllLiteralString(s, "<"+p.Name+">")
	}
	return s
}
