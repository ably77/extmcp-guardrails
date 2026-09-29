// Package jsonx marshals JSON the way MCP clients expect to read it.
package jsonx

import (
	"bytes"
	"encoding/json"
)

// Marshal encodes v without HTML escaping, so mask tokens such as
// <BANK_ACCOUNT> reach the client as written.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
