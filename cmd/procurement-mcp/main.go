// Command procurement-mcp serves the mock procurement tools over
// StreamableHTTP at /mcp.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ably77/extmcp-guardrails/internal/procurement"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	srv := procurement.NewServer()
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true},
	))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	log.Printf("procurement-mcp listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
