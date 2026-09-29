GO_PKG := github.com/ably77/extmcp-guardrails/gen/extmcp;extmcp

.PHONY: gen test build

gen:
	protoc -I proto \
	  --go_out=gen/extmcp --go_opt=paths=source_relative --go_opt=Mext_mcp.proto='$(GO_PKG)' \
	  --go-grpc_out=gen/extmcp --go-grpc_opt=paths=source_relative --go-grpc_opt=Mext_mcp.proto='$(GO_PKG)' \
	  proto/ext_mcp.proto

test:
	go test ./...

build:
	go build -o bin/extmcp ./cmd/extmcp
	go build -o bin/procurement-mcp ./cmd/procurement-mcp
