# extmcp-guardrails

An ExtMCP policy server and a mock procurement MCP server for the [MCP Guardrails lab](https://github.com/solo-io/fe-enterprise-agentgateway-workshop/blob/main/labs/mcp/mcp-guardrails.md) in the Enterprise Agentgateway workshop.

ExtMCP is agentgateway's MCP-aware policy callout. For each MCP method you opt in (`tools/call`, `tools/list`, and so on), agentgateway sends a gRPC request to an external server with the method, the target backend, the JSON-RPC `params` or `result`, and CEL-evaluated caller metadata. The server passes the message, rewrites it, or denies it with a JSON-RPC error. The protocol is [`ext_mcp.proto`](proto/ext_mcp.proto), vendored from [agentgateway](https://github.com/agentgateway/agentgateway/blob/main/crates/protos/proto/ext_mcp.proto).

## Images

| Image | Binary | Port |
|---|---|---|
| `docker.io/ably7/extmcp-guardrails:0.1.1` | `cmd/extmcp`: the policy server, gRPC over cleartext HTTP/2 | `9001` |
| `docker.io/ably7/procurement-mcp:0.1.1` | `cmd/procurement-mcp`: mock procurement tools over StreamableHTTP at `/mcp`, health at `/healthz` | `8000` |

Both are multi-arch (`linux/amd64`, `linux/arm64`).

## Policy reference

The policy server reads one YAML file (default `/etc/extmcp/config.yaml`, usually a mounted ConfigMap). `mode` picks what the server enforces. Run one Deployment per mode and chain them as separate processors.

### `authz` mode

```yaml
mode: authz
personas:
  buyer:
    tools:
      - get_supplier
      - create_purchase_order
      - send_supplier_email
    poLimit: 10000
  finance-approver:
    tools:
      - "*"
    poLimit: 250000
disabledTools: []
email:
  allowedDomains:
    - try-solo.io
approval:
  url: https://approvals.try-solo.io/requests
```

| Key | Meaning |
|---|---|
| `personas.<name>.tools` | Tools the persona may list and call. `"*"` allows every tool. |
| `personas.<name>.poLimit` | Highest `create_purchase_order` amount the persona may submit. |
| `disabledTools` | Tools denied to every persona, including `"*"` personas. Also hidden from `tools/list`. |
| `email.allowedDomains` | Exact recipient domains `send_supplier_email` may target. Subdomains do not match. |
| `approval.url` | Base URL placed in the approval payload of an over-limit denial. |

The persona comes from the `persona` key of the request's `metadata_context`. Set it on the gateway with `remote.metadata: {persona: jwt.persona}`. The server also logs `sub` when present.

Decisions, in order:

| Check | Method and phase | Result |
|---|---|---|
| Persona missing or unknown | `tools/call` request, `tools/list` response | Deny `PERMISSION_DENIED` (JSON-RPC `-32001`) |
| Tool in `disabledTools` | `tools/call` request | Deny `PERMISSION_DENIED` |
| Tool not in the persona's list | `tools/call` request | Deny `PERMISSION_DENIED` |
| Tool not in the persona's list, or disabled | `tools/list` response | Tool removed from the result |
| `amount` missing, not a number, or not positive | `tools/call` request | Deny `INVALID` |
| `amount` above `poLimit` | `tools/call` request | Deny `RESOURCE_EXHAUSTED` (`-32003`) with `mcp_error` `{"approval_required":true,"limit":...,"amount":...,"approval_url":...}` |
| `to` is not one address in an allowed domain | `tools/call` request | Deny `PERMISSION_DENIED` |
| Anything else | | Pass, with metadata `{decision: allow, persona}` |

Other methods pass through unchanged.

The server reads argument keys exactly as sent. `{"amount":10,"Amount":999999}` is checked against `amount`, the key an MCP server reads, so a case-variant duplicate cannot change what the policy sees.

### `redact` mode

```yaml
mode: redact
patterns:
  - name: BANK_ACCOUNT
    regex: '\b\d{8,17}\b'
  - name: TAX_ID
    regex: '\b\d{2}-\d{7}\b'
```

On a `tools/call` response, the server replaces each match with `<NAME>` in every `text` content item and in every string or number inside `structuredContent`. Patterns apply in list order. A result with no matches passes unchanged.

Redaction covers `tools/call` results only. Embedded `resource` content items, and the results of `resources/read` and `prompts/get`, pass through as the MCP server sent them. A pattern that matches a number in `structuredContent` replaces it with a string token, so a pattern such as `\b\d{8,17}\b` also masks large numeric fields and can break a client that validates the tool's output schema. Anchor patterns to the values you mean to mask.

### Reloading

The server hashes the policy file every `RELOAD_INTERVAL` and swaps in a changed file once it parses. An invalid file keeps the previous policy running and logs `policy reload failed` once. Changing `mode` needs a restart.

The previous policy lives only in memory. If the pod restarts while the file is invalid, the server exits at startup and the pod crashloops, and a `FailClosed` processor then fails every governed call. Check `kubectl logs` for `policy reload failed` after each edit, and fix the file before anything restarts the pod. Kubernetes refreshes a mounted ConfigMap on the kubelet sync period, so an edit can take up to about a minute to reach the file.

### Environment

| Variable | Default | |
|---|---|---|
| `CONFIG_PATH` | `/etc/extmcp/config.yaml` | Policy file |
| `PORT` | `9001` | gRPC listen port (h2c) |
| `RELOAD_INTERVAL` | `5s` | Policy poll interval |
| `LOG_LEVEL` | `info` | `debug` also logs the full `metadata_context` of each call |
| `SIMULATED_DELAY` | `0s` | Wait this long before each decision, to test gateway timeouts. The wait ends early when the gateway's deadline passes. |

Each decision is one JSON log line on stdout with `msg` set to `allow`, `deny`, `filter`, `redact`, or `pass`, plus `persona`, `sub`, `method`, `tool`, and `reason` or `removed` or `hits`.

## Run locally

```bash
make test
CONFIG_PATH=testdata/authz.yaml PORT=19001 go run ./cmd/extmcp
PORT=18000 go run ./cmd/procurement-mcp
```

## Fork and modify

1. Add a case to the `switch cp.Name` block in `CheckCall` (`internal/authz/authz.go`) for the tool you want to govern.
2. Add rows to `TestCheckCall` in `internal/authz/authz_test.go` and run `make test`.
3. Build and push: `./build-and-push.sh <version>`. The script uses the `ly-builder` buildx builder and the `ably7` Docker Hub namespace; change both for your registry.

To pick up a newer protocol, update the commit in the `proto/ext_mcp.proto` header, replace the file, and run `make gen` (requires `protoc`, `protoc-gen-go`, and `protoc-gen-go-grpc`).
