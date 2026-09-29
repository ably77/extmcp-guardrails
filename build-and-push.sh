#!/bin/bash
set -e

# Build and push both images to Docker Hub.
# Usage: ./build-and-push.sh [version]
# Example: ./build-and-push.sh 0.1.1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="${1:-0.1.1}"

build() {
  local app="$1" image="$2"
  echo "=== Building and pushing ${image}:${VERSION} ==="
  docker buildx build --builder ly-builder \
    --platform linux/amd64,linux/arm64 \
    --build-arg APP="$app" \
    -t "${image}:${VERSION}" \
    -t "${image}:latest" \
    --push .
}

build extmcp ably7/extmcp-guardrails
build procurement-mcp ably7/procurement-mcp

echo ""
echo "=== Pushed ably7/extmcp-guardrails:${VERSION} and ably7/procurement-mcp:${VERSION} ==="
