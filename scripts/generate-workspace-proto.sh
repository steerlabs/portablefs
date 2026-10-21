#!/usr/bin/env bash
# Generate both paired bindings with the repository's pinned protobuf runtimes.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"
command -v protoc >/dev/null
command -v protoc-gen-go >/dev/null
command -v protoc-gen-swift >/dev/null
expected_go="$(sed -nE 's/.*google.golang.org\/protobuf (v[^ ]+).*/\1/p' vcs/go.mod)"
[[ "$(protoc-gen-go --version)" == "protoc-gen-go $expected_go" ]]
expected_swift="$(sed -nE 's/.*swift-protobuf.git", exact: "([^"]+)".*/\1/p' swift/PortableFSKit/Package.swift)"
[[ "$(protoc-gen-swift --version)" == "protoc-gen-swift $expected_swift" ]]
protoc -I . --go_out=vcs --go_opt=module=github.com/steerlabs/portablefs/vcs proto/workspace/v8/control.proto
out=swift/PortableFSKit/Sources/PortableFSWorkspaceCore/Generated
mkdir -p "$out"
protoc -I . --swift_out="$out" --swift_opt=Visibility=Public proto/workspace/v8/control.proto
descriptor="$(mktemp -t portablefs-workspace-descriptor.XXXXXX)"
trap 'rm -f "$descriptor"' EXIT
protoc -I . --descriptor_set_out="$descriptor" proto/workspace/v8/control.proto
go -C vcs run ./internal/workspacecontrol/generate "$descriptor" "$repo_root/proto/workspace/v8/control.proto" \
  "$repo_root/$out/WorkspaceWireSchema.swift" "$repo_root/vcs/internal/workspacecontrol/schema_digest.go" \
  "$repo_root/vcs/internal/workspacepb/control.pb.go" "$repo_root/$out/proto/workspace/v8/control.pb.swift"
gofmt -w vcs/internal/workspacecontrol/schema_digest.go
