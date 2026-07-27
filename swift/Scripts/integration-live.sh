#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SWIFT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_DIR="$SWIFT_ROOT/PortableFSKit"
GO_REPO="${PFS_GO_REPO:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
GO_BIN="${GO_BIN:-}"

if [[ -z "$GO_BIN" ]]; then
  if command -v go >/dev/null 2>&1; then
    GO_BIN="$(command -v go)"
  elif [[ -x /opt/homebrew/bin/go ]]; then
    GO_BIN=/opt/homebrew/bin/go
  elif [[ -x /usr/local/go/bin/go ]]; then
    GO_BIN=/usr/local/go/bin/go
  elif [[ -x /usr/local/bin/go ]]; then
    GO_BIN=/usr/local/bin/go
  fi
fi

if [[ -z "$GO_BIN" || ! -x "$GO_BIN" ]]; then
  echo "go toolchain not found; set GO_BIN=/path/to/go" >&2
  exit 2
fi

if [[ ! -d "$GO_REPO/vcs" ]]; then
  echo "Go worktree not found at $GO_REPO" >&2
  exit 2
fi

TMP_ROOT="${PFS_LIVE_TMP:-$(mktemp -d "${TMPDIR:-/tmp}/pfs-live.XXXXXX")}"
BIN_DIR="$TMP_ROOT/bin"
RUN_DIR="$TMP_ROOT/run"
LOG_DIR="$TMP_ROOT/logs"
mkdir -p "$BIN_DIR" "$RUN_DIR" "$LOG_DIR"

PIDS=()

cleanup() {
  local status=$?
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
  if [[ $status -ne 0 ]]; then
    echo "integration-live failed; logs in $LOG_DIR" >&2
    for log in "$LOG_DIR"/*.log; do
      [[ -f "$log" ]] || continue
      echo "---- ${log##*/} tail ----" >&2
      tail -80 "$log" >&2 || true
    done
  fi
  if [[ "${PFS_LIVE_KEEP:-0}" != "1" ]]; then
    rm -rf "$TMP_ROOT"
  else
    echo "kept live integration temp dir: $TMP_ROOT" >&2
  fi
}
trap cleanup EXIT

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

wait_tcp() {
  local host="$1"
  local port="$2"
  python3 - "$host" "$port" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
deadline = time.time() + 20
last = None
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            sys.exit(0)
    except OSError as exc:
        last = exc
        time.sleep(0.05)
raise SystemExit(f"tcp {host}:{port} did not become ready: {last}")
PY
}

wait_unix() {
  local path="$1"
  python3 - "$path" <<'PY'
import socket, sys, time
path = sys.argv[1]
deadline = time.time() + 20
last = None
while time.time() < deadline:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect(path)
        s.close()
        sys.exit(0)
    except OSError as exc:
        last = exc
        time.sleep(0.05)
raise SystemExit(f"unix socket {path} did not become ready: {last}")
PY
}

VOLUME_API_PORT="$(free_port)"
VCS_FS_PORT="$(free_port)"
VCS_NFS_PORT="$(free_port)"
VOLUME_API_URL="http://127.0.0.1:$VOLUME_API_PORT"
VCS_FS_ADDR="127.0.0.1:$VCS_FS_PORT"
CONTROL_SOCKET="$RUN_DIR/control.sock"
FRONTEND_SOCKET="$RUN_DIR/frontend.sock"

cat > "$TMP_ROOT/volume_api_stub.py" <<'PY'
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

host = sys.argv[1]
port = int(sys.argv[2])

state = {
    "head": "head-0",
    "manifest_version": "v1",
    "entries": [],
    "commit": 0,
    "fencing": 0,
    "blobs": {},
}
lock = threading.Lock()

def read_body(handler):
    length = int(handler.headers.get("Content-Length", "0") or "0")
    return handler.rfile.read(length)

def write_json(handler, status, body):
    data = json.dumps(body, separators=(",", ":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/v1/volumes/") and parsed.path.endswith("/status"):
            with lock:
                entries = list(state["entries"])
                head = state["head"]
            write_json(self, 200, {"head": {"id": head, "manifest": {"entries": entries}}})
            return
        if parsed.path.startswith("/v1/blobs/"):
            digest = urllib.parse.unquote(parsed.path[len("/v1/blobs/"):])
            with lock:
                data = state["blobs"].get(digest)
            if data is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/v1/blobs/"):
            digest = urllib.parse.unquote(parsed.path[len("/v1/blobs/"):])
            data = read_body(self)
            with lock:
                state["blobs"][digest] = data
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        body = read_body(self)
        try:
            payload = json.loads(body.decode() or "{}")
        except json.JSONDecodeError:
            payload = {}
        if parsed.path == "/v1/volumes":
            write_json(self, 200, {"volume": {"id": "vol-live"}})
            return
        if parsed.path.startswith("/v1/volumes/") and parsed.path.endswith("/attach"):
            with lock:
                state["fencing"] += 1
                head = state["head"]
                version = state["manifest_version"]
                fencing = state["fencing"]
            write_json(self, 200, {
                "session": {"id": "sess-live", "lease": {"id": "lease-live", "fencingToken": fencing}},
                "branch": {"headCommitId": head},
                "manifest": {"version": version},
            })
            return
        if parsed.path == "/v1/attach-sessions/sess-live/commit":
            manifest = payload.get("manifest") or {}
            with lock:
                state["commit"] += 1
                state["head"] = f"head-{state['commit']}"
                state["manifest_version"] = manifest.get("version") or state["manifest_version"]
                state["entries"] = list(manifest.get("entries") or [])
                head = state["head"]
            write_json(self, 200, {"commit": {"id": head}})
            return
        if parsed.path == "/v1/attach-sessions/sess-live/detach":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/v1/leases/lease-live/renew":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

server = ThreadingHTTPServer((host, port), Handler)
print(f"volume api stub listening on {host}:{port}", flush=True)
server.serve_forever()
PY

echo "building Go binaries from $GO_REPO/vcs"
(
  cd "$GO_REPO/vcs"
  GOFLAGS="${GOFLAGS:-} -mod=readonly" "$GO_BIN" build -o "$BIN_DIR/vcs" ./cmd/vcs
  GOFLAGS="${GOFLAGS:-} -mod=readonly" "$GO_BIN" build -o "$BIN_DIR/portablefsd" ./cmd/portablefsd
)

python3 "$TMP_ROOT/volume_api_stub.py" 127.0.0.1 "$VOLUME_API_PORT" >"$LOG_DIR/volume-api.log" 2>&1 &
PIDS+=("$!")
wait_tcp 127.0.0.1 "$VOLUME_API_PORT"

(
  cd "$GO_REPO/vcs"
  env \
    VOLUME_API_URL="$VOLUME_API_URL" \
    VOLUME_API_TOKEN="" \
    VCS_VOLUME_ID="vol-live" \
    VCS_BRANCH="main" \
    VCS_WRITABLE=1 \
    VCS_ADDR="127.0.0.1:$VCS_NFS_PORT" \
    VCS_FS_ADDR="$VCS_FS_ADDR" \
    VCS_WAL="$TMP_ROOT/vcs.wal" \
    VCS_CHECKPOINT_INTERVAL=3600 \
    VCS_FAILOVER_POLL=1 \
    VCS_LEASE_TTL=60 \
    VCS_CACHE_RAM_MB=32 \
    VCS_CACHE_DISK_MB=0 \
    "$BIN_DIR/vcs"
) >"$LOG_DIR/vcs.log" 2>&1 &
PIDS+=("$!")
wait_tcp 127.0.0.1 "$VCS_FS_PORT"

"$BIN_DIR/portablefsd" \
  -frontend-socket "$FRONTEND_SOCKET" \
  -control-socket "$CONTROL_SOCKET" \
  -state-dir "$TMP_ROOT/portablefsd-state" >"$LOG_DIR/portablefsd.log" 2>&1 &
PORTABLEFSD_PID="$!"
PIDS+=("$PORTABLEFSD_PID")
wait_unix "$CONTROL_SOCKET"
wait_unix "$FRONTEND_SOCKET"

ATTACH_BODY="$(python3 - "$VCS_FS_ADDR" <<'PY'
import json, sys
authority = sys.argv[1]
print(json.dumps({
    "volumeId": "vol-live",
    "branch": "main",
    "authorityUrl": authority,
    "authToken": "",
    "mountPath": "/Volumes/PortableFSLive",
    "options": {
        "writePolicy": "writethrough",
        "fsyncPolicy": "local",
        "negativeCache": True,
        "diskCacheMb": 1
    }
}, separators=(",", ":")))
PY
)"

ATTACH_RESPONSE="$(curl --silent --show-error --fail \
  --unix-socket "$CONTROL_SOCKET" \
  -H "Content-Type: application/json" \
  --data "$ATTACH_BODY" \
  http://portablefsd/v1/attaches)"
ATTACH_REF="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["attachRef"])' <<<"$ATTACH_RESPONSE")"

echo "live attachRef=$ATTACH_REF"
echo "frontend socket=$FRONTEND_SOCKET"
echo "control socket=$CONTROL_SOCKET"

(
  cd "$PKG_DIR"
  PFS_LIVE=1 \
    PFS_LIVE_FRONTEND_SOCKET="$FRONTEND_SOCKET" \
    PFS_LIVE_CONTROL_SOCKET="$CONTROL_SOCKET" \
    PFS_LIVE_ATTACH_REF="$ATTACH_REF" \
    PFS_LIVE_PORTABLEFSD_PID="$PORTABLEFSD_PID" \
    PFS_LIVE_PORTABLEFSD_BIN="$BIN_DIR/portablefsd" \
    PFS_LIVE_PORTABLEFSD_STATE_DIR="$TMP_ROOT/portablefsd-state" \
    PFS_LIVE_PORTABLEFSD_RESTART_LOG="$LOG_DIR/portablefsd-restart.log" \
    PFS_LIVE_AUTHORITY_URL="$VCS_FS_ADDR" \
    PFS_LIVE_VOLUME_ID="vol-live" \
    PFS_LIVE_BRANCH="main" \
    PFS_LIVE_MOUNT_PATH="/Volumes/PortableFSLive" \
    swift test --filter PfsLiveIntegration
)
