//go:build darwin

package cli

import (
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// Use the production transport and authenticator. RoundTripper fakes bypass
// DialContext and cannot prove that peer rejection precedes every HTTP request.
func TestFSDControlAuthenticatesEveryUnixRequest(t *testing.T) {
	digest, err := daemonctl.CurrentExecutableSHA256()
	if err != nil {
		t.Fatal(err)
	}
	identity := daemonctl.Identity{
		SchemaVersion: daemonctl.IdentitySchemaVersion, ControlProtocol: daemonctl.ControlProtocolVersion,
		DaemonVersion: "peer-test", ExecutableSHA256: digest,
		PFSLocalMajor: pfslocal.ProtocolMajor, PFSLocalMinor: pfslocal.ProtocolMinor,
	}
	identityJSON, err := daemonctl.EncodeIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	const ref = "att_AAAAAAAAAAAAAAAAAAAAAA"
	for _, action := range []string{"outgoing identity", "paired identity", "inventory", "stop", "frontend ready", "operational inventory"} {
		for _, verdict := range []string{"accept real peer", "reject real digest", "reject authenticator error"} {
			t.Run(action+"/"+verdict, func(t *testing.T) {
				socket := filepath.Join(shortSocketDir(t), "control.sock")
				ln, err := net.Listen("unix", socket)
				if err != nil {
					t.Fatal(err)
				}
				var requests atomic.Int32
				var requestPath atomic.Value
				server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					requestPath.Store(r.URL.Path)
					switch r.URL.Path {
					case daemonctl.LifecycleIdentityPath:
						_, _ = w.Write(identityJSON)
					case daemonctl.LifecycleInventoryPath:
						_, _ = w.Write([]byte(`{"attachment_count":0}`))
					case daemonctl.LifecycleStopIfIdlePath, "/v2/attaches/" + ref + "/frontend-ready":
						w.WriteHeader(http.StatusNoContent)
					case "/v2/attaches":
						_, _ = w.Write([]byte(`{"attaches":[]}`))
					default:
						http.NotFound(w, r)
					}
				})}
				go func() { _ = server.Serve(ln) }()
				t.Cleanup(func() { _ = server.Close(); _ = ln.Close() })
				ctl := newFsdControl(socket)
				if action != "outgoing identity" && action != "paired identity" {
					if err := ctl.requireOutgoingIdentityWithin(identity, time.Second); err != nil {
						t.Fatal(err)
					}
				}
				requests.Store(0)
				expected := identity
				if verdict == "reject real digest" {
					expected.ExecutableSHA256 = strings.Repeat("0", 64)
					ctl.expectedPeerSHA256 = expected.ExecutableSHA256
				}
				sentinel := errors.New("peer authenticator refused")
				authCalls := 0
				productionAuthenticator := ctl.authenticatePeer
				ctl.authenticatePeer = func(conn net.Conn, want string) error {
					authCalls++
					if want != expected.ExecutableSHA256 {
						t.Errorf("auth digest = %q, want %q", want, expected.ExecutableSHA256)
					}
					if verdict == "reject authenticator error" {
						return sentinel
					}
					return productionAuthenticator(conn, want)
				}
				var callErr error
				wantPath := daemonctl.LifecycleIdentityPath
				switch action {
				case "outgoing identity":
					callErr = ctl.requireOutgoingIdentityWithin(expected, time.Second)
				case "paired identity":
					callErr = ctl.requireCompatibleIdentityWithin(expected.DaemonVersion, expected.ExecutableSHA256, time.Second)
				case "inventory":
					wantPath = daemonctl.LifecycleInventoryPath
					_, callErr = ctl.lifecycleInventory()
				case "stop":
					wantPath = daemonctl.LifecycleStopIfIdlePath
					callErr = ctl.stopIfIdle()
				case "frontend ready":
					wantPath = "/v2/attaches/" + ref + "/frontend-ready"
					callErr = ctl.requireFrontendReady(ref)
				case "operational inventory":
					wantPath = "/v2/attaches"
					_, callErr = ctl.listAttaches()
				}
				if authCalls != 1 {
					t.Fatalf("authenticator calls = %d, want 1", authCalls)
				}
				if verdict == "accept real peer" {
					if callErr != nil || requests.Load() != 1 || requestPath.Load() != wantPath {
						t.Fatalf("error=%v requests=%d path=%v, want %s", callErr, requests.Load(), requestPath.Load(), wantPath)
					}
				} else {
					if callErr == nil || requests.Load() != 0 {
						t.Fatalf("peer rejection did not block HTTP: error=%v requests=%d", callErr, requests.Load())
					}
					if verdict == "reject authenticator error" && !errors.Is(callErr, sentinel) {
						t.Fatalf("lost authentication error: %v", callErr)
					}
				}
			})
		}
	}
}
