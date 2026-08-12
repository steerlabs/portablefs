package portablefsd

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func servePreflightFrontend(
	t *testing.T,
	version string,
	resolveError *pfslocal.ErrorReply,
) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pfsp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "p.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			envelope, err := pfslocal.ReadFrame(conn)
			if err != nil {
				return
			}
			var reply any
			switch envelope.Body.(type) {
			case *pfslocal.Hello:
				reply = &pfslocal.HelloReply{
					ProtocolMajor: pfslocal.ProtocolMajor,
					ProtocolMinor: pfslocal.ProtocolMinor,
					DaemonVersion: version,
				}
			case *pfslocal.ResolveRequest:
				if resolveError != nil {
					reply = resolveError
				} else {
					reply = &pfslocal.ResolveReply{}
				}
			default:
				return
			}
			if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{
				RequestID: envelope.RequestID,
				Body:      reply,
			}); err != nil {
				return
			}
		}
	}()
	return path
}

func TestFrontendPreflightNegotiatesAndResolvesThroughDaemon(t *testing.T) {
	path := servePreflightFrontend(t, "test-version", nil)
	if err := preflightFrontendAt(path, "att_AAAAAAAAAAAAAAAAAAAAAA", "test-version"); err != nil {
		t.Fatal(err)
	}
}

func TestFrontendPreflightFailsClosedOnResolveRefusal(t *testing.T) {
	path := servePreflightFrontend(t, "test-version", &pfslocal.ErrorReply{
		Errno:   2,
		Message: "unknown attach",
	})
	err := preflightFrontendAt(path, "att_AAAAAAAAAAAAAAAAAAAAAA", "test-version")
	if err == nil || !strings.Contains(err.Error(), "unknown attach") {
		t.Fatalf("preflight error = %v", err)
	}
}

func TestFrontendPreflightFailsClosedOnAbsentSocket(t *testing.T) {
	err := preflightFrontendAt(
		filepath.Join(t.TempDir(), "absent.sock"),
		"att_AAAAAAAAAAAAAAAAAAAAAA",
		"test-version",
	)
	if err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Fatalf("preflight error = %v", err)
	}
}
