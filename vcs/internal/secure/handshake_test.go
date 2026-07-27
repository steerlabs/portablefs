package secure

import (
	"net"
	"testing"
)

// TestHandshakeAcceptsMatchingToken: a client and server sharing the token both
// succeed, so an authenticated peer is served.
func TestHandshakeAcceptsMatchingToken(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	errc := make(chan error, 1)
	go func() { errc <- ServerHandshake(s, "secret") }()
	if err := ClientHandshake(c, "secret"); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

// TestHandshakeRejectsWrongToken: a mismatched token is rejected on both ends, so
// an unauthenticated peer is never served.
func TestHandshakeRejectsWrongToken(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	errc := make(chan error, 1)
	go func() { errc <- ServerHandshake(s, "right") }()
	cerr := ClientHandshake(c, "wrong")
	serr := <-errc
	if serr == nil {
		t.Fatal("server accepted a wrong token")
	}
	if cerr == nil {
		t.Fatal("client did not observe rejection")
	}
}

// TestHandshakeRejectsTokenlessClient reproduces the deadlock the e2e caught: a
// client with no token connecting to a server that REQUIRES one must be rejected
// promptly (the old asymmetric no-op left the server blocked forever on a token
// frame the tokenless client never sent).
func TestHandshakeRejectsTokenlessClient(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	errc := make(chan error, 1)
	go func() { errc <- ServerHandshake(s, "required-token") }()
	cerr := ClientHandshake(c, "") // client presents no token
	serr := <-errc
	if serr == nil {
		t.Fatal("server must reject a tokenless client when a token is required")
	}
	if cerr == nil {
		t.Fatal("client must observe the rejection, not hang")
	}
}

// TestHandshakeNoTokenIsNoop: with no token configured the handshake still does a
// (trivial, empty-token) exchange and both sides accept — backward compatible with
// loopback / tunnelled deployments.
func TestHandshakeNoTokenIsNoop(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	errc := make(chan error, 1)
	go func() { errc <- ServerHandshake(s, "") }()
	if err := ClientHandshake(c, ""); err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// TestRequireSecureExposure: a non-loopback bind needs TLS or a token; loopback is
// always allowed.
func TestRequireSecureExposure(t *testing.T) {
	t.Setenv("VCS_TLS_CERT", "")
	t.Setenv("VCS_AUTH_TOKEN", "")
	for _, loopback := range []string{"127.0.0.1:2050", "[::1]:2050", "localhost:2050"} {
		if err := RequireSecureExposure(loopback); err != nil {
			t.Fatalf("loopback bind %q should be allowed: %v", loopback, err)
		}
	}
	// All-interfaces binds are network-reachable and must be refused unauthenticated.
	// ":2050" parses to an empty host, which previously slipped the loopback exemption.
	for _, exposed := range []string{"0.0.0.0:2050", ":2050", "[::]:2050", "10.0.0.5:2050"} {
		if err := RequireSecureExposure(exposed); err == nil {
			t.Fatalf("exposed bind %q with no TLS and no token must be refused", exposed)
		}
	}
	t.Setenv("VCS_AUTH_TOKEN", "secret")
	for _, exposed := range []string{"0.0.0.0:2050", ":2050", "[::]:2050"} {
		if err := RequireSecureExposure(exposed); err != nil {
			t.Fatalf("exposed bind %q with a token should be allowed: %v", exposed, err)
		}
	}
}

// TestRequireSecureExposureCertWithoutKey: a cert WITHOUT a key yields a plaintext
// listener (ServerTLS needs both), so the exposure gate must NOT accept it as secure.
func TestRequireSecureExposureCertWithoutKey(t *testing.T) {
	t.Setenv("VCS_AUTH_TOKEN", "")
	t.Setenv("VCS_TLS_KEY", "")
	t.Setenv("VCS_TLS_CERT", "/etc/cert.pem") // cert set, key missing → plaintext listener
	if err := RequireSecureExposure("0.0.0.0:2050"); err == nil {
		t.Fatal("a cert without a key is a PLAINTEXT listener — exposure must be refused")
	}
	// Both set → genuinely TLS → allowed.
	t.Setenv("VCS_TLS_KEY", "/etc/key.pem")
	if err := RequireSecureExposure("0.0.0.0:2050"); err != nil {
		t.Fatalf("cert+key (real TLS) should be allowed: %v", err)
	}
}
