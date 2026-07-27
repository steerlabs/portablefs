package secure

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// maxTokenLen bounds the handshake token a server will read, so a hostile peer
// cannot drive an unbounded allocation before authenticating.
const maxTokenLen = 4096

// handshakeTimeout bounds how long a side waits on the auth exchange. A legit
// handshake is a few bytes (~1 round trip, sub-second even on a slow WAN), so this
// is generous; it exists so a peer that connects and stalls — or a protocol
// mismatch (e.g. plaintext to a TLS port) — is rejected instead of tying up a
// goroutine indefinitely.
const handshakeTimeout = 5 * time.Second

// AuthToken is the shared secret for the data-plane handshake (custom FUSE
// protocol + replication), from VCS_AUTH_TOKEN. Empty means no application-level
// auth (acceptable only on a loopback bind or behind a separate authenticated
// tunnel — see RequireSecureExposure).
func AuthToken() string { return os.Getenv("VCS_AUTH_TOKEN") }

// AdminToken is the CONTROL-PLANE secret for the lifecycle admin API
// (/v1/ops/*), from VCS_ADMIN_TOKEN. It is deliberately distinct from the
// data-plane AuthToken: a leaked/shared mount credential must never authorize
// quiescing the volume, and the admin credential must never authenticate a
// mount. The authority manager mints a fresh admin token per authority
// instance identity, so the credential rotates with every replacement.
func AdminToken() string { return os.Getenv("VCS_ADMIN_TOKEN") }

// ErrAuthRejected is the peer's DEFINITE refusal of the presented credential:
// the dial completed and the peer answered the handshake with a rejection
// byte. That is an authentication outcome from a REACHABLE peer, not a
// transport failure — reachability trackers must not count it toward an
// unreachability verdict (an expired-but-renewable credential would otherwise
// masquerade as a dead authority).
var ErrAuthRejected = errors.New("secure: authentication rejected by peer")

// ClientHandshake sends token as the first frame on conn (an empty token sends a
// zero-length frame) and waits for the server's accept byte. The exchange is
// ALWAYS performed — even with no token — so the two sides never deadlock on an
// asymmetric no-op (a token-requiring server waiting for a frame a tokenless
// client never sends).
//
// Wire: [2-byte big-endian len][token bytes] -> [1-byte status] (0 = accepted).
func ClientHandshake(conn net.Conn, token string) error {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(token)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(token) > 0 {
		if _, err := conn.Write([]byte(token)); err != nil {
			return err
		}
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		return err
	}
	if ack[0] != 0 {
		return ErrAuthRejected
	}
	return nil
}

// ServerHandshake reads and constant-time-verifies the client's token frame
// (always — even when no token is configured, so an unauthenticated client is
// rejected immediately rather than hanging the read). On any mismatch it signals
// rejection and returns an error; the caller must then close the connection.
func ServerHandshake(conn net.Conn, token string) error {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if int(n) > maxTokenLen {
		_, _ = conn.Write([]byte{1})
		return errors.New("secure: oversize handshake token")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(buf, []byte(token)) != 1 {
		_, _ = conn.Write([]byte{1})
		return errors.New("secure: invalid handshake token")
	}
	_, err := conn.Write([]byte{0})
	return err
}

// RequireSecureExposure fails when addr binds a non-loopback interface without any
// gate — no TLS (VCS_TLS_CERT) and no token (VCS_AUTH_TOKEN). A data-plane port
// reachable from the network must be authenticated or encrypted; loopback binds
// are exempt (local clients / a separate tunnel).
func RequireSecureExposure(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if IsLoopbackBind(host) {
		return nil // loopback only — not network-reachable
	}
	// TLS only actually protects the listener when BOTH cert AND key are set (see
	// ServerTLS) — a cert without a key silently yields a PLAINTEXT listener, so gate
	// on the same both-set condition rather than the cert alone.
	tlsConfigured := os.Getenv("VCS_TLS_CERT") != "" && os.Getenv("VCS_TLS_KEY") != ""
	if tlsConfigured || AuthToken() != "" {
		return nil
	}
	return fmt.Errorf(
		"refusing to serve %s on a non-loopback address with no TLS (set VCS_TLS_CERT/VCS_TLS_KEY) "+
			"and no token (set VCS_AUTH_TOKEN); bind 127.0.0.1 or configure one",
		addr,
	)
}

// IsLoopbackBind reports whether host binds only the loopback interface and is thus
// not reachable from the network. Critically, the empty host and the unspecified
// addresses ("0.0.0.0", "::") bind ALL interfaces — they are network-reachable and
// must NOT be treated as loopback (the ":2050" form parses to an empty host, which
// previously slipped through the exemption and exposed the data plane unauthed).
// Any host we cannot positively classify as loopback fails closed (treated as
// reachable, so TLS or a token is required).
func IsLoopbackBind(host string) bool {
	switch host {
	case "", "0.0.0.0", "::":
		return false // all interfaces — network-reachable
	case "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
