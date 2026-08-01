package fsproto

// Reconnect-storm hygiene for the dial path.
//
// Mounts reach their authority through the manager's TCP data-plane router,
// which answers the client's token frame with a single ack byte: 0 admits the
// tunnel, 1 rejects the session token and closes. Session tokens are HMACs
// keyed per (manager epoch, token generation), so a manager restart or a lease
// rotation invalidates every outstanding token at once. Redialing with the
// same token can therefore never succeed. The dial path classifies that
// terminal result so callers can surface it without probing another
// resolution path.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ErrSessionTokenRejected reports that the remote end explicitly rejected this
// client's session token during the dial handshake — the router's ack byte 1,
// or a clean close right after the token frame before any ack. It is a
// credential failure, not a network failure: the token is dead (manager
// restart, lease rotation, revocation) and every redial with it will be
// rejected too. Callers surface the error and explicitly remount.
var ErrSessionTokenRejected = errors.New("fsproto: session token rejected by data-plane router")

// ErrCredentialRefused is the EXPLICIT half of ErrSessionTokenRejected: the
// peer read the token frame and answered ack 1. It is the only form strong
// enough to latch a terminal, operator-facing credential verdict.
//
// The other form — a clean EOF before any ack — is a REDIAL heuristic, not
// proof. A router restarting, a manager rolling, or an authority shutting down
// mid-handshake all produce it, and treating it as "your credential is dead;
// run portablefs login" told operators to fix a credential that was fine. It
// still ends the dial pass and still stays off the transport breaker; it simply
// makes no claim about the credential.
var ErrCredentialRefused = fmt.Errorf("%w (peer refused the credential)", ErrSessionTokenRejected)

// dialHandshakeTimeout bounds the auth exchange on a fresh connection,
// mirroring secure.ClientHandshake's bound (a legit exchange is one round
// trip; a stalled peer must not pin the dial forever).
const dialHandshakeTimeout = 5 * time.Second

// clientHandshake performs the data-plane auth exchange on a fresh connection:
// [2-byte big-endian len][token bytes] -> [1-byte ack], the same wire shape as
// secure.ClientHandshake (which stays untouched for its other callers). It
// exists to CLASSIFY the outcome instead of flattening it to a generic error:
//
//   - ack 0: accepted;
//   - ack 1: the peer (the manager's router, or a direct authority) rejected
//     the token -> ErrSessionTokenRejected;
//   - clean EOF before any ack: the router tore the connection down after
//     reading the token frame without admitting it — treated as a rejection,
//     because an admitted tunnel always acks 0 first;
//   - anything else (timeout, reset, write failure): ordinary transport
//     failure, retried through the normal redial path.
func clientHandshake(nc net.Conn, token string) error {
	_ = nc.SetDeadline(time.Now().Add(dialHandshakeTimeout))
	defer func() { _ = nc.SetDeadline(time.Time{}) }()
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(token)))
	if _, err := nc.Write(hdr[:]); err != nil {
		return err
	}
	if len(token) > 0 {
		if _, err := nc.Write([]byte(token)); err != nil {
			return err
		}
	}
	var ack [1]byte
	if _, err := io.ReadFull(nc, ack[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return ErrSessionTokenRejected
		}
		return err
	}
	if ack[0] != 0 {
		return ErrCredentialRefused
	}
	return nil
}
