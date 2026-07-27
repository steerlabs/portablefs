package fsproto

// Reconnect-storm hygiene for the dial path.
//
// Mounts reach their authority through the manager's TCP data-plane router,
// which answers the client's token frame with a single ack byte: 0 admits the
// tunnel, 1 rejects the session token and closes. Session tokens are HMACs
// keyed per (manager epoch, token generation), so a manager restart or a lease
// rotation invalidates every outstanding token at once. Redialing with the
// same token can therefore never succeed — the ONLY fix is re-resolving the
// mount session for a fresh credential. This file gives the dial path the two
// pieces that make that safe at fleet scale: a typed rejection error, and a
// single-flight credential re-resolve so N pooled connections observing the
// same rejection coalesce into one manager round-trip.

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// ErrSessionTokenRejected reports that the remote end explicitly rejected this
// client's session token during the dial handshake — the router's ack byte 1,
// or a clean close right after the token frame before any ack. It is a
// credential failure, not a network failure: the token is dead (manager
// restart, lease rotation, revocation) and every redial with it will be
// rejected too. Callers holding a credential source re-resolve the mount
// session and retry with the fresh token; callers with a static token surface
// the error.
var ErrSessionTokenRejected = errors.New("fsproto: session token rejected by data-plane router")

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
		return ErrSessionTokenRejected
	}
	return nil
}

// SetOnTokenRejected installs the credential re-resolver invoked when a dial's
// token frame is explicitly rejected (ErrSessionTokenRejected). fn re-resolves
// the mount session against the manager — the same ladder the lease keeper
// uses at renewal time — installs the fresh token into this client's token
// source, and reports whether a retry now has a fresh credential to use.
// Concurrent rejections are coalesced client-side (see refreshRejectedToken);
// fn itself runs one call at a time. Set once at mount time, before traffic.
func (c *Client) SetOnTokenRejected(fn func() bool) {
	c.refreshMu.Lock()
	c.onTokenRejected = fn
	if c.refreshBackoff == nil {
		// Clients built outside dialPool (tests, embedders) still get the
		// failure pacing.
		c.refreshBackoff = NewBackoff(DefaultReconnectBase, DefaultReconnectCap)
	}
	c.refreshMu.Unlock()
}

// refreshRejectedToken coalesces concurrent "my token was rejected" signals
// into one credential re-resolve. observedGen is the refresh generation read
// BEFORE the rejected dial fetched its token: if another goroutine completed a
// re-resolve since, the fresh credential is already installed and the caller
// just retries — this is what turns N pooled connections hitting the same
// dead token into exactly ONE manager round-trip. Returns true when a retry
// has a fresh credential to use.
//
// Resolver invocations are paced by a full-jitter backoff window armed after
// EVERY invocation — failed (manager still down) or "succeeded" while the
// router still rejects the fresh token (mid-restart split) — and cleared only
// when a dial actually lands (noteDialSuccess). Rejections inside the window
// return false immediately instead of hammering the manager at op rate, and
// the next rejection after the window retries — the mount keeps trying on the
// decaying schedule without ever wedging.
func (c *Client) refreshRejectedToken(observedGen uint64) bool {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if c.refreshGen.Load() != observedGen {
		return true
	}
	if c.onTokenRejected == nil {
		return false
	}
	if !c.refreshWait.IsZero() && time.Now().Before(c.refreshWait) {
		return false
	}
	ok := c.onTokenRejected()
	c.refreshWait = time.Now().Add(c.refreshBackoff.Next())
	if ok {
		c.refreshGen.Add(1)
	}
	return ok
}

// noteDialSuccess records that a dial+handshake landed: the pool's shared
// redial backoff AND the credential re-resolve pacing both restart from
// scratch, so the next incident recovers as fast as the first. Nil-tolerant
// for clients assembled outside dialPool (tests, embedders).
func (c *Client) noteDialSuccess() {
	if c.redial != nil {
		c.redial.Reset()
	}
	c.refreshMu.Lock()
	c.refreshWait = time.Time{}
	if c.refreshBackoff != nil {
		c.refreshBackoff.Reset()
	}
	c.refreshMu.Unlock()
}
