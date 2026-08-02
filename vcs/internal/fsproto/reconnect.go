package fsproto

// Reconnect-storm hygiene for the dial path.
//
// Mounts reach their authority through the manager's TCP data-plane router,
// which answers the client's token frame with a single ack byte. The dial path
// CLASSIFIES that answer so callers can surface it without probing another
// resolution path — and, since round 18d, so that four unrelated conditions
// stop being reported as one.
//
// ── ONE ACK BYTE HELD FOUR DIFFERENT ANSWERS ─────────────────────────────────
//
// The router answered ack 1 for every refusal it could make:
//
//	1. the session token did not resolve (manager restart, lease rotation,
//	   release, revoke, expiry) — a genuine, terminal credential death;
//	2. the lease was at its tunnel limit (maxTunnelsPerLease, default 64) or the
//	   router was at its global limit — capacity, retryable, nothing to do with
//	   the credential;
//	3. the lease ended or rotated between the token check and the registration
//	   of the admitted tunnel — a transition race, retryable;
//	4. the reservation could not be consumed (the client or backend socket died
//	   during the backend dial, or a rotation sweep took the reservation) —
//	   also a race.
//
// The client treated ANY nonzero ack as proof that the credential was dead, so
// it LATCHED a terminal credential verdict and told the operator "lease expired
// or revoked; run `portablefs login`". Measured live: a mount latched that
// message with FOUR AND A HALF MINUTES of lease validity left, and re-login was
// not the remedy — the mount needed to be remounted, or simply to wait for a
// tunnel slot. The classification could not be fixed on the client, because the
// four conditions were indistinguishable on the wire. So the wire says which.
//
// ── COMPATIBILITY ────────────────────────────────────────────────────────────
//
// The frame shape is unchanged: [2-byte len][token] -> [1 ack byte]. Only the
// ack VOCABULARY grew, and it grew in the refusal range, so both mixed
// directions degrade to exactly today's behaviour rather than to a new one:
//
//   - OLD client, NEW router: an old client's rule is "ack != 0 means the
//     credential was refused". Codes 2-4 therefore latch a credential verdict —
//     which is precisely what ack 1 already did for those same conditions. An
//     old client is no less correct than it is today, and there is no code it
//     would newly ADMIT: zero still means, and only ever means, admitted.
//   - NEW client, OLD router: an old router only ever emits 0 or 1, and 1 keeps
//     its exact old meaning here (terminal credential refusal). Correct for the
//     genuine case, and identical to today for the rest.
//   - NEW client, FUTURE router: an unrecognized refusal code is a refusal that
//     makes NO credential claim (ErrDialRefusedUnclassified). A later code can
//     therefore be added without a client of this vintage inventing a terminal
//     verdict for it.
//
// The improvement itself — a capacity refusal no longer latching a credential
// verdict — is realized when the manager and the daemon ship together, which
// the pfslocal/fsproto version discipline already requires.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Data-plane router ack vocabulary. This is a WIRE CONTRACT shared with
// apps/authority-manager/src/data-plane-router.ts (AckCode); the two lists must
// be changed together.
const (
	// ackAdmitted: the tunnel is open. Zero has always meant this and always
	// will — every other value is a refusal.
	ackAdmitted = 0
	// ackCredentialRejected: the session token did not resolve. TERMINAL. This
	// is the only code entitled to a credential verdict.
	ackCredentialRejected = 1
	// ackAtCapacity: the lease is at maxTunnelsPerLease, or the router is at
	// maxOpenTunnels. RETRYABLE, and says nothing about the credential.
	ackAtCapacity = 2
	// ackLeaseTransition: the lease ended or rotated its token generation
	// during this handshake. RETRYABLE with a freshly resolved credential.
	ackLeaseTransition = 3
	// ackAuthorityUnavailable: the router admitted the credential but could
	// reach no backend authority. RETRYABLE; a transport-class condition
	// behind the router, not a credential one.
	ackAuthorityUnavailable = 4
)

// ErrDialRefused is the umbrella for "the peer refused this dial pass". It is
// NOT a statement about the credential — see ErrCredentialRefused for the only
// form that is. What every wrapper shares is the retry contract: the peer
// ANSWERED, so this is not unreachability and must never trip the transport
// breaker (see failfast.go); and every address in the list carries the same
// credential, so the dial pass ends here rather than adding to the storm.
//
// It kept its old identity ErrSessionTokenRejected for one release so callers
// outside this file can migrate; that alias is a lie by name and is going away.
var ErrDialRefused = errors.New("fsproto: data-plane router refused the dial")

// ErrSessionTokenRejected is the previous name of ErrDialRefused.
//
// Deprecated: it claims a session-token verdict the umbrella never carried.
// Use ErrDialRefused, or one of the specific refusals below.
var ErrSessionTokenRejected = ErrDialRefused

// ErrCredentialRefused is the ONLY refusal that speaks about the credential:
// the peer read the token frame and answered ack 1, meaning the token did not
// resolve at all. It is the only form strong enough to latch a terminal,
// operator-facing credential verdict, and the only one whose remedy is
// `portablefs login` plus a remount.
//
// The clean-EOF form — a connection closed after the token frame and before any
// ack — is a REDIAL heuristic, not proof. A router restarting, a manager
// rolling, or an authority shutting down mid-handshake all produce it, and
// treating it as "your credential is dead" told operators to fix a credential
// that was fine. It ends the dial pass and stays off the transport breaker; it
// simply makes no claim about the credential.
var ErrCredentialRefused = fmt.Errorf("%w: the credential was rejected", ErrDialRefused)

// ErrTunnelCapacity: the lease already holds the maximum number of concurrent
// data-plane tunnels the manager permits (maxTunnelsPerLease, default 64), or
// the router is at its global tunnel ceiling. RETRYABLE. Re-authenticating
// cannot help — a fresh credential lands on the same full lease — and neither
// can remounting the same volume, which needs a tunnel of its own. What helps
// is fewer concurrent tunnels on this lease, or a higher server-side limit.
var ErrTunnelCapacity = fmt.Errorf(
	"%w: the lease is at its concurrent data-plane tunnel limit", ErrDialRefused)

// ErrLeaseTransition: the access lease ended or rotated its token generation
// while this handshake was in flight, so the tunnel was refused rather than
// admitted onto a superseded generation. RETRYABLE. The credential the mount
// holds may already be stale; a remount resolves a current one. Re-login is
// only the remedy if the lease is genuinely gone, which THIS answer does not
// claim — the next dial with a current credential will say.
var ErrLeaseTransition = fmt.Errorf(
	"%w: the access lease ended or rotated during the handshake", ErrDialRefused)

// ErrRouterBackendUnavailable: the router accepted the credential and could
// reach no backend authority for it. RETRYABLE, and a transport-class condition
// on the far side of the router — nothing the operator's credentials or mount
// can fix.
var ErrRouterBackendUnavailable = fmt.Errorf(
	"%w: the router reached no backend authority", ErrDialRefused)

// ErrDialRefusedUnclassified: a refusal code this client does not know, which
// is what a NEWER router's new code looks like from here. It is a refusal that
// makes no claim about anything, which is the only safe reading of a byte whose
// meaning has not shipped yet.
var ErrDialRefusedUnclassified = fmt.Errorf("%w: unrecognized refusal", ErrDialRefused)

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
//   - ack 1..4: the peer refused, and said WHY (see the ack vocabulary above);
//     only ack 1 is a credential verdict;
//   - any other ack: a refusal from a newer peer, classified as such and
//     claiming nothing;
//   - clean EOF before any ack: the router tore the connection down after
//     reading the token frame without admitting it — a refusal, because an
//     admitted tunnel always acks 0 first, but not a credential verdict;
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
			return fmt.Errorf("%w: the peer closed before answering", ErrDialRefused)
		}
		return err
	}
	return classifyRouterAck(ack[0])
}

// classifyRouterAck maps one ack byte to the exact fact it carries.
func classifyRouterAck(ack byte) error {
	switch ack {
	case ackAdmitted:
		return nil
	case ackCredentialRejected:
		return ErrCredentialRefused
	case ackAtCapacity:
		return ErrTunnelCapacity
	case ackLeaseTransition:
		return ErrLeaseTransition
	case ackAuthorityUnavailable:
		return ErrRouterBackendUnavailable
	default:
		return fmt.Errorf("%w (ack byte %d)", ErrDialRefusedUnclassified, ack)
	}
}

// RefusalRemedy renders the operator-facing sentence for a dial refusal: what
// happened, and the action that can actually change it.
//
// It exists because every one of these conditions used to render as "lease
// expired or revoked; run `portablefs login`", and for three of the four that
// instruction repairs something that is not broken while the real cause goes
// unmentioned. A message that names an action which cannot fix the condition is
// worse than no message: it spends the outage.
//
// It returns "" for anything that is not a refusal, so callers can use it as
// the test for "is there a router verdict to report".
func RefusalRemedy(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrCredentialRefused):
		return "the authority rejected this mount's access credential; " +
			"run `portablefs login` and remount"
	case errors.Is(err, ErrTunnelCapacity):
		return "the access lease is at its concurrent data-plane tunnel limit " +
			"(PORTABLEFS_AUTHORITY_ROUTER_MAX_TUNNELS_PER_LEASE, default 64); " +
			"the mount retries automatically — unmount other mounts sharing this " +
			"lease, or raise the server-side limit. Re-authenticating does not " +
			"change this"
	case errors.Is(err, ErrLeaseTransition):
		return "the access lease ended or rotated during the handshake; " +
			"the mount retries automatically with a current credential — if it " +
			"persists, remount. Re-authenticating is only the remedy once a " +
			"handshake actually reports the credential rejected"
	case errors.Is(err, ErrRouterBackendUnavailable):
		return "the manager's router accepted the credential but reached no " +
			"backend authority; this is an authority-side outage — the mount " +
			"retries automatically and no local action changes it"
	case errors.Is(err, ErrDialRefused):
		return "the manager's data-plane router refused the connection without " +
			"a recognized reason; the mount retries automatically. Check the " +
			"router's logs — this is not known to be a credential problem"
	}
	return ""
}
