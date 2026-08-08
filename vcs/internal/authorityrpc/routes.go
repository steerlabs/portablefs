package authorityrpc

import (
	"encoding/hex"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// RoutesMismatchError is a refusal that names both sides of a routing-topology
// disagreement. An errno cannot say which two configurations disagreed, and a
// disagreement is exactly the failure a human has to fix by editing one of two
// files, so both revisions travel with the refusal.
//
// It is the same type on both sides of the wire. The authority builds one and
// encodes it; the client decodes one and returns it whole. Rendering it to a
// string at the client boundary is what an earlier revision did, and it made
// the refusal self-sufficient on the wire and useless in Go: a fresh mount is
// supposed to adopt the declaration this carries, and it cannot adopt a
// sentence. It unwraps to ErrRoutesMismatch, so a caller that only wants to
// know what kind of failure this is can still ask with errors.Is.
type RoutesMismatchError struct {
	Active    [32]byte
	Presented [32]byte
	// Declared is false when the peer sent no revision at all. Silence is not
	// agreement, so it is still a refusal; it just reads differently.
	Declared bool
	Subject  string
	// SessionRefused marks the refusal that is terminal for a mount: the
	// revision it was admitted against is no longer active.
	SessionRefused bool
	// Canonical is the volume's active declaration, carried only on an attach
	// refusal. A mount cannot read .portablefs/local-dirs without a session and
	// cannot get a session without declaring a revision; handing it the active
	// declaration is what breaks that circle without inventing a second, weaker
	// kind of session that is allowed to disagree.
	Canonical []byte
	// Detail is the authority's own rendering, kept verbatim when this error was
	// decoded from a refusal. The two peers may not be the same build, and the
	// message an operator reads should be the one the authority wrote.
	Detail string
}

func (e *RoutesMismatchError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	if !e.Declared {
		return fmt.Sprintf("%s: no routing revision declared; this volume runs %s (%s)",
			e.Subject, hex.EncodeToString(e.Active[:]), localroutes.ConfigPath)
	}
	return fmt.Sprintf("%s: mount runs routing revision %s, this volume runs %s; reconcile %s and retry",
		e.Subject, hex.EncodeToString(e.Presented[:]), hex.EncodeToString(e.Active[:]), localroutes.ConfigPath)
}

// Unwrap makes errors.Is(err, ErrRoutesMismatch) answer for the decoded error
// as well as for a formatted one, so callers that only classify keep working
// while callers that adopt can reach the payload with errors.As.
func (e *RoutesMismatchError) Unwrap() error { return ErrRoutesMismatch }

func (e *RoutesMismatchError) proto() *authoritypb.RoutesMismatch {
	mismatch := &authoritypb.RoutesMismatch{
		ActiveRevision: append([]byte(nil), e.Active[:]...),
		Detail:         e.Error(),
		SessionRefused: e.SessionRefused,
		CanonicalRules: append([]byte(nil), e.Canonical...),
	}
	if e.Declared {
		mismatch.PresentedRevision = append([]byte(nil), e.Presented[:]...)
	}
	return mismatch
}

// routesMismatchError rebuilds the refusal a peer sent. A malformed revision is
// dropped rather than guessed at: the fields it could not fill stay zero, and
// Declared says which those are, so a caller can never mistake an unparseable
// revision for a real one.
func routesMismatchError(mismatch *authoritypb.RoutesMismatch) *RoutesMismatchError {
	if mismatch == nil {
		return nil
	}
	decoded := &RoutesMismatchError{
		Detail:         mismatch.GetDetail(),
		SessionRefused: mismatch.GetSessionRefused(),
		Canonical:      append([]byte(nil), mismatch.GetCanonicalRules()...),
	}
	if raw := mismatch.GetActiveRevision(); len(raw) == len(decoded.Active) {
		copy(decoded.Active[:], raw)
	}
	if raw := mismatch.GetPresentedRevision(); len(raw) == len(decoded.Presented) {
		copy(decoded.Presented[:], raw)
		decoded.Declared = true
	}
	return decoded
}
