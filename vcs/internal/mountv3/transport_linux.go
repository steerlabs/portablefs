//go:build linux

package mountv3

import (
	"context"
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
)

// Profile maps a coherence profile name to the two forms a mount needs: the
// frontend's kernel-cache contract and the wire declaration the authority
// sizes its barrier from. They travel together so a frontend can never mount
// with one profile while having attached with the other.
func Profile(name string) (fusev3.CoherenceProfile, authoritypb.CoherenceProfile, error) {
	switch name {
	case "strict":
		return fusev3.CoherenceStrict, authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT, nil
	case "uncached":
		return fusev3.CoherenceUncached, authoritypb.CoherenceProfile_COHERENCE_PROFILE_UNCACHED, nil
	default:
		return 0, 0, fmt.Errorf("coherence must be strict or uncached, not %q", name)
	}
}

// Transport joins the fusev3 mount frontend to the authority client. It
// exists because the two are owned separately and their contracts are not
// identical: the frontend needs a session identity and a detach that carries
// evidence, and the client's shape for those is the transport's business.
type Transport struct {
	*authorityrpc.Client
	session []byte
}

// sessionIdentified is the accessor a strict mount cannot do without. The
// authority's visibility events name their initiator by session ID, and a
// frontend that cannot tell whether an event is its own must either repair its
// own in-flight mutation -- which deadlocks against the VFS lock that syscall
// holds -- or skip repairs it owes. Neither is acceptable, so a strict mount is
// refused outright when the transport cannot supply it.
type sessionIdentified interface{ SessionID() []byte }

// NewTransport wraps an attached authority client for fusev3.MountVolume.
// profile must be the profile the client attached with.
func NewTransport(client *authorityrpc.Client, profile fusev3.CoherenceProfile) (*Transport, error) {
	transport := &Transport{Client: client}
	if identified, ok := any(client).(sessionIdentified); ok {
		transport.session = identified.SessionID()
	}
	if profile == fusev3.CoherenceStrict && len(transport.session) == 0 {
		return nil, errors.New("strict coherence needs authorityrpc.Client to expose the attach reply's session ID (SessionID() []byte); mount with coherence=uncached until it does")
	}
	return transport, nil
}

func (t *Transport) SessionID() []byte { return t.session }

// DetachAfterUnmount forwards the official supervisor's observation that its
// exact mount and serving connection are terminal. The report is refused when
// incomplete and authorityrpc binds it to this transport's current session.
func (t *Transport) DetachAfterUnmount(ctx context.Context, proof fusev3.MountAbsenceProof) error {
	if proof.ObservedUnixNanos == 0 || len(proof.Observation) == 0 || proof.Component == "" {
		return errors.New("mount absence proof is incomplete")
	}
	return t.Client.DetachAfterUnmount(ctx, &authoritypb.MountAbsenceProof{
		ObservedUnixNanos: proof.ObservedUnixNanos,
		Observation:       proof.Observation,
		Component:         proof.Component,
	})
}
