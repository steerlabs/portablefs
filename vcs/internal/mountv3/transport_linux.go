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
	default:
		return 0, 0, fmt.Errorf("coherence must be strict, not %q", name)
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

// NewTransport wraps an attached authority client for fusev3.MountVolume.
// authorityrpc.Client is concrete and DialClient validates the ACTIVE reply's
// session ID before returning it, so there is no fallible adapter boundary
// between an admitted session and MountVolume. Keeping a runtime interface
// assertion here used to create a nominal post-ACTIVE/pre-kernel failure path
// which could not occur for this type but still complicated exact cleanup.
func NewTransport(client *authorityrpc.Client) *Transport {
	return &Transport{Client: client, session: client.SessionID()}
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
