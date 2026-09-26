//go:build linux

package fusev3

import (
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"time"
)

// AuthorizationSession binds renewal to one exact authority session. Its calls
// never follow an epoch replacement; the owner must discard results after the
// associated change channel closes and start the replacement at sequence one.
type AuthorizationSession interface {
	AuthorizationSessionID() volumeserver.SessionID
	InitialAuthorizationDeadline() time.Time
	Reauthorize(context.Context, []byte, uint64) (time.Time, error)
}

func (m *Mount) CurrentAuthorizationSession() (AuthorizationSession, <-chan struct{}, error) {
	e := m.rpc.(*epochRPC)
	e.mu.RLock()
	defer e.mu.RUnlock()
	session, ok := e.rpc.(AuthorizationSession)
	if !ok {
		return nil, nil, errors.New("fusev3: transport has no authorization session")
	}
	return session, e.authorizationChanged, nil
}
