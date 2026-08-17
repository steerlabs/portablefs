//go:build linux

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// authorizedSession is the part of the authority client renewal owns: which
// session the authority admitted, how long its signed authorization lasts, and
// the one call that replaces it. The mount holds the client directly, so a
// renewal reaches the live session through the session itself; there is no
// second process and no control socket in the path.
type authorizedSession interface {
	AuthorizationSessionID() volumeserver.SessionID
	InitialAuthorizationDeadline() time.Time
	Reauthorize(context.Context, []byte, uint64) (time.Time, error)
}

// credentialRenewal is the running renewal for one mount. Failed reports the
// single terminal verdict: the renewer could not install the next
// authorization before its safe cutoff, so the mount must be withdrawn while
// the authorization it still holds is valid, rather than left to be fenced
// mid-operation when the deadline passes.
type credentialRenewal struct {
	failed chan error
	stop   context.CancelFunc
	done   chan struct{}
}

// startCredentialRenewal renews this mount's authorization from the same
// capability file the mount was started with.
//
// It is unconditional. A mount whose credential file is never rotated fails
// closed at the renewer's cutoff exactly as a mount with no renewal fails at
// its deadline, so there is no configuration in which renewal is off and
// nothing to get wrong; a mount whose file is rotated keeps running. The
// authority assigns the session, the credential manager mints against it, and
// the mount is the only party that can present the result to its own session.
func startCredentialRenewal(session authorizedSession, capabilityFile string, attachCapability []byte) (*credentialRenewal, error) {
	if session == nil {
		return nil, errors.New("automatic renewal requires the authority session")
	}
	id := session.AuthorizationSessionID()
	if id == (volumeserver.SessionID{}) {
		return nil, errors.New("authority attach returned no reauthorization session identity")
	}
	sessionID := base64.RawURLEncoding.EncodeToString(id[:])
	deadline := session.InitialAuthorizationDeadline()
	if !deadline.After(time.Now()) {
		return nil, fmt.Errorf("authority installed authorization deadline %s, which is not in the future", deadline.UTC().Format(time.RFC3339))
	}
	source, err := mountenrollment.NewFileGrantSource(capabilityFile, attachCapability, nil)
	if err != nil {
		return nil, fmt.Errorf("bind rotating capability source: %w", err)
	}
	renewer := &mountenrollment.Renewer{
		Source:  source,
		Observe: func(status mountenrollment.RenewalStatus) { logRenewalStatus(sessionID, status) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	renewal := &credentialRenewal{failed: make(chan error, 1), stop: cancel, done: make(chan struct{})}
	log.Printf("authorization session %s expires %s; write the capability for sequence 1 of this session to %s to extend it",
		sessionID, deadline.UTC().Format(time.RFC3339), capabilityFile)
	go func() {
		defer close(renewal.done)
		if err := renewer.Run(ctx, sessionID, deadline, func(ctx context.Context, capability string, sequence uint64, certificatePEM []byte) (time.Time, error) {
			if len(certificatePEM) != 0 {
				return time.Time{}, errors.New("a file-rotated capability does not carry a replacement client certificate")
			}
			return session.Reauthorize(ctx, []byte(capability), sequence)
		}); err != nil {
			renewal.failed <- err
		}
	}()
	return renewal, nil
}

// Close ends renewal and waits for it. A renewal cancelled by its owner is not
// a failure and never reports one.
func (renewal *credentialRenewal) Close() {
	if renewal == nil {
		return
	}
	renewal.stop()
	<-renewal.done
}

// logRenewalStatus is this mount's whole renewal interface to its operator: the
// session and sequence the next capability must be minted for, and the instant
// after which no capability can save this mount.
func logRenewalStatus(sessionID string, status mountenrollment.RenewalStatus) {
	deadline := status.AuthorizationDeadline.UTC().Format(time.RFC3339)
	switch {
	case !status.LastSuccess.IsZero():
		log.Printf("session %s reauthorized through sequence %d; authorization deadline %s", sessionID, status.Sequence, deadline)
	case status.ConsecutiveFailures != 0:
		log.Printf("session %s sequence %d not installed after %d attempt(s) (%s); retrying at %s, authorization deadline %s",
			sessionID, status.Sequence, status.ConsecutiveFailures, status.LastError,
			status.NextAttempt.UTC().Format(time.RFC3339), deadline)
	default:
		log.Printf("session %s awaits capability sequence %d at %s; authorization deadline %s",
			sessionID, status.Sequence, status.NextAttempt.UTC().Format(time.RFC3339), deadline)
	}
}
