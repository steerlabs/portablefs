//go:build linux

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// The provider publishes a session and its retirement edge atomically.
type authorizedSessionProvider interface {
	CurrentAuthorizationSession() (fusev3.AuthorizationSession, <-chan struct{}, error)
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
func startCredentialRenewal(provider authorizedSessionProvider, capabilityFile string, attachCapability []byte) (*credentialRenewal, error) {
	if provider == nil {
		return nil, errors.New("automatic renewal requires the authority session")
	}
	session, changed, err := provider.CurrentAuthorizationSession()
	if err != nil {
		return nil, err
	}
	validate := func(session fusev3.AuthorizationSession) error {
		if session == nil || session.AuthorizationSessionID() == (volumeserver.SessionID{}) {
			return errors.New("authority attach returned no reauthorization session identity")
		}
		if !session.InitialAuthorizationDeadline().After(time.Now()) {
			return fmt.Errorf("authority installed expired authorization deadline %s", session.InitialAuthorizationDeadline())
		}
		return nil
	}
	if err := validate(session); err != nil {
		return nil, err
	}
	// Validate the source synchronously; every replacement needs a fresh pin.
	if _, err := mountenrollment.NewFileGrantSource(capabilityFile, attachCapability, nil); err != nil {
		return nil, fmt.Errorf("bind rotating capability source: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	renewal := &credentialRenewal{failed: make(chan error, 1), stop: cancel, done: make(chan struct{})}
	go func() {
		defer close(renewal.done)
		for ctx.Err() == nil {
			source, sourceErr := mountenrollment.NewFileGrantSource(capabilityFile, attachCapability, nil)
			if sourceErr != nil {
				renewal.failed <- sourceErr
				return
			}
			id := session.AuthorizationSessionID()
			sessionID := base64.RawURLEncoding.EncodeToString(id[:])
			deadline := session.InitialAuthorizationDeadline()
			log.Printf("authorization session %s expires %s; write the capability for sequence 1 of this session to %s to extend it", sessionID, deadline.UTC().Format(time.RFC3339), capabilityFile)
			renewer := &mountenrollment.Renewer{Source: source, Observe: func(event mountenrollment.RenewalEvent) { logRenewalEvent(sessionID, event) }}
			child, stop := context.WithCancel(ctx)
			result := make(chan error, 1)
			exact := session
			go func() {
				result <- renewer.Run(child, sessionID, deadline, func(ctx context.Context, capability string, sequence uint64, certificatePEM []byte) (time.Time, error) {
					if len(certificatePEM) != 0 {
						return time.Time{}, errors.New("a file-rotated capability does not carry a replacement client certificate")
					}
					return exact.Reauthorize(ctx, []byte(capability), sequence)
				})
			}()
			var runErr error
			select {
			case <-ctx.Done():
				stop()
				<-result
				return
			case <-changed:
				stop()
				<-result
			case runErr = <-result:
				stop()
			}
			if ctx.Err() != nil {
				return
			}
			// A closed retirement edge wins even when an old call failed concurrently.
			select {
			case <-changed:
				session, changed, err = provider.CurrentAuthorizationSession()
				if err == nil {
					err = validate(session)
				}
				if err != nil {
					renewal.failed <- err
					return
				}
			default:
				if runErr != nil {
					renewal.failed <- runErr
				}
				return
			}
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

// logRenewalEvent is this mount's whole renewal interface to its operator: the
// session and sequence the next capability must be minted for, and the instant
// after which no capability can save this mount.
func logRenewalEvent(sessionID string, event mountenrollment.RenewalEvent) {
	status := event.Status
	deadline := status.AuthorizationDeadline.UTC().Format(time.RFC3339)
	switch event.Kind {
	case mountenrollment.RenewalSucceeded:
		log.Printf("session %s reauthorized through sequence %d; authorization deadline %s", sessionID, status.Sequence, deadline)
	case mountenrollment.RenewalRetrying:
		log.Printf("session %s sequence %d not installed after %d attempt(s) (%s); retrying at %s, authorization deadline %s",
			sessionID, status.Sequence, status.ConsecutiveFailures, status.LastError,
			status.NextAttempt.UTC().Format(time.RFC3339), deadline)
	case mountenrollment.RenewalScheduled:
		log.Printf("session %s awaits capability sequence %d at %s; authorization deadline %s",
			sessionID, status.Sequence, status.NextAttempt.UTC().Format(time.RFC3339), deadline)
	case mountenrollment.RenewalDenied, mountenrollment.RenewalCutoff:
		log.Printf("session %s renewal ended at sequence %d (%s); authorization deadline %s",
			sessionID, status.Sequence, status.LastError, deadline)
	case mountenrollment.RenewalStopped:
		log.Printf("session %s renewal stopped at sequence %d; authorization deadline %s", sessionID, status.Sequence, deadline)
	default:
		log.Printf("session %s emitted unknown renewal event %q at sequence %d; authorization deadline %s",
			sessionID, event.Kind, status.Sequence, deadline)
	}
}
