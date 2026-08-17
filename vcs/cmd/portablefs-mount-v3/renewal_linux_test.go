//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type renewalSession struct {
	id       volumeserver.SessionID
	deadline time.Time

	mu        sync.Mutex
	installed []string
	sequences []uint64
	reached   chan struct{}
}

func (session *renewalSession) AuthorizationSessionID() volumeserver.SessionID { return session.id }

func (session *renewalSession) InitialAuthorizationDeadline() time.Time { return session.deadline }

func (session *renewalSession) Reauthorize(_ context.Context, token []byte, sequence uint64) (time.Time, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.installed = append(session.installed, string(token))
	session.sequences = append(session.sequences, sequence)
	claims, err := volumecap.Inspect(token)
	if err != nil {
		return time.Time{}, err
	}
	select {
	case <-session.reached:
	default:
		close(session.reached)
	}
	// The authority installs the deadline the capability itself declares.
	return time.Unix(claims.Expires, 0), nil
}

func mintRenewalCapability(t *testing.T, key ed25519.PrivateKey, sessionID string, sequence uint64, expires time.Time) []byte {
	t.Helper()
	claims := volumecap.Claims{
		VolumeID: "vol", Subject: "mount", Access: []string{"read", "write"}, Nonce: "nonce",
		NotBefore: expires.Add(-time.Hour).Unix(), Expires: expires.Unix(),
		PeerSPKI:  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		SessionID: sessionID, Sequence: sequence,
	}
	token, err := volumecap.Sign(key, claims)
	if err != nil {
		t.Fatalf("sign capability: %v", err)
	}
	return token
}

func writeRenewalCapability(t *testing.T, path string, token []byte) {
	t.Helper()
	if err := os.WriteFile(path, token, 0o600); err != nil {
		t.Fatalf("write capability: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod capability: %v", err)
	}
}

// A standalone mount schedules renewal from the moment it is mounted, against
// the authorization deadline the authority installed, and installs whatever the
// credential manager rotated into the file it was started with.
func TestStandaloneMountRenewsFromItsCapabilityFile(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate capability key: %v", err)
	}
	deadline := time.Now().Add(2 * time.Minute).Truncate(time.Second)
	session := &renewalSession{id: volumeserver.SessionID{1, 2, 3, 4}, deadline: deadline, reached: make(chan struct{})}
	sessionID := base64.RawURLEncoding.EncodeToString(session.id[:])
	path := filepath.Join(t.TempDir(), "access.token")
	attach := mintRenewalCapability(t, key, "", 0, deadline)
	writeRenewalCapability(t, path, attach)
	renewed := mintRenewalCapability(t, key, sessionID, 1, deadline.Add(10*time.Minute))
	writeRenewalCapability(t, path, renewed)

	renewal, err := startCredentialRenewal(session, path, attach)
	if err != nil {
		t.Fatalf("startCredentialRenewal: %v", err)
	}
	defer renewal.Close()
	select {
	case <-session.reached:
	case err := <-renewal.failed:
		t.Fatalf("renewal failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("renewal did not reach the session")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.sequences) != 1 || session.sequences[0] != 1 {
		t.Fatalf("sequences = %v, want the one exact first reauthorization", session.sequences)
	}
	if session.installed[0] != string(renewed) {
		t.Fatal("the mount installed something other than the rotated capability")
	}
}

// Nothing rotated the file, so renewal ends the mount at the renewer's cutoff,
// while the authorization the mount holds is still valid.
func TestStandaloneMountFailsClosedWhenNothingRotatesTheFile(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate capability key: %v", err)
	}
	deadline := time.Now().Add(6 * time.Second)
	session := &renewalSession{id: volumeserver.SessionID{9}, deadline: deadline, reached: make(chan struct{})}
	path := filepath.Join(t.TempDir(), "access.token")
	attach := mintRenewalCapability(t, key, "", 0, deadline)
	writeRenewalCapability(t, path, attach)

	renewal, err := startCredentialRenewal(session, path, attach)
	if err != nil {
		t.Fatalf("startCredentialRenewal: %v", err)
	}
	defer renewal.Close()
	select {
	case err := <-renewal.failed:
		if !strings.Contains(err.Error(), "safe cutoff") {
			t.Fatalf("err = %v, want the renewer's safe-cutoff refusal", err)
		}
		if remaining := time.Until(deadline); remaining <= 0 {
			t.Fatalf("renewal gave up %s after the authorization deadline; it must give up before it", -remaining)
		}
	case <-session.reached:
		t.Fatal("an unrotated file produced a grant")
	case <-time.After(20 * time.Second):
		t.Fatal("renewal never failed closed")
	}
}

func TestStandaloneRenewalRequiresASessionAndAnUnexpiredAuthorization(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate capability key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "access.token")
	attach := mintRenewalCapability(t, key, "", 0, time.Now().Add(time.Minute))
	writeRenewalCapability(t, path, attach)
	if _, err := startCredentialRenewal(&renewalSession{deadline: time.Now().Add(time.Minute), reached: make(chan struct{})}, path, attach); err == nil {
		t.Fatal("renewal without a reauthorization session identity must be refused")
	}
	expired := &renewalSession{id: volumeserver.SessionID{5}, deadline: time.Now().Add(-time.Second), reached: make(chan struct{})}
	if _, err := startCredentialRenewal(expired, path, attach); err == nil {
		t.Fatal("renewal of an already expired authorization must be refused")
	}
}
