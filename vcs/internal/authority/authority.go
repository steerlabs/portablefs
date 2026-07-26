// Package authority holds a volume's single write authority for the lifetime of
// a VCS: one fenced, exclusive lease, acquired at startup and renewed, used for
// every commit. The backend's exclusive-lease model means a second VCS cannot
// acquire the same volume (no split-brain), and the fencing token makes a stale
// VCS's commits fail after it has been superseded.
package authority

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
)

// DefaultLeaseTTLMs is the lease lifetime; the VCS renews well within it.
const DefaultLeaseTTLMs = 10 * 60 * 1000

// Backend is the volume-api surface an Authority depends on (*backend.Client
// satisfies it). Narrowing to an interface lets the failover poll be tested
// without real infra.
type Backend interface {
	Attach(ctx context.Context, volumeID, branch, holderID string, leaseTtlMs int64) (*backend.AttachResult, error)
	AttachReceipted(ctx context.Context, volumeID, branch, holderID string, leaseTtlMs int64, operationID string) (*backend.AttachResult, error)
	Commit(ctx context.Context, sessionID string, in backend.CommitInput) (string, error)
	Detach(ctx context.Context, sessionID string) error
	RenewLease(ctx context.Context, leaseID string, fencingToken, leaseTtlMs int64) error
	PutBlob(ctx context.Context, digest string, data []byte) error
}

// Authority is a held write lease + the locally-tracked branch head. Because the
// VCS is the sole writer of record, the head only advances via its own commits,
// so tracking it locally is correct.
type Authority struct {
	client Backend

	mu           sync.Mutex
	sessionID    string
	leaseID      string
	fencingToken int64
	version      string
	head         string
	ttlMs        int64
}

// Acquire opens the exclusive write session/lease. It fails if another VCS
// already holds the volume.
func Acquire(ctx context.Context, client Backend, volumeID, branch, holderID string, ttlMs int64) (*Authority, error) {
	if ttlMs <= 0 {
		ttlMs = DefaultLeaseTTLMs
	}
	att, err := client.Attach(ctx, volumeID, branch, holderID, ttlMs)
	if err != nil {
		return nil, err
	}
	return &Authority{
		client:       client,
		sessionID:    att.SessionID,
		leaseID:      att.LeaseID,
		fencingToken: att.FencingToken,
		version:      att.ManifestVersion,
		head:         att.HeadCommitID,
		ttlMs:        ttlMs,
	}, nil
}

// AcquireWhenFree blocks until it can take the exclusive lease, polling while the
// volume is still held by a live primary (IsLeaseBusy). It returns as soon as the
// lease is acquired — the standby's signal to promote itself to primary — or with
// a hard error / ctx cancellation. The backend's fencing token ensures a stale
// primary that returns can no longer commit, so taking over here is safe.
func AcquireWhenFree(ctx context.Context, client Backend, volumeID, branch, holderID string, ttlMs int64, poll time.Duration) (*Authority, error) {
	for {
		auth, err := Acquire(ctx, client, volumeID, branch, holderID, ttlMs)
		if err == nil {
			return auth, nil
		}
		if !backend.IsLeaseBusy(err) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// AcquireReceiptedWhenFree is the MANAGED acquire: the receipted attach route
// with one retry-stable operation id for the whole wait. It polls while the
// exclusive lease is busy (the predecessor is still draining) and while the
// response is ambiguous (transport failure, timeout, 5xx — the attach may
// have landed with its response lost; the same operation id replays the
// exact outcome instead of orphaning a lease). A definitive rejection other
// than lease-busy (403, 404, 409 branch-mode conflicts) returns immediately.
func AcquireReceiptedWhenFree(ctx context.Context, client Backend, volumeID, branch, holderID string, ttlMs int64, poll time.Duration) (*Authority, error) {
	if ttlMs <= 0 {
		ttlMs = DefaultLeaseTTLMs
	}
	operationID, err := newAttachOperationID()
	if err != nil {
		return nil, err
	}
	if poll <= 0 {
		poll = time.Second
	}
	for {
		att, attachErr := client.AttachReceipted(ctx, volumeID, branch, holderID, ttlMs, operationID)
		if attachErr == nil {
			return &Authority{
				client:       client,
				sessionID:    att.SessionID,
				leaseID:      att.LeaseID,
				fencingToken: att.FencingToken,
				version:      att.ManifestVersion,
				head:         att.HeadCommitID,
				ttlMs:        ttlMs,
			}, nil
		}
		if backend.IsDefinitiveRejection(attachErr) && !backend.IsLeaseBusy(attachErr) {
			return nil, attachErr
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

func newAttachOperationID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("create attach operation id: %w", err)
	}
	return "pfa_" + hex.EncodeToString(random[:]), nil
}

// Version is the manifest version to stamp on commits.
func (a *Authority) Version() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.version
}

// Head is the current branch head (advanced by our own commits).
func (a *Authority) Head() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.head
}

// PutBlob uploads a content-addressed blob.
func (a *Authority) PutBlob(ctx context.Context, digest string, data []byte) error {
	return a.client.PutBlob(ctx, digest, data)
}

// Commit advances the head using the held session/lease + fencing token.
func (a *Authority) Commit(ctx context.Context, treeHash string, entries []backend.ManifestEntry, mutationCount, byteCount int64) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	newHead, err := a.client.Commit(ctx, a.sessionID, backend.CommitInput{
		ExpectedHeadCommitID: a.head,
		LeaseID:              a.leaseID,
		FencingToken:         a.fencingToken,
		Manifest:             backend.Manifest{Version: a.version, TreeHash: treeHash, Entries: entries},
		MutationCount:        mutationCount,
		ByteCount:            byteCount,
	})
	if err != nil {
		return "", err
	}
	a.head = newHead
	return newHead, nil
}

// Renew extends the lease.
func (a *Authority) Renew(ctx context.Context) error {
	a.mu.Lock()
	lease, token, ttl := a.leaseID, a.fencingToken, a.ttlMs
	a.mu.Unlock()
	return a.client.RenewLease(ctx, lease, token, ttl)
}

// Release detaches the session and releases the lease.
func (a *Authority) Release(ctx context.Context) error {
	a.mu.Lock()
	sess := a.sessionID
	a.mu.Unlock()
	return a.client.Detach(ctx, sess)
}

// LeaseID names the exact write lease this authority holds, so lifecycle
// operations can prove THIS lease (not a replacement's) was released.
func (a *Authority) LeaseID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.leaseID
}

// SessionID names the attach session bound to the held lease. The remote
// journal cross-checks it in SQL so a claim can never mix sessions and leases
// from different attach cycles.
func (a *Authority) SessionID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionID
}

// FencingToken is the branch writer fence issued with the lease: the single
// monotonic writer clock. The remote journal stores it as the generation's
// writer fence; a claim presenting a lower token is stale and refused.
func (a *Authority) FencingToken() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fencingToken
}
