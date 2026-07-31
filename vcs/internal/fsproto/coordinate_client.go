package fsproto

// Client side of the managed (journaled) coordination protocol: lock,
// checkout, checkin, open-pin, flush, and barrier mutations ride the SAME
// exact session-slot machinery as tree mutations — one identity per decision,
// definite replies commit the identity, transport failures replay the
// IDENTICAL identity (an identity is NEVER reused after any send until a
// durable outcome or replay resolves it), and every definite status —
// EAGAIN, EBUSY, ENOENT, EDQUOT, ENOSPC included — is a durably recorded
// outcome, so a later attempt uses a fresh slot sequence. There is no
// unrecorded definite reply: when the authority cannot record durably, the
// connection drops (UNKNOWN) and the identity parks for replay.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// doCoordinate executes one coordination mutation under an exact identity.
// It mirrors doExactOnce's transport contract; EAGAIN/EBUSY are returned to
// the caller (definite, identity consumed — retries use a fresh identity at
// the caller's cadence). ctx carries the park-transfer hook, so a coordination
// identity that parks takes the caller's exclusion with it.
func (c *Client) doCoordinate(ctx context.Context, req *Request) (*Response, error) {
	if live, err := c.EnsureExactSession(); err != nil {
		return nil, err
	} else if !live {
		return &Response{Status: ESTALE}, nil
	}
	es := c.exactState()
	if es == nil || es.isFenced() {
		return &Response{Status: ESTALE}, nil
	}
	slot, seq, err := es.acquire(opTimeout)
	if err != nil {
		return nil, err
	}
	req.Env = es.envelope(slot, seq)
	if req.Owner == "" {
		req.Owner = c.owner
	}
	sent := false
	for attempt := 0; attempt < exactForegroundAttempts; attempt++ {
		resp, wasSent, rerr := c.roundtripExact(req)
		if rerr == nil {
			c.finishExact(es, slot, seq, resp)
			return resp, nil
		}
		sent = sent || wasSent
		if !sent {
			es.abort(slot)
			if es.isFenced() {
				return &Response{Status: ESTALE}, nil
			}
			return nil, rerr
		}
	}
	c.parkExact(ctx, es, slot, seq, req)
	return nil, ErrMutationUnknown
}

// doCoordinateResolved is doCoordinate for decisions whose outcome the
// caller must KNOW before proceeding (delegation acquire and release): a
// sent-but-unanswered request replays the IDENTICAL exact identity until a
// definite reply arrives, the session fences, or the client closes. It never
// hands the identity to the background replayer and returns
// ErrMutationUnknown — an unknown acquire outcome would leave the authority
// possibly holding a grant the engine does not know exists, and reinterpreting
// it as a denial (write-through) would fork the mutation lanes.
func (c *Client) doCoordinateResolved(req *Request) (*Response, error) {
	if live, err := c.EnsureExactSession(); err != nil {
		return nil, err
	} else if !live {
		return &Response{Status: ESTALE}, nil
	}
	es := c.exactState()
	if es == nil || es.isFenced() {
		return &Response{Status: ESTALE}, nil
	}
	slot, seq, err := es.acquire(opTimeout)
	if err != nil {
		return nil, err
	}
	req.Env = es.envelope(slot, seq)
	if req.Owner == "" {
		req.Owner = c.owner
	}
	sent := false
	backoff := parkRetryMin
	for {
		resp, wasSent, rerr := c.roundtripExactResolved(req)
		if rerr == nil {
			c.finishExact(es, slot, seq, resp)
			return resp, nil
		}
		sent = sent || wasSent
		if !sent {
			// Nothing ever hit a connection: the identity is provably
			// unused, so the authority holds nothing — a definite outcome.
			es.abort(slot)
			if es.isFenced() {
				return &Response{Status: ESTALE}, nil
			}
			return nil, rerr
		}
		select {
		case <-es.stop:
			// Fenced with the identity unresolved: the slot retires with
			// the session; any grant it committed is bound to the fenced
			// generation and resolves through terminalization + recovery.
			return &Response{Status: ESTALE}, nil
		case <-c.closed:
			return nil, rerr
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > parkRetryMax {
			backoff = parkRetryMax
		}
	}
}

// LockManaged performs a managed (journaled, inode-keyed) lock operation.
// handleIno is the open handle's stable inode (rename/unlink stable); zero
// lets the authority resolve the path at decision time. Setlk/unlock are
// non-blocking; Setlkw blocks server-side (volatile, bounded per RPC) and
// returns a definite EAGAIN when the bounded wait expires — the caller
// re-issues at its own cadence with a fresh identity.
func (c *Client) LockManaged(path string, handleIno uint64, mode uint8, lkID, start, end uint64, write, unlock bool) (LockResult, error) {
	return c.LockManagedContext(context.Background(), path, handleIno, mode, lkID, start, end, write, unlock)
}

func (c *Client) LockManagedContext(ctx context.Context, path string, handleIno uint64, mode uint8, lkID, start, end uint64, write, unlock bool) (LockResult, error) {
	if mode == LkGetlk {
		r, err := c.DoContext(ctx, &Request{
			Op: OpLock, Path: path, HandleIno: handleIno, Owner: c.owner,
			LkMode: LkGetlk, LkID: lkID, LkStart: start, LkEnd: end, LkWrite: write,
		})
		if err != nil {
			return LockResult{Status: EIO}, err
		}
		return LockResult{Status: r.Status, Conflict: r.LkConflict, CStart: r.LkStart, CEnd: r.LkEnd, CWrite: r.LkWrite}, nil
	}
	if err := ctx.Err(); err != nil {
		return LockResult{Status: EIO}, err
	}
	resumeAuthority := beginAuthorityWait(ctx)
	defer resumeAuthority()
	resp, err := c.doCoordinate(ctx, &Request{
		Op: OpLock, Path: path, HandleIno: handleIno, Owner: c.owner,
		LkMode: mode, LkID: lkID, LkStart: start, LkEnd: end, LkWrite: write, LkUnlock: unlock,
	})
	if err != nil {
		return LockResult{Status: EIO}, err
	}
	return LockResult{Status: resp.Status}, nil
}

// CheckoutManaged acquires a managed checkout and returns its durable grant
// epoch. A definite EBUSY reports the holder (best effort) with granted=false.
func (c *Client) CheckoutManaged(path string) (granted bool, heldBy, epoch string, err error) {
	resp, err := c.doCoordinate(context.Background(), &Request{Op: OpCheckout, Path: path, Owner: c.owner})
	if err != nil {
		return false, "", "", err
	}
	switch resp.Status {
	case OK:
		return true, "", resp.CheckoutEpoch, nil
	case EBUSY:
		return false, resp.Owner, "", nil
	default:
		return false, "", "", statusError("managed checkout", resp.Status)
	}
}

// CheckinManaged releases the caller's managed checkout grant (path, epoch).
// ENOENT (not the caller's live grant) is reported as an error. The outcome
// is RESOLVED: a lost release reply replays the identical identity until the
// stored outcome answers — the caller never guesses whether the grant is
// still held.
func (c *Client) CheckinManaged(path, epoch string) error {
	resp, err := c.doCoordinateResolved(&Request{Op: OpCheckin, Path: path, CheckoutEpoch: epoch, Owner: c.owner})
	if err != nil {
		return err
	}
	if resp.Status != OK {
		return statusError("managed checkin", resp.Status)
	}
	return nil
}

// PrepareDelegationRelease durably pins an ordered batch of open paths while
// the exact delegation remains held. The returned inode vector is aligned
// with paths. Once sent, a lost reply is replayed until its exact mapping is
// known or the session terminates: neither peers nor this mount can change the
// bindings while the grant and the caller's handoff barrier remain held.
func (c *Client) PrepareDelegationRelease(path, epoch string, paths []string) ([]uint64, uint64, error) {
	if path == "" || epoch == "" || len(paths) == 0 || len(paths) > MaxPrepareOpenPaths {
		return nil, 0, fmt.Errorf("fsproto: invalid delegation prepare shape")
	}
	if live, err := c.EnsureExactSession(); err != nil {
		return nil, 0, err
	} else if !live {
		return nil, 0, ErrSessionFenced
	}
	resp, err := c.doAttachedResolved(&Request{
		Op:            OpDelegationPrepareRelease,
		Path:          path,
		CheckoutEpoch: epoch,
		OpenPaths:     append([]string(nil), paths...),
	})
	if err != nil {
		return nil, 0, err
	}
	if resp.Status != OK {
		return nil, resp.Gen, statusError("delegation prepare release", resp.Status)
	}
	if len(resp.OpenInos) != len(paths) {
		return nil, resp.Gen, fmt.Errorf(
			"fsproto: delegation prepare returned %d inodes for %d paths",
			len(resp.OpenInos), len(paths),
		)
	}
	return append([]uint64(nil), resp.OpenInos...), resp.Gen, nil
}

// FlushWriteback ships one dense global run of the mount write-back stream.
// scopes maps every record to the exact live grant authorizing it. Exactness
// rides the stream's durable watermark + digest (a lost reply resends
// identical bytes and the authority drops the covered prefix), so no slot
// identity is consumed.
func (c *Client) FlushWriteback(writebackID string, scopes []WBScope, prevDigest, endDigest [32]byte, records []wal.Record) (uint64, int32, error) {
	return c.flushWriteback(context.Background(), writebackID, scopes, prevDigest, endDigest, records, false)
}

// FlushWritebackContext is the normal flusher path. When ctx expires it
// interrupts and joins the checked-out transport before returning, so the
// single flusher remains the single authority writer even across timeouts.
func (c *Client) FlushWritebackContext(ctx context.Context, writebackID string, scopes []WBScope, prevDigest, endDigest [32]byte, records []wal.Record) (uint64, int32, error) {
	return c.flushWriteback(ctx, writebackID, scopes, prevDigest, endDigest, records, false)
}

// FlushWritebackResolved is the recovery-only form of FlushWriteback. Once
// any attempt may have reached the authority, it replays the identical
// digest-addressed batch until a definite reply, session fence, or client
// teardown. Recovery callers retain their exclusive local store lock for this
// entire call, so a possibly-sent flush never becomes a detached writer.
func (c *Client) FlushWritebackResolved(writebackID string, scopes []WBScope, prevDigest, endDigest [32]byte, records []wal.Record) (uint64, int32, error) {
	return c.flushWriteback(context.Background(), writebackID, scopes, prevDigest, endDigest, records, true)
}

func (c *Client) flushWriteback(ctx context.Context, writebackID string, scopes []WBScope, prevDigest, endDigest [32]byte, records []wal.Record, resolved bool) (uint64, int32, error) {
	req := &Request{
		Op:           OpFlushBatch,
		SessionID:    writebackID,
		Owner:        c.owner,
		WBPrevDigest: prevDigest[:],
		WBEndDigest:  endDigest[:],
		Records:      records,
		WBScopes:     scopes,
	}
	var (
		resp *Response
		err  error
	)
	if resolved {
		resp, err = c.doAttachedResolved(req)
	} else {
		resp, _, err = c.roundtripAttachedContext(ctx, req)
	}
	if err != nil {
		return 0, EIO, err
	}
	if resolved && resp.Status == ESTALE {
		return 0, EIO, ErrSessionFenced
	}
	return resp.AppliedThrough, resp.Status, nil
}

// DelegationGrant is the authority's adaptive decision for one scope.
type DelegationGrant struct {
	Granted bool
	Epoch   string
	// Exists/Self describe the scope path when it exists; HasChildren
	// carries an existing directory's authoritative snapshot. A duplicate
	// replay of a lost grant reply has neither — the caller re-seeds with
	// one readdir under the held grant.
	Exists      bool
	Self        Attr
	HasChildren bool
	Children    []Dirent
}

// DelegationAcquire asks the adaptive policy to delegate scope to this
// mount's stream. granted=false is a DEFINITE denial (run write-through and
// back off); the outcome is resolved — a lost grant reply replays the
// identical identity until the stored outcome answers, so the authority can
// never hold a grant the caller does not know exists.
func (c *Client) DelegationAcquire(scope, writebackID string) (DelegationGrant, error) {
	resp, err := c.doCoordinateResolved(&Request{Op: OpDelegationAcquire, Path: scope, SessionID: writebackID, Owner: c.owner})
	if err != nil {
		return DelegationGrant{}, err
	}
	switch resp.Status {
	case OK:
		g := DelegationGrant{Granted: true, Epoch: resp.CheckoutEpoch}
		if resp.Attr != nil {
			g.Exists = true
			g.Self = *resp.Attr
			if resp.Attr.Kind == "directory" {
				g.HasChildren = true
				g.Children = resp.Entries
			}
		}
		return g, nil
	case EBUSY, EAGAIN:
		return DelegationGrant{}, nil
	default:
		return DelegationGrant{}, statusError("delegation acquire", resp.Status)
	}
}

// WritebackState reads a stream's durable watermark + digest.
func (c *Client) WritebackState(writebackID string) (exists bool, through uint64, digest [32]byte, err error) {
	resp, err := c.doAttached(&Request{Op: OpWritebackState, SessionID: writebackID}, true)
	if err != nil {
		return false, 0, digest, err
	}
	if resp.Status != OK {
		return false, 0, digest, statusError("writeback state", resp.Status)
	}
	copy(digest[:], resp.WBDigest)
	return resp.WBExists, resp.AppliedThrough, digest, nil
}

// WritebackRebind claims a parked stream's recovery scopes under this
// session after the authority verified the stream identity and digest.
// Typed conflicts are returned without error; nothing partial commits.
func (c *Client) WritebackRebind(writebackID string, scopes []WBScope, through uint64, digest [32]byte) ([]WBConflict, error) {
	resp, err := c.doCoordinateResolved(&Request{
		Op: OpWritebackRebind, SessionID: writebackID, Owner: c.owner,
		WBScopes: scopes, WBThrough: through, WBPrevDigest: digest[:],
	})
	if err != nil {
		return nil, err
	}
	if resp.Status == OK {
		return nil, nil
	}
	if len(resp.WBConflicts) > 0 {
		return resp.WBConflicts, nil
	}
	if resp.Status == EIO {
		return nil, fmt.Errorf("fsproto: writeback rebind rejection omitted its durable typed conflicts")
	}
	return nil, statusError("writeback rebind", resp.Status)
}

// WritebackDiscard releases a parked stream's recovery scopes as an audited
// data-loss decision. Its exact outcome is resolved before return: recovery
// keeps the store lock held until the discard commits, is definitely refused,
// or the client session is terminalized.
func (c *Client) WritebackDiscard(writebackID string, scopes []WBScope) error {
	resp, err := c.doCoordinateResolved(&Request{
		Op: OpWritebackDiscard, SessionID: writebackID, Owner: c.owner, WBScopes: scopes,
	})
	if err != nil {
		return err
	}
	if resp.Status != OK {
		return statusError("writeback discard", resp.Status)
	}
	return nil
}

// MarkOpenManaged journals the durable open pin transition for ino.
// ENOENT means the inode is gone (reaped): the open must fail.
func (c *Client) MarkOpenManaged(ino uint64, open bool) (int32, error) {
	resp, err := c.doCoordinate(context.Background(), &Request{Op: OpMarkOpen, OpenIno: ino, OpenState: open, Owner: c.owner})
	if err != nil {
		return EIO, err
	}
	return resp.Status, nil
}

// unmarkOpenBatchManaged releases a batch of open pins under ONE exact
// identity (OpUnmarkOpenInodes) and does not return until that identity
// RESOLVES — the stored outcome, a fence, or client teardown. It must never
// park the identity with the background replayer: the open registry
// serializes per-ino mark/unmark transitions on this call's return, so a
// backgrounded unresolved release could execute AFTER a fresh MarkOpen of
// the same ino and strip the new pin. Blocking here keeps the registry's
// per-ino pending barrier spanning the whole resolution instead.
func (c *Client) unmarkOpenBatchManaged(req *Request) (int32, error) {
	if live, err := c.EnsureExactSession(); err != nil {
		return EIO, err
	} else if !live {
		return ESTALE, nil
	}
	es := c.exactState()
	if es == nil || es.isFenced() {
		return ESTALE, nil
	}
	slot, seq, err := es.acquire(opTimeout)
	if err != nil {
		return EIO, err
	}
	req.Env = es.envelope(slot, seq)
	if req.Owner == "" {
		req.Owner = c.owner
	}
	sent := false
	backoff := parkRetryMin
	for {
		resp, wasSent, rerr := c.roundtripExactResolved(req)
		if rerr == nil {
			c.finishExact(es, slot, seq, resp)
			return resp.Status, nil
		}
		sent = sent || wasSent
		if !sent {
			// Nothing ever hit a connection: the identity is provably unused.
			es.abort(slot)
			if es.isFenced() {
				return ESTALE, nil
			}
			return EIO, rerr
		}
		select {
		case <-es.stop:
			// Fenced with the identity unresolved: the slot retires with the
			// session, and the authority releases every pin at the terminal.
			return ESTALE, nil
		case <-c.closed:
			return EIO, rerr
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > parkRetryMax {
			backoff = parkRetryMax
		}
	}
}

// Sync is the envelope-less durability + apply barrier (per-file fsync
// semantics): it returns nil only after every journal row admitted before
// the call is durable, applied, and its invalidations are published.
func (c *Client) Sync() error {
	deadline := time.Now().Add(opTimeout)
	backoff := 100 * time.Millisecond
	for {
		r, err := c.Do(&Request{Op: OpFsync})
		if err == nil && r.Status == OK {
			return nil
		}
		if err == nil {
			return statusError("sync barrier", r.Status)
		}
		if errors.Is(err, ErrAuthorityUnreachable) {
			// Fail-fast engaged: the barrier cannot make progress against a
			// confirmed-unreachable authority, and the reachability prober (not
			// this loop) owns recovery. Surface immediately instead of spinning
			// the whole op budget re-consulting the gate.
			return err
		}
		// The barrier is idempotent (a pure wait): transport failures retry
		// within the op budget.
		if !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(backoff)
		if backoff *= 2; backoff > time.Second {
			backoff = time.Second
		}
	}
}

// SyncVolume is the VOLUME sync barrier: it (1) GATES new local mutations and
// waits for every earlier and parked exact identity to resolve by holding the
// whole slot budget, (2) submits one journaled control-only barrier row under
// an exact identity, whose ordered apply proves every earlier journal row is
// durable, applied, and published, then (3) releases the gate. Callers flush
// their write-back sessions FIRST (the flush consumes slots itself).
func (c *Client) SyncVolume() error {
	es := c.exactState()
	if es == nil {
		live, err := c.EnsureExactSession()
		if err != nil {
			return err
		}
		if !live {
			return ErrSessionFenced
		}
		es = c.exactState()
	}
	if es.isFenced() {
		return ErrSessionFenced
	}
	// GATE: acquire the whole slot budget. Every in-flight or parked
	// identity must resolve first, and no new local mutation can start.
	held := make([]uint32, 0, es.slots)
	releaseHeld := func() {
		for _, slot := range held {
			es.avail <- slot
		}
		held = held[:0]
	}
	deadline := time.NewTimer(opTimeout)
	defer deadline.Stop()
	for uint32(len(held)) < es.slots {
		select {
		case slot := <-es.avail:
			held = append(held, slot)
		case <-es.stop:
			releaseHeld()
			return ErrSessionFenced
		case <-deadline.C:
			releaseHeld()
			return statusError("volume barrier gate timed out awaiting outstanding identities", EAGAIN)
		}
	}
	defer releaseHeld()

	// The barrier identity rides one of the held slots; the gate stays
	// closed until the barrier resolves.
	slot := held[0]
	es.mu.Lock()
	seq := es.seq[slot] + 1
	es.mu.Unlock()
	req := &Request{Op: OpFsync, Env: es.envelope(slot, seq), Owner: c.owner}
	sent := false
	for attempt := 0; attempt < exactForegroundAttempts; attempt++ {
		resp, wasSent, rerr := c.roundtripExact(req)
		if rerr == nil {
			es.mu.Lock()
			es.seq[slot] = seq // consumed; the deferred release re-opens the gate
			fenced := es.fenced
			es.mu.Unlock()
			switch {
			case resp.Status == OK:
				return nil
			case resp.Status == ESTALE:
				if !fenced {
					es.fence()
				}
				return ErrSessionFenced
			default:
				return statusError("volume barrier", resp.Status)
			}
		}
		sent = sent || wasSent
		if !sent {
			return rerr
		}
	}
	// UNKNOWN: the barrier identity parks and replays; the slot must stay
	// out of the pool until it resolves, so hand it to the replayer instead
	// of the deferred release. The barrier owns no delegation-transition claim
	// of its own (its caller holds the volume lifecycle gate exclusively), so
	// there is no exclusion to transfer here; the retained slot already keeps
	// every later barrier and mutation ordered behind this identity.
	for i, s := range held {
		if s == slot {
			held = append(held[:i], held[i+1:]...)
			break
		}
	}
	c.parkExact(context.Background(), es, slot, seq, req)
	return ErrMutationUnknown
}
