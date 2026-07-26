package workfs

import (
	"context"
	"fmt"
	"sync"
)

// admissionGate is the reusable mutation-admission primitive behind Seal: every
// mutating operation enters the gate before it buffers anything and exits only
// after its FULL acknowledgement boundary (WAL fsync + replication via
// CommitThrough, then the invalidation publish) — not merely after releasing
// fs.mu. Sealing closes admission (later entrants fail with ErrSealed before
// they can buffer, apply, or acknowledge anything) and then WAITS for every
// already-admitted operation to drain through that boundary. So when
// SealAndDrain returns:
//
//   - no mutation is in flight anywhere — not between fs.mu release and
//     wal.CommitThrough, not inside an ApplyBatch group commit, not in an
//     fsproto/NFS/billy handler's FS call;
//   - every acknowledged mutation is applied, WAL-durable, and replicated;
//   - the WAL has no unflushed tail, so a following checkpoint barrier never
//     needs the replication channel again.
//
// The same gate serves quiesce (lifecycle.Controller), graceful eviction
// (lifecycle.Controller.Evict), and manager-driven teardown — one admission
// mechanism, not three ad-hoc ones.
type admissionGate struct {
	mu       sync.Mutex
	sealed   bool
	inflight int
	waiters  []chan struct{} // closed when sealed && inflight == 0
}

// enter admits one mutating operation. It never blocks: a sealed gate rejects
// with ErrSealed, an open gate admits immediately. Safe to call while holding
// fs.mu (the gate has its own mutex and no lock ordering with fs.mu).
func (g *admissionGate) enter() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return ErrSealed
	}
	g.inflight++
	return nil
}

// exit marks one admitted operation complete (call via defer at the operation's
// acknowledgement boundary). When the gate is sealed and the last in-flight
// operation exits, all drain waiters are released.
func (g *admissionGate) exit() {
	g.mu.Lock()
	g.inflight--
	var release []chan struct{}
	if g.sealed && g.inflight == 0 {
		release = g.waiters
		g.waiters = nil
	}
	g.mu.Unlock()
	for _, ch := range release {
		close(ch)
	}
}

// isSealed reports whether admission has been closed.
func (g *admissionGate) isSealed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sealed
}

// seal closes admission (idempotent) and returns a channel that is closed once
// every already-admitted operation has exited. Sealing is one-way.
func (g *admissionGate) seal() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sealed = true
	ch := make(chan struct{})
	if g.inflight == 0 {
		close(ch)
		return ch
	}
	g.waiters = append(g.waiters, ch)
	return ch
}

// Seal closes write admission permanently (the quiesce/shutdown write barrier)
// and drains every in-flight mutation through its acknowledgement boundary
// (apply + WAL fsync + replication + invalidation publish). When Seal returns
// nil:
//
//   - every mutation that was or will be acknowledged is fully applied and
//     durable (fsync'd and replicated), so a following checkpoint barrier's
//     snapshot covers exactly the acknowledged history and needs no further
//     WAL flush;
//   - every later mutation attempt fails with ErrSealed before it can buffer,
//     apply, or acknowledge.
//
// On ctx expiry the gate STAYS sealed (fail closed — admission never reopens)
// but in-flight operations may still be completing; the caller must treat the
// seal as incomplete and retry before trusting a barrier. There is deliberately
// no Unseal: a quiesced authority never serves writes again — a replacement
// authority is created through the normal ensure/start path instead.
func (fs *FS) Seal(ctx context.Context) error {
	drained := fs.admit.seal()
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("vcs: seal: in-flight mutations did not drain: %w", ctx.Err())
	}
}

// Sealed reports whether write admission has been closed by Seal.
func (fs *FS) Sealed() bool { return fs.admit.isSealed() }
