package portablefsd

import (
	"context"
	"errors"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

const (
	// v3CloseTokenWireBytes is one CloseRequest inside CloseBatchRequest.closes:
	// a one-byte tag and length around the nested message, whose handle field is
	// itself a one-byte tag, a one-byte length, and the 16-byte token.
	v3CloseTokenWireBytes = 20
	// v3ReclaimTokenWireBytes is one item capability inside
	// ReclaimRequest.items: a one-byte tag, a one-byte length, and the token.
	v3ReclaimTokenWireBytes = 18
	// v3ReleaseBatchTokens is B: the token budget of one work batch, closes and
	// reclaims together. It is the authority's CloseBatch bound, so one batch
	// needs at most one CloseBatch and one Reclaim.
	v3ReleaseBatchTokens = authorityrpc.MaxCloseBatch
)

// errV3ReleaseClosed refuses a reservation once release admission has closed:
// the data plane is terminal, or teardown has transferred every later token to
// the session detach. Nothing was detached under such a refusal.
var errV3ReleaseClosed = errors.New("portablefsd: release admission is closed")

// v3ReleaseLimit is B, also bounded by the negotiated encoded-frame bytes. The
// authority client admitted maxWrite payload bytes beside the request envelope
// reserve in one frame, and a close token is the larger encoding, so a batch
// whose tokens fit maxWrite as closes fits either request.
func v3ReleaseLimit(maxWrite uint32) int {
	return max(1, min(v3ReleaseBatchTokens, int(maxWrite)/v3CloseTokenWireBytes))
}

// v3ReleaseOwner is the one owner of authority release obligations on a data
// plane: handle Close, item Reclaim, duplicate capabilities returned for items
// already held, and abandoned provisional resources.
//
// It holds at most one in-flight work batch and one forming batch of at most
// limit tokens each. A work batch sends one CloseBatch for its closes and then
// one Reclaim for its items; closes go first because a Close that returned
// locally may precede the Reclaim the kernel issues next, and it costs nothing
// with one worker. An idle owner starts a batch at once, and tokens submitted
// while one is in flight form the next; there is no timer and no goroutine per
// token. A producer returns as soon as the owner has accepted its tokens and
// waits only for room in the forming batch, so authority resources lag local
// retirement by at most 2*limit accepted tokens plus the producers' bounded
// pre-enqueue obligations (see v3DataPlane.abandonedDebt).
//
// Each token reaches the owner exactly once, after its last local owner let go,
// so no request repeats a token. A failed or uncertain release is sticky: the
// authority rejects a whole CloseBatch or Reclaim for one stale or duplicate
// token and can partially apply either on a storage error, so no failed batch
// is ever retried item by item and no later batch is sent.
type v3ReleaseOwner struct {
	send  func(closes, reclaims [][]byte) error
	limit int

	mu      sync.Mutex
	changed chan struct{}
	forming *v3ReleaseBatch
	running bool
	// closed stops new admission. Once set, later submissions are owned by the
	// session's own end: a terminal session releases every capability with it,
	// and a draining teardown hands the rest to the authenticated detach.
	closed bool
	// discard is set by a terminal data plane: forming tokens are left to
	// session cleanup instead of being sent.
	discard bool
	failure error
}

type v3ReleaseBatch struct {
	closes   [][]byte
	reclaims [][]byte
	// reserved counts capacity granted to producers that have not yet
	// committed. The worker never takes a batch with outstanding reservations;
	// a reservation is held only across a short local detach.
	reserved int
}

func (b *v3ReleaseBatch) tokens() int { return len(b.closes) + len(b.reclaims) }

// v3ReleaseReservation is capacity in the forming batch for up to n tokens. A
// producer reserves before it detaches local ownership, so a token that leaves
// its local index is accepted by the owner in the same step.
type v3ReleaseReservation struct {
	owner *v3ReleaseOwner
	batch *v3ReleaseBatch
	n     int
	done  bool
}

func newV3ReleaseOwner(limit int, send func(closes, reclaims [][]byte) error) *v3ReleaseOwner {
	return &v3ReleaseOwner{send: send, limit: max(1, limit), changed: make(chan struct{})}
}

func (r *v3ReleaseOwner) signalLocked() {
	close(r.changed)
	r.changed = make(chan struct{})
}

// reserve waits for room for n tokens in the forming batch. It refuses with
// the sticky failure, errV3ReleaseClosed, or the context's error; a refusal
// grants nothing. A closed owner is not a failure: the producer may still
// retire local ownership, because the session's end owns what it would send.
func (r *v3ReleaseOwner) reserve(ctx context.Context, n int) (*v3ReleaseReservation, error) {
	if n < 1 || n > r.limit {
		return nil, errors.New("portablefsd: release reservation exceeds the batch bound")
	}
	for {
		r.mu.Lock()
		switch {
		case r.failure != nil:
			err := r.failure
			r.mu.Unlock()
			return nil, err
		case r.closed:
			r.mu.Unlock()
			return nil, errV3ReleaseClosed
		case r.forming == nil:
			r.forming = &v3ReleaseBatch{}
		}
		if r.forming.tokens()+r.forming.reserved+n <= r.limit {
			r.forming.reserved += n
			reservation := &v3ReleaseReservation{owner: r, batch: r.forming, n: n}
			r.mu.Unlock()
			return reservation, nil
		}
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// commit transfers at most n tokens into the reserved batch and releases the
// rest of the reservation. It runs exactly once; cancel is commit of nothing.
// A reservation granted before admission closed is honored by a drain; after a
// terminal transition its tokens belong to session cleanup. The nil
// reservation is the closed owner's: the session's end already owns the token.
func (res *v3ReleaseReservation) commit(closes, reclaims [][]byte) {
	if res == nil {
		return
	}
	r := res.owner
	r.mu.Lock()
	defer r.mu.Unlock()
	if res.done {
		panic("portablefsd: release reservation settled twice")
	}
	if len(closes)+len(reclaims) > res.n {
		panic("portablefsd: release commit exceeded its reservation")
	}
	res.done = true
	res.batch.reserved -= res.n
	if !r.discard && r.failure == nil {
		res.batch.closes = append(res.batch.closes, closes...)
		res.batch.reclaims = append(res.batch.reclaims, reclaims...)
	}
	if !r.running && res.batch.tokens() != 0 && res.batch == r.forming {
		r.running = true
		go r.run()
	}
	r.signalLocked()
}

func (res *v3ReleaseReservation) cancel() { res.commit(nil, nil) }

// submit transfers tokens that have already left local ownership, waiting only
// for room. A closed owner accepts them on behalf of the session's end. The
// only refusal is the sticky failure, which leaves them to that same terminal
// session cleanup.
func (r *v3ReleaseOwner) submit(closes, reclaims [][]byte) error {
	for len(closes)+len(reclaims) != 0 {
		n := min(len(closes)+len(reclaims), r.limit)
		reservation, err := r.reserve(context.Background(), n)
		if errors.Is(err, errV3ReleaseClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		closeCount := min(n, len(closes))
		reservation.commit(closes[:closeCount], reclaims[:n-closeCount])
		closes, reclaims = closes[closeCount:], reclaims[n-closeCount:]
	}
	return nil
}

func (r *v3ReleaseOwner) run() {
	r.mu.Lock()
	for {
		for r.forming != nil && r.forming.reserved != 0 {
			changed := r.changed
			r.mu.Unlock()
			<-changed
			r.mu.Lock()
		}
		if r.forming == nil || r.forming.tokens() == 0 {
			break
		}
		batch := r.forming
		r.forming = nil
		send := r.failure == nil && !r.discard
		r.signalLocked()
		r.mu.Unlock()
		var err error
		if send {
			err = r.send(batch.closes, batch.reclaims)
		}
		r.mu.Lock()
		if err != nil && r.failure == nil {
			r.failure = err
		}
	}
	r.running = false
	r.signalLocked()
	r.mu.Unlock()
}

// abandon is the terminal transition. Admission closes, waiting producers wake,
// and forming tokens are left to session cleanup; an in-flight batch still
// settles on its original session. Idempotent.
func (r *v3ReleaseOwner) abandon() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed, r.discard = true, true
	if r.forming != nil {
		r.forming.closes, r.forming.reclaims = nil, nil
	}
	r.signalLocked()
}
