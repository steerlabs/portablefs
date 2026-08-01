package portablefsd

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func (s *Server) ServeFrontend(ctx context.Context) error {
	if s.cfg.FrontendSocket == "" {
		return fmt.Errorf("frontend socket is required")
	}
	ln, err := listenUnixSocket(s.cfg.FrontendSocket)
	if err != nil {
		return err
	}
	s.frontendLnMu.Lock()
	s.frontendLnMu.Unlock()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	log.Printf("portablefsd frontend socket listening at %s", s.cfg.FrontendSocket)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if s.frontendConnections.Add(1) > maxFrontendConnections {
			s.frontendConnections.Add(-1)
			_ = c.Close()
			continue
		}
		fc := &frontendConn{srv: s, conn: c}
		go func() {
			defer s.frontendConnections.Add(-1)
			fc.serve(ctx)
		}()
	}
}

type frontendConn struct {
	srv    *Server
	conn   net.Conn
	origin uint64
	cancel context.CancelFunc

	writeMu sync.Mutex

	attachMu sync.RWMutex
	attach   *attach

	eventsMu sync.Mutex
	events   *eventSubscriber

	publicationMu     sync.Mutex
	operations        map[uint64]*frontendOperationEntry
	lastOperationID   uint64
	publicationClosed bool
	closeOnce         sync.Once
	inFlight          atomic.Int32
	handlerWG         sync.WaitGroup
}

type frontendOperationEntry struct {
	ready          chan struct{}
	op             *frontendOperation
	err            error
	activeRequests int
	replyExposed   bool
	ackPending     bool
}

const maxFrontendOperationsPerConnection = 4096
const maxFrontendRequestsInFlight = 1024
const maxFrontendConnections = 256

type frontendProtocolState uint8

const (
	frontendAwaitingHello frontendProtocolState = iota
	frontendAwaitingResolve
	frontendAttached
)

func (c *frontendConn) serve(ctx context.Context) {
	connCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	defer c.close()
	defer cancel()
	var lastRequestID uint64
	state := frontendAwaitingHello
	for {
		env, err := pfslocal.ReadFrame(c.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("frontend read: %v", err)
			}
			return
		}
		if _, ack := env.Body.(*pfslocal.PublicationAck); ack {
			if state != frontendAttached || env.RequestID != 0 {
				return
			}
			req := env.Body.(*pfslocal.PublicationAck)
			if req.PublishedRequestID != 0 ||
				req.OperationID == 0 ||
				!c.acknowledgePublication(req.OperationID) {
				return
			}
			continue
		} else {
			if env.RequestID == 0 || env.RequestID <= lastRequestID {
				return
			}
			lastRequestID = env.RequestID
		}
		switch req := env.Body.(type) {
		case *pfslocal.Hello:
			if state != frontendAwaitingHello {
				return
			}
			if req.ProtocolMajor != pfslocal.ProtocolMajor ||
				req.ProtocolMinor < pfslocal.ProtocolMinor {
				c.errorReply(env.RequestID, darwinEINVAL, "unsupported protocol version")
				return
			}
			c.reply(env.RequestID, &pfslocal.HelloReply{
				ProtocolMajor: pfslocal.ProtocolMajor,
				ProtocolMinor: pfslocal.ProtocolMinor,
				DaemonVersion: c.srv.cfg.Version,
			})
			state = frontendAwaitingResolve
		case *pfslocal.ResolveRequest:
			if state != frontendAwaitingResolve {
				return
			}
			a := c.srv.registry.get(req.AttachRef)
			if a == nil {
				c.errorReply(env.RequestID, darwinENOENT, "unknown attach_ref")
				continue
			}
			rep, eno := a.rootReply(connCtx)
			if eno != 0 {
				c.errorReply(env.RequestID, eno, errMessage("resolve", eno))
				continue
			}
			if !c.setAttach(a) {
				return
			}
			state = frontendAttached
			c.reply(env.RequestID, &rep)
		default:
			if state != frontendAttached {
				return
			}
			if c.inFlight.Add(1) > maxFrontendRequestsInFlight {
				c.inFlight.Add(-1)
				return
			}
			publishes := frontendRequestPublishes(req)
			if publishes && env.OperationID == 0 {
				c.inFlight.Add(-1)
				return
			}
			initializeOperation := false
			if env.OperationID != 0 {
				var ok bool
				initializeOperation, ok =
					c.reserveLogicalOperation(
						env.OperationID,
						publishes,
					)
				if !ok {
					c.inFlight.Add(-1)
					return
				}
			}
			c.handlerWG.Add(1)
			go func(
				a *attach,
				requestID uint64,
				operationID uint64,
				initializeOperation bool,
				body any,
			) {
				defer c.handlerWG.Done()
				defer c.inFlight.Add(-1)
				c.handleAttached(
					connCtx,
					a,
					requestID,
					operationID,
					initializeOperation,
					body,
				)
			}(c.currentAttach(), env.RequestID, env.OperationID, initializeOperation, req)
		}
	}
}

func (c *frontendConn) close() {
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		// Closing the transport unblocks any handler currently writing a
		// reply. Admission and release waits observe the canceled connCtx.
		_ = c.conn.Close()
		// Freeze publication bookkeeping before joining handlers. Once an
		// exposed reply loses its connection without an acknowledgement, the
		// kernel view is unprovable. Publish that terminal verdict to the
		// handoff gate immediately: a handler can be waiting behind the very
		// handoff that is waiting for this operation, so handlerWG cannot be
		// joined safely until the gate has been woken and the handoff aborts.
		c.publicationMu.Lock()
		c.publicationClosed = true
		var exposedUnacknowledged *frontendOperation
		orphaned := make([]*frontendOperation, 0, len(c.operations))
		for _, entry := range c.operations {
			if entry.op == nil {
				continue
			}
			if exposedUnacknowledged == nil &&
				entry.replyExposed && !entry.ackPending {
				exposedUnacknowledged = entry.op
			}
			orphaned = append(orphaned, entry.op)
		}
		c.publicationMu.Unlock()
		if exposedUnacknowledged != nil {
			exposedUnacknowledged.attach.failFrontendGate(fmt.Errorf(
				"kernel coherence barrier failed closed: %w",
				errors.New("frontend disconnected before acknowledging an exposed kernel publication"),
			))
		}
		// DEFINITIVE RESOLUTION OF EVERY OUTSTANDING PUBLICATION ACK.
		//
		// A publication acknowledgement is a statement about a LIVE frontend's
		// cache. Once the connection is gone that cache is gone with it: the
		// kernel-coherence barrier a handoff waits for is vacuously satisfied,
		// and there is no future event that could ever satisfy it otherwise.
		// Resolving these operations only AFTER handlerWG.Wait() made the
		// verdict conditional on every handler exiting, which is exactly the
		// wrong order: a handler can be parked inside the drain that the
		// handoff waiting on this operation is performing, so the drain and
		// the disconnect deadlock and the acknowledged tail strands with no
		// failure recorded. Retire the gate membership FIRST — nothing can be
		// published on a closed connection (markPublicationReplyExposed
		// refuses once publicationClosed is set), so the operations carry no
		// remaining coherence obligation.
		for _, op := range orphaned {
			op.attach.finishFrontendOperation(op)
		}
		// A handler may still be completing a local syscall or mutation after
		// cancellation. Joining it here keeps connection teardown ordered
		// behind its own handlers; it no longer gates any delegation handoff.
		c.handlerWG.Wait()
		c.publicationMu.Lock()
		pending := c.operations
		c.operations = nil
		c.publicationMu.Unlock()
		for _, entry := range pending {
			<-entry.ready
			if entry.op != nil {
				if entry.replyExposed && !entry.ackPending {
					entry.op.attach.failCoherence(errors.New(
						"frontend disconnected before acknowledging an exposed kernel publication",
					))
				}
				entry.op.attach.finishFrontendOperation(entry.op)
			}
		}
		if a := c.currentAttach(); a != nil {
			a.removeConn(c.conn)
		}
		c.eventsMu.Lock()
		if c.events != nil {
			if a := c.currentAttach(); a != nil {
				a.unsubscribe(c.events)
			}
			c.events = nil
		}
		c.eventsMu.Unlock()
	})
}

func (c *frontendConn) currentAttach() *attach {
	c.attachMu.RLock()
	defer c.attachMu.RUnlock()
	return c.attach
}

func (c *frontendConn) setAttach(a *attach) bool {
	c.attachMu.Lock()
	if c.attach != nil {
		c.attachMu.Unlock()
		return false
	}
	c.attach = a
	if c.origin == 0 {
		c.origin = a.newOrigin()
	}
	c.attachMu.Unlock()
	a.addConn(c.conn)
	return true
}

func (c *frontendConn) write(env *pfslocal.Envelope) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return pfslocal.WriteFrame(c.conn, env)
}

func (c *frontendConn) reply(req uint64, body any) {
	c.replyWithPublication(req, 0, body, false)
}

func (c *frontendConn) replyWithPublication(
	req uint64,
	operationID uint64,
	body any,
	ackRequired bool,
) {
	if ackRequired && !c.markPublicationReplyExposed(operationID) {
		_ = c.conn.Close()
		return
	}
	if err := c.write(&pfslocal.Envelope{
		RequestID:              req,
		PublicationAckRequired: ackRequired,
		Body:                   body,
	}); err != nil {
		log.Printf("frontend write reply: %v", err)
		_ = c.conn.Close()
	}
}

func (c *frontendConn) markPublicationReplyExposed(operationID uint64) bool {
	c.publicationMu.Lock()
	defer c.publicationMu.Unlock()
	entry := c.operations[operationID]
	if c.publicationClosed ||
		entry == nil ||
		entry.op == nil ||
		entry.ackPending {
		return false
	}
	entry.replyExposed = true
	return true
}

func (c *frontendConn) errorReply(req uint64, eno int32, msg string) {
	c.reply(req, &pfslocal.ErrorReply{Errno: eno, Message: msg})
}

func (c *frontendConn) acknowledgePublication(operationID uint64) bool {
	c.publicationMu.Lock()
	entry := c.operations[operationID]
	if entry == nil ||
		entry.op == nil ||
		!entry.replyExposed ||
		entry.ackPending {
		c.publicationMu.Unlock()
		return false
	}
	entry.ackPending = true
	finish := entry.activeRequests == 0
	if finish {
		delete(c.operations, operationID)
	}
	c.publicationMu.Unlock()
	if finish {
		entry.op.attach.finishFrontendOperation(entry.op)
	}
	return true
}

func (c *frontendConn) finishLogicalRequest(operationID uint64) {
	c.publicationMu.Lock()
	entry := c.operations[operationID]
	if entry == nil || entry.activeRequests <= 0 {
		c.publicationMu.Unlock()
		return
	}
	entry.activeRequests--
	finish := entry.ackPending && entry.activeRequests == 0
	if finish {
		delete(c.operations, operationID)
	}
	c.publicationMu.Unlock()
	if finish {
		entry.op.attach.finishFrontendOperation(entry.op)
	}
}

// reserveLogicalOperation runs only on the connection's serial frame-reader
// goroutine. It validates first-seen operation IDs in wire order before
// parallel handlers can reorder their admission, and reserves the map entry
// that every handler for that logical operation will share.
func (c *frontendConn) reserveLogicalOperation(
	operationID uint64,
	publishes bool,
) (initialize, ok bool) {
	c.publicationMu.Lock()
	defer c.publicationMu.Unlock()
	if c.publicationClosed || operationID == 0 {
		return false, false
	}
	if entry := c.operations[operationID]; entry != nil {
		if entry.ackPending {
			return false, false
		}
		entry.activeRequests++
		return false, true
	}
	if !publishes {
		return false, false
	}
	if operationID <= c.lastOperationID {
		return false, false
	}
	if c.operations == nil {
		c.operations = map[uint64]*frontendOperationEntry{}
	}
	if len(c.operations) >= maxFrontendOperationsPerConnection {
		return false, false
	}
	c.operations[operationID] = &frontendOperationEntry{
		ready:          make(chan struct{}),
		activeRequests: 1,
	}
	c.lastOperationID = operationID
	return true, true
}

func (c *frontendConn) beginLogicalOperation(
	ctx context.Context,
	a *attach,
	operationID uint64,
	initialize bool,
	body any,
) (context.Context, *frontendOperationParticipant, bool, bool, error) {
	paths, pathEpoch, publishes := a.frontendOperationPaths(body)

	if operationID == 0 {
		if publishes {
			return ctx, nil, false, false, fmt.Errorf("invalid frontend operation id")
		}
		return ctx, nil, false, false, nil
	}
	if initialize && !publishes {
		return ctx, nil, false, false, fmt.Errorf(
			"frontend operation id began with a nonpublishing request",
		)
	}

	c.publicationMu.Lock()
	if c.publicationClosed {
		// close() retains the operation table until every handler exits. The
		// one initializing handler owns ready's completion even when
		// disconnect wins before that handler begins; continuations and close
		// can then join the same definite net.ErrClosed outcome.
		if initialize {
			if entry := c.operations[operationID]; entry != nil {
				entry.err = net.ErrClosed
				close(entry.ready)
			}
		}
		c.publicationMu.Unlock()
		return ctx, nil, false, false, net.ErrClosed
	}
	entry := c.operations[operationID]
	if entry == nil || entry.ackPending {
		c.publicationMu.Unlock()
		return ctx, nil, false, false, fmt.Errorf("frontend operation was not reserved")
	}
	if !initialize {
		c.publicationMu.Unlock()
		select {
		case <-entry.ready:
		case <-ctx.Done():
			return ctx, nil, false, false, ctx.Err()
		}
		if entry.err != nil {
			return ctx, nil, false, false, entry.err
		}
		if !publishes {
			// HANDLE CLOSE NEVER WAITS FOR A DELEGATION HANDOFF.
			//
			// The publication gate exists to hold a handoff until cacheable
			// state a callback exposed has been acknowledged, and to keep a
			// request's reply on the correct side of that handoff. A request
			// that publishes nothing — close, fsync, statfs, reclaim,
			// syncVolume — exposes no such state, so it has no side to be on.
			// Admitting it as an ordinary participant made it WAIT twice for
			// no coherence benefit: an extension collapses the
			// logical operation to the mount-wide scope on any path-epoch
			// change, and the resume half of suspendFrontendOperation blocks
			// until every overlapping delegation handoff has ended — a window
			// that spans the release's authority round trips and is unbounded
			// when the uplink is slow or dead. A close(2) carrying an
			// operation ID therefore queued on a scope release while the
			// identical close carrying none returned instantly.
			//
			// Join PERMANENTLY SUSPENDED instead. The participant still
			// exists, so the logical operation cannot be considered finished
			// while this request runs (that is what keeps a recall holding a
			// namespace mirror lock from deadlocking against the very
			// operation it is waiting to publish), but it is never a member
			// of the active publication set, so it neither blocks a handoff
			// nor waits for one. close(2) is bounded local bookkeeping:
			// admitted data belongs to the engine and drains in the
			// background; fsync, synchronize, unmount and recall remain the
			// only drain barriers.
			participant, err := a.joinFrontendOperationSuspended(entry.op)
			if err != nil {
				return ctx, nil, false, false, err
			}
			return context.WithValue(ctx, frontendOperationContextKey{}, participant),
				participant, true, false, nil
		}
		participant, err := a.reserveFrontendExtension(entry.op, paths, pathEpoch)
		if err != nil {
			return ctx, nil, false, false, err
		}
		return context.WithValue(ctx, frontendOperationContextKey{}, participant),
			participant, true, publishes, nil
	}
	c.publicationMu.Unlock()

	// RESERVE, never begin: the operation is created with its first
	// participant suspended and waits for no handoff. Its continuations
	// therefore observe entry.ready promptly, and the gate wait this call used
	// to pay is deferred to activation, where it can be paid holding no
	// frontend mirror (see the publication activation protocol in
	// coherence_refresh.go).
	op, participant := a.reserveFrontendOperation(paths, pathEpoch)
	var err error
	c.publicationMu.Lock()
	if c.publicationClosed {
		err = net.ErrClosed
	}
	if err == nil {
		entry.op = op
	}
	entry.err = err
	close(entry.ready)
	c.publicationMu.Unlock()
	if err != nil {
		a.finishFrontendParticipant(participant)
		a.finishFrontendOperation(op)
		return ctx, nil, false, false, err
	}
	return context.WithValue(ctx, frontendOperationContextKey{}, participant),
		participant, true, true, nil
}

func (c *frontendConn) handleAttached(
	ctx context.Context,
	a *attach,
	requestID uint64,
	operationID uint64,
	initializeOperation bool,
	body any,
) {
	// ── THE DISPATCHER-ORDERING CONTRACT ────────────────────────────────────
	//
	// One request runs in four phases, and the order is the whole point:
	//
	//	0. DEADLINE     One absolute bound for the operation, installed before
	//	   + RESERVE.   anything can wait; then this request joins its logical
	//	                operation SUSPENDED, holding nothing and waiting for
	//	                nothing.
	//	1. ADMISSION.   Classification, delegation transition and metadata-lane
	//	                pacing — every step that can BLOCK on the uplink — taken
	//	                holding NOTHING, and carrying the reserved publication
	//	                identity so a release's handoff recognises this
	//	                request's own operation.
	//	2. PUBLICATION  The frontend mirrors (serialization, name stripes,
	//	   + MIRRORS.   per-handle gate), then a NONBLOCKING attempt to activate
	//	                into the publication set. Nothing acquired here waits on
	//	                the far end, and nothing here waits at all while a mirror
	//	                is held.
	//	3. MUTATE.      The handler: a nonblocking revalidate of what phase 1
	//	                decided, then the mutation itself.
	//
	// RESERVE exists because a CONTINUATION used to run phase 1 before it
	// joined its logical operation, so its admission context carried no
	// publication identity. A delegation release taken during classification
	// reached OnHandoffStart, which saw the continuation's OWN already-active
	// operation as a foreign member of the publication set and waited for it —
	// an operation that cannot finish, because this continuation is one of its
	// in-flight requests. A bounded deadlock resolved only by the operation
	// deadline, surfacing as an EINTR and a spurious drain error.
	//
	// Phase 1 used to sit INSIDE phase 2. lockFrontendRequest takes the frontend
	// serialization lock, the name stripes and a per-handle frontend RLock; then
	// mutation admission could park for a full metadata admission budget. A
	// close(2) on the same descriptor needs that handle gate EXCLUSIVELY, so it
	// queued behind a request that was waiting on the authority — close-behind-
	// backlog, the exact shape the close-is-local-bookkeeping work removed by one
	// route, reappearing by another. The fix is structural and lives here, once,
	// rather than in each handler: no frontend lock is held while anything waits
	// on the uplink, on any request, ever.
	//
	// The unwind obeys the same contract. A lane invalidated inside the locks
	// unwinds by RELEASING the mirrors and taking this request out of the
	// publication set before it re-admits, so the second pass's claim and release
	// are also paid holding nothing.
	//
	// Within phase 2 there is now ONE order for every request, continuation or
	// not: take the mirrors while suspended (blocking no handoff), then ATTEMPT
	// activation. The two orders this replaced each waited under the mirrors —
	// a new operation in the gate entry it took after them, a continuation in
	// the resume half of its suspend/mirrors/resume sequence — and that wait
	// spans a delegation release's authority round trips.
	if operationID != 0 {
		defer c.finishLogicalRequest(operationID)
	}

	// PHASE 0.
	ctx, cancelOperation := clientcore.WithOperationDeadline(ctx)
	defer cancelOperation()

	// RESERVE. Holds nothing, waits for nothing except this logical
	// operation's own reservation by its initializing request.
	gateCtx, participant, participates, publishes, err := c.beginLogicalOperation(
		ctx, a, operationID, initializeOperation, body,
	)
	if err != nil {
		_ = c.conn.Close()
		return
	}
	if participates {
		defer a.finishFrontendParticipant(participant)
	}

	// PHASE 1, first pass. Holds nothing at all, and carries the reserved
	// publication identity: the lane, the transition token and the deadline are
	// phase 1's, the publication identity is the reservation's, and phase 3
	// needs both.
	opCtx, settleMutation, admitEno, classified := a.admitRequest(gateCtx, body, false)
	settleOnce := func() {
		if settleMutation != nil {
			settleMutation()
			settleMutation = nil
		}
	}
	defer settleOnce()

	// PHASE 2.
	var unlockRequest func()
	defer func() {
		if unlockRequest != nil {
			unlockRequest()
		}
	}()
	unlockRequest, err = a.enterFrontendMirrors(gateCtx, body, participant)
	if err != nil {
		_ = c.conn.Close()
		return
	}
	if err := a.frontendAdmissionError(); err != nil {
		if publishes {
			c.replyWithPublication(
				requestID,
				operationID,
				&pfslocal.ErrorReply{
					Errno: darwinEIO, Message: err.Error(),
				},
				true,
			)
		} else {
			c.errorReply(requestID, darwinEIO, err.Error())
		}
		return
	}
	started := time.Now()
	var (
		reply any
		eno   int32
	)
	// PHASE 3, and the unwind it owns.
	//
	// Under the locks the transition state is only CHECKED; a check that fails
	// unwinds with every frontend lock released and this request suspended out of
	// the publication set, and the next pass resolves the authority lane
	// unconditionally — not a claim about a grant, so a recall has nothing left
	// to invalidate.
	for {
		if admitEno != 0 {
			settleOnce()
			reply, eno = nil, admitEno
			break
		}
		var replied bool
		reply, eno, replied = a.dispatchRequest(opCtx, c, requestID, body)
		settleOnce()
		if replied {
			return
		}
		if eno != errnoLaneChanged || !classified {
			break
		}
		// UNWIND. Drop the mirrors and leave the publication set BEFORE
		// re-admitting: the second pass's claim and delegation release are as
		// unbounded as the first pass's and must be paid in the same place.
		// Re-entry is the same reserve/mirrors/attempt-activation sequence the
		// first pass used, so the second pass's gate wait is paid holding
		// nothing too.
		unlockRequest()
		unlockRequest = nil
		a.suspendFrontendParticipant(participant)
		opCtx, settleMutation, admitEno, classified = a.admitRequest(gateCtx, body, true)
		unlockRequest, err = a.enterFrontendMirrors(gateCtx, body, participant)
		if err != nil {
			settleOnce()
			_ = c.conn.Close()
			return
		}
	}
	if eno == errnoLaneChanged {
		// The sentinel escaped. It cannot: only a CLASSIFIED operation carries a
		// resolved lane, and only a resolved lane lets the engine answer
		// ErrLaneChanged — so an unclassified handler has no way to produce it.
		// Reaching here means that invariant broke, and the one thing that must
		// not happen is replying -1 to the kernel. Answer definitely instead.
		eno = darwinEIO
	}
	if pfsdTrace {
		log.Printf("pfsd-trace %s eno=%d duration=%s", traceOp(a, body), eno, time.Since(started))
	}
	if eno != 0 {
		if publishes {
			c.replyWithPublication(
				requestID,
				operationID,
				&pfslocal.ErrorReply{
					Errno:   eno,
					Message: errMessage(fmt.Sprintf("%T", body), eno),
				},
				true,
			)
		} else {
			c.errorReply(requestID, eno, errMessage(fmt.Sprintf("%T", body), eno))
		}
		return
	}
	a.synthesizeFrontendMutation(body, c.origin)
	c.replyWithPublication(requestID, operationID, reply, publishes)
}

// dispatchRequest runs one request's handler under the operation context the
// pre-lock classifier produced. replied reports that the handler already
// answered the connection itself, and the caller must return without replying
// again.
func (a *attach) dispatchRequest(
	ctx context.Context,
	c *frontendConn,
	requestID uint64,
	body any,
) (reply any, eno int32, replied bool) {
	switch req := body.(type) {
	case *pfslocal.LookupRequest:
		reply, eno = a.lookup(ctx, req)
	case *pfslocal.EnumerateRequest:
		reply, eno = a.enumerate(ctx, req)
	case *pfslocal.GetAttrRequest:
		reply, eno = a.getattr(ctx, req)
	case *pfslocal.SetAttrRequest:
		reply, eno = a.setattr(ctx, req)
	case *pfslocal.OpenRequest:
		reply, eno = a.open(ctx, req)
	case *pfslocal.CloseRequest:
		reply, eno = a.close(req)
	case *pfslocal.ReadRequest:
		reply, eno = a.read(ctx, req)
	case *pfslocal.WriteRequest:
		reply, eno = a.write(ctx, req)
	case *pfslocal.CreateRequest:
		reply, eno = a.create(ctx, req)
	case *pfslocal.MkdirRequest:
		reply, eno = a.mkdir(ctx, req)
	case *pfslocal.RemoveRequest:
		eno = a.remove(ctx, req)
		reply = &pfslocal.RemoveReply{}
	case *pfslocal.RenameRequest:
		eno = a.rename(ctx, req)
		reply = &pfslocal.RenameReply{}
	case *pfslocal.SymlinkRequest:
		reply, eno = a.symlink(ctx, req)
	case *pfslocal.ReadlinkRequest:
		reply, eno = a.readlink(ctx, req)
	case *pfslocal.HardLinkRequest:
		reply, eno = a.hardLink(ctx, req)
	case *pfslocal.XattrGetRequest:
		reply, eno = a.xattrGet(ctx, req)
	case *pfslocal.XattrSetRequest:
		reply, eno = a.xattrSet(ctx, req)
	case *pfslocal.XattrListRequest:
		reply, eno = a.xattrList(ctx, req)
	case *pfslocal.XattrRemoveRequest:
		reply, eno = a.xattrRemove(ctx, req)
	case *pfslocal.StatfsRequest:
		reply, eno = a.statfs()
	case *pfslocal.SyncVolumeRequest:
		reply, eno = a.syncVolume(ctx)
	case *pfslocal.FsyncRequest:
		eno = a.fsync(ctx, req)
		reply = &pfslocal.FsyncReply{}
	case *pfslocal.ReclaimRequest:
		eno = a.reclaim(req)
		reply = &pfslocal.ReclaimReply{}
	case *pfslocal.SubscribeEventsRequest:
		if err := c.subscribeEvents(a); err != nil {
			c.errorReply(requestID, darwinEIO, err.Error())
			return nil, 0, true
		}
		reply = &pfslocal.SubscribeEventsReply{}
	default:
		c.errorReply(requestID, darwinEINVAL, fmt.Sprintf("unsupported request %T", body))
		return nil, 0, true
	}
	return reply, eno, false
}

// pfsdTrace (PFSD_TRACE=1) logs every frontend op with its resolved paths and
// errno — the pfslocal boundary is otherwise invisible, and kernel-side
// caching bugs can only be diagnosed by seeing exactly what the extension
// asked and what the daemon answered.
var pfsdTrace = os.Getenv("PFSD_TRACE") == "1"

func traceOp(a *attach, body any) string {
	itemPath := func(item pfslocal.Item) string {
		a.mu.RLock()
		defer a.mu.RUnlock()
		if rec := a.items[item.ItemID]; rec != nil {
			return rec.path
		}
		return fmt.Sprintf("item#%d?", item.ItemID)
	}
	switch req := body.(type) {
	case *pfslocal.LookupRequest:
		return fmt.Sprintf("lookup dir=%q name=%q", itemPath(req.Dir), req.Name)
	case *pfslocal.EnumerateRequest:
		return fmt.Sprintf("enumerate dir=%q", itemPath(req.Dir))
	case *pfslocal.GetAttrRequest:
		return fmt.Sprintf("getattr %q", itemPath(req.Item))
	case *pfslocal.OpenRequest:
		return fmt.Sprintf("open %q", itemPath(req.Item))
	case *pfslocal.CreateRequest:
		return fmt.Sprintf("create dir=%q name=%q", itemPath(req.Dir), req.Name)
	case *pfslocal.RemoveRequest:
		return fmt.Sprintf("remove dir=%q name=%q", itemPath(req.Dir), req.Name)
	case *pfslocal.RenameRequest:
		return fmt.Sprintf("rename %q/%q -> %q/%q", itemPath(req.FromDir), req.FromName, itemPath(req.ToDir), req.ToName)
	default:
		return fmt.Sprintf("%T", body)
	}
}

func (c *frontendConn) subscribeEvents(a *attach) error {
	c.eventsMu.Lock()
	defer c.eventsMu.Unlock()
	if c.events != nil {
		return nil
	}
	if !a.isCredentialPending() {
		readyCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if !a.waitEventsReady(readyCtx) {
			return fmt.Errorf("authority event stream is not ready")
		}
	}
	sub := a.subscribe(c.origin)
	c.events = sub
	go func() {
		for ev := range sub.ch {
			if err := c.write(&pfslocal.Envelope{RequestID: 0, Body: &pfslocal.Event{Kind: ev.Kind}}); err != nil {
				_ = c.conn.Close()
				return
			}
		}
		_ = c.conn.Close()
	}()
	return nil
}

func listenUnixSocket(p string) (net.Listener, error) {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("Unix socket parent %s must be a private 0700 directory", dir)
	}
	if _, err := os.Lstat(p); err == nil {
		return nil, fmt.Errorf("refusing to replace existing Unix socket %s; another or previously crashed portablefsd may own it", p)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect Unix socket %s: %w", p, err)
	}
	// bind(2) publishes a Unix socket pathname before Go returns from
	// net.Listen, so chmod-after-bind has an observable permissive-mode
	// window. Bind under a short private staging name in the already-0700
	// parent, set the final mode, then publish the already-secured socket inode
	// with link(2). The short name preserves macOS's small sockaddr_un path
	// limit even when the configured final path is close to that limit. Link
	// is atomic and refuses an existing destination, preserving the
	// singleton's never-replace-owner contract without a process-global umask.
	stagePath, err := unusedUnixStagePath(dir)
	if err != nil {
		return nil, err
	}
	cleanupStage := func() { _ = os.Remove(stagePath) }
	ln, err := net.Listen("unix", stagePath)
	if err != nil {
		cleanupStage()
		return nil, err
	}
	unixLn, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		cleanupStage()
		return nil, fmt.Errorf("listen Unix socket %s returned %T", stagePath, ln)
	}
	// The final pathname, not the private staging name, owns cleanup.
	unixLn.SetUnlinkOnClose(false)
	if err := os.Chmod(stagePath, 0o600); err != nil {
		_ = ln.Close()
		cleanupStage()
		return nil, err
	}
	identity, err := os.Lstat(stagePath)
	if err != nil {
		_ = ln.Close()
		cleanupStage()
		return nil, err
	}
	if err := os.Link(stagePath, p); err != nil {
		_ = ln.Close()
		cleanupStage()
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("refusing to replace existing Unix socket %s; another or previously crashed portablefsd may own it", p)
		}
		return nil, fmt.Errorf("publish Unix socket %s: %w", p, err)
	}
	published := &publishedUnixListener{Listener: ln, path: p, identity: identity}
	if err := os.Remove(stagePath); err != nil {
		_ = published.Close()
		cleanupStage()
		return nil, fmt.Errorf("retire staged Unix socket name: %w", err)
	}
	return published, nil
}

func unusedUnixStagePath(dir string) (string, error) {
	var suffix [2]byte
	for attempt := 0; attempt < 64; attempt++ {
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", fmt.Errorf("generate Unix socket staging name: %w", err)
		}
		p := filepath.Join(dir, fmt.Sprintf(".p%02x%02x", suffix[0], suffix[1]))
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			return p, nil
		} else if err != nil {
			return "", fmt.Errorf("inspect Unix socket staging name: %w", err)
		}
	}
	return "", fmt.Errorf("allocate unique Unix socket staging name in %s", dir)
}

// publishedUnixListener removes only the exact socket inode it published.
// A same-user process replacing the path during shutdown is never deleted.
type publishedUnixListener struct {
	net.Listener
	path     string
	identity os.FileInfo
	once     sync.Once
	err      error
}

func (l *publishedUnixListener) Close() error {
	l.once.Do(func() {
		closeErr := l.Listener.Close()
		current, statErr := os.Lstat(l.path)
		switch {
		case os.IsNotExist(statErr):
			statErr = nil
		case statErr != nil:
		case !os.SameFile(current, l.identity):
			statErr = fmt.Errorf("refusing to remove replaced Unix socket %s", l.path)
		default:
			statErr = os.Remove(l.path)
			if os.IsNotExist(statErr) {
				statErr = nil
			}
		}
		l.err = errors.Join(closeErr, statErr)
	})
	return l.err
}
