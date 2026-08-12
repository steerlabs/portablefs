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
	"syscall"
	"time"

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
	// helloClientName is frozen by the one accepted Hello frame. It is used
	// only to distinguish the shipping FSKit frontend from daemon self-probes;
	// the app-group socket remains the peer authorization boundary.
	helloClientName string
	connCtx         context.Context
	cancel          context.CancelFunc

	writeMu sync.Mutex

	attachMu sync.RWMutex
	attach   *attach

	eventsMu sync.Mutex
	events   *eventSubscriber
	v3Events bool

	publicationMu     sync.Mutex
	operations        map[uint64]*frontendOperationEntry
	lastOperationID   uint64
	publicationClosed bool
	closeOnce         sync.Once
	inFlight          atomic.Int32
	visibilityAckBusy atomic.Bool
	handlerWG         sync.WaitGroup

	resourceMu     sync.Mutex
	provisional    map[uint64]*v3ProvisionalResources
	resourceClosed bool

	// testAfterRetractionCapture fires between a reply's retraction-verdict
	// capture and its frame write. It exists because that gap is not otherwise
	// reachable from a test and it is exactly the gap a delegation handoff used
	// to fit a crossing into: the verdict said "not retracted", the crossing
	// happened, and the frame carrying the stale verdict went out afterwards.
	// nil in production.
	testAfterRetractionCapture func(operationID uint64)
}

type frontendOperationEntry struct {
	ready          chan struct{}
	op             *frontendOperation
	err            error
	activeRequests int
	replyExposed   bool
	ackPending     bool
}

var errFrontendPublicationUnprovable = errors.New(
	"portablefsd: FSKit frontend publication is unprovable",
)

// frontendRequestDeadline is what the daemon TELLS a frontend to wait for one
// reply, and it is derived from the daemon's own budgets rather than chosen.
//
// ── WHY THE FRONTEND MUST NOT PICK THIS NUMBER ──────────────────────────────
//
// It used to. The extension carried requestDeadlineNanoseconds = 60s; the
// daemon gave one request an operationAdmissionBudget of 50s. Nothing related
// the two, and 10s is not a margin: one request's ADMISSION may legitimately
// consume most of its 50s, and admission is only part of a handler — the live
// battery recorded a warm rmdir that took 80s and SUCCEEDED. So the frontend's
// bound expired first on an operation the daemon was still going to answer
// correctly, and a latency outlier was converted into a protocol event.
//
// ── WHY IT IS A MULTIPLE, NOT A SUM ─────────────────────────────────────────
//
// The daemon does not promise a total handler bound; it promises a definite
// OUTCOME, and its internal budgets bound the waits it can be asked to make.
// A frontend deadline exists only to notice a daemon that has stopped
// answering at all, which is a different question from "is this slow". So the
// number is deliberately far above anything a healthy handler can reach, and it
// moves with operationAdmissionBudget so the two can never drift apart again.
//
// The remaining bound on a genuinely wedged request is the frontend's, and its
// expiry is now REQUEST-LOCAL (see PfsLocalClient.timeoutRequest): it answers
// that one request and leaves the connection — and therefore every other
// operation's publication — alone.
//
// ── ROUND 17: WHY THIS NUMBER IS NOT A SAFETY MECHANISM, AND MUST NOT BE ────
//
// The obvious reading of "200s exceeds the ~60s FSKit reply envelope" is that
// the multiplier is the defect and the advertised bound should be CLAMPED to
// the kernel's own ceiling, so that an expiry would mean "the mutation did not
// and will not commit". It cannot mean that, for two independent reasons, and
// clamping would buy nothing while costing a certified property:
//
//  1. THE DAEMON PROMISES NO TOTAL HANDLER BOUND. operationAdmissionBudget is
//     an absolute deadline on the WAITS a request may be asked to make, not on
//     the request. A handler past every wait can still commit — the live
//     battery's 80s warm rmdir SUCCEEDED against a 50s budget — so there is no
//     instant T after which "has not committed" implies "will not commit".
//     Advertising 60s instead of 200s changes when the extension gives up; it
//     changes nothing about when the daemon can commit.
//
//  2. THE KERNEL'S CEILING IS EXTERNAL. Whatever this daemon advertises, FSKit
//     abandons an upcall on its own schedule. A negotiated number can neither
//     enlarge that ceiling nor make the extension's expiry coincide with it, so
//     the extension's deadline can never be the mechanism that keeps the
//     kernel's view correct.
//
// And clamping has a real cost: a 60s frontend bound against a 50s daemon
// budget is exactly the pairing round 15 removed, on exactly the operation
// (the 80s rmdir) that motivated removing it.
//
// So the deadline is demoted, deliberately, from a correctness mechanism to a
// LIVENESS one — it exists to notice a daemon that has stopped answering. The
// correctness boundary is the publication ledger itself: if a publishing reply
// becomes ready after the callback has already acknowledged failure, or an
// exposed reply loses its connection before acknowledgement, this incarnation
// is fenced. There is no repair path that may guess what FSKit installed.
func frontendRequestDeadline() time.Duration {
	return frontendRequestDeadlineFactor * operationAdmissionBudgetValue()
}

// frontendRequestDeadlineFactor is how far the advertised bound sits above the
// daemon's own per-operation budget. It must be strictly greater than 1: a
// frontend bound at or below the daemon's budget expires on operations the
// daemon is still going to answer correctly, which is exactly the pairing that
// broke (60s frontend vs 50s daemon).
const frontendRequestDeadlineFactor = 4

const maxFrontendOperationsPerConnection = 4096
const maxFrontendRequestsInFlight = 1024
const maxFrontendConnections = 256
const maxProvisionalResourcesPerConnection = maxFrontendRequestsInFlight

type frontendProtocolState uint8

const (
	frontendAwaitingHello frontendProtocolState = iota
	frontendAwaitingResolve
	frontendAttached
)

func (c *frontendConn) serve(ctx context.Context) {
	connCtx, cancel := context.WithCancel(ctx)
	c.connCtx = connCtx
	c.cancel = cancel
	defer c.close()
	defer cancel()
	// Two watermarks, one per ordering lane. Request IDs are allocated in one
	// strictly increasing sequence, but the frontend writes on two lanes: the
	// reserved control lane (visibility acknowledgements, liveness) is
	// dequeued ahead of ordinary requests precisely so a barrier ack can
	// never queue behind a request burst. The lanes therefore interleave on
	// the wire, and a single global watermark misreads that interleaving as
	// replay: under a mutation storm the first visibility ack that overtook a
	// queued ordinary request killed the connection — and with it the mount.
	// Each lane is FIFO and increasing within itself, which is exactly the
	// replay protection the check exists for.
	var lastRequestID uint64
	var lastControlRequestID uint64
	state := frontendAwaitingHello
	for {
		env, err := pfslocal.ReadFrame(c.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("frontend read: %v", err)
			}
			return
		}
		// Validate this envelope metadata before dispatching any body, including
		// handshake and reserved control-lane bodies. Otherwise those early paths
		// could silently accept a proof bit whose meaning they cannot uphold.
		if !validFrontendSourcePhaseQueueability(
			env.Body, env.OperationID, env.SourcePhaseQueueable,
		) {
			log.Printf(
				"portablefsd frontend: closing connection: source-phase-queueable request has operation id %d and body %T",
				env.OperationID, env.Body,
			)
			return
		}
		if disposition, ok := env.Body.(*pfslocal.ResourceReplyDisposition); ok {
			if state != frontendAttached || env.RequestID != 0 || env.OperationID != 0 || disposition.TargetRequestID == 0 {
				log.Printf("portablefsd frontend: closing connection: malformed resource reply disposition")
				return
			}
			if !c.settleProvisionalResource(disposition) {
				log.Printf(
					"portablefsd frontend: closing connection: invalid resource disposition target=%d accept_handles=%t accepted_items=%d",
					disposition.TargetRequestID, disposition.AcceptHandles, disposition.AcceptedItemCount,
				)
				return
			}
			continue
		}
		if _, ack := env.Body.(*pfslocal.PublicationAck); ack {
			// A protocol violation closes the connection — for a strict-v3
			// mount that close is the mount's death sentence, so the exact
			// violated condition is logged rather than the connection just
			// vanishing with both ends blaming the other.
			if state != frontendAttached || env.RequestID != 0 {
				log.Printf("portablefsd frontend: closing connection: publication ack before attach or with request id %d", env.RequestID)
				return
			}
			req := env.Body.(*pfslocal.PublicationAck)
			if req.PublishedRequestID != 0 || req.OperationID == 0 {
				log.Printf("portablefsd frontend: closing connection: malformed publication ack (publishedRequestID=%d operationID=%d)", req.PublishedRequestID, req.OperationID)
				return
			}
			if !c.acknowledgePublication(req.OperationID) {
				log.Printf("portablefsd frontend: closing connection: publication ack for unknown or already-acknowledged operation %d", req.OperationID)
				return
			}
			if a := c.currentAttach(); a != nil {
				if bridge := a.v3CoherenceBridge(); bridge != nil {
					_ = bridge.acknowledgePublication(req.OperationID)
				}
			}
			continue
		} else {
			lane, ok := admitLaneRequestID(env.Body, env.RequestID, &lastRequestID, &lastControlRequestID)
			if !ok {
				log.Printf("portablefsd frontend: closing connection: %s-lane request id %d violated its lane's strictly-increasing order", lane, env.RequestID)
				return
			}
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
			c.helloClientName = req.ClientName
			c.reply(env.RequestID, &pfslocal.HelloReply{
				ProtocolMajor:     pfslocal.ProtocolMajor,
				ProtocolMinor:     pfslocal.ProtocolMinor,
				DaemonVersion:     c.srv.cfg.Version,
				RequestDeadlineMs: uint32(frontendRequestDeadline().Milliseconds()),
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
			rep, eno := a.v3RootReply()
			if eno != 0 {
				c.errorReply(env.RequestID, eno, errMessage("resolve", eno))
				continue
			}
			if !c.setAttach(a) {
				return
			}
			state = frontendAttached
			if c.reply(env.RequestID, &rep) &&
				c.helloClientName == nativeFSKitFrontendClientName {
				a.registerNativeFrontendWitness(c)
			}
		default:
			if state != frontendAttached {
				return
			}
			// Visibility acknowledgement is the strict mount's reserved control
			// lane. It bypasses ordinary admission and frontend namespace locks,
			// and runs off the serial reader so a source COMPLETE can wait for a
			// PublicationAck arriving later on this same connection.
			if ack, ok := req.(*pfslocal.VisibilityAckRequest); ok {
				if env.OperationID != 0 {
					return
				}
				// Exactly one visibility event can be outstanding, and a correct
				// frontend waits for this request's reply before issuing another.
				// Bound the reserved lane independently instead of permitting a
				// local peer to create an unbounded set of goroutines parked on
				// the source-publication barrier.
				if !c.visibilityAckBusy.CompareAndSwap(false, true) {
					return
				}
				c.handlerWG.Add(1)
				go func(requestID uint64, request *pfslocal.VisibilityAckRequest) {
					defer c.handlerWG.Done()
					defer c.visibilityAckBusy.Store(false)
					c.handleVisibilityAck(connCtx, requestID, request)
				}(env.RequestID, ack)
				continue
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
				// Reservation is the first durable fact shared by the wire
				// reader and the handler goroutine. Publish the same fact to the
				// authority bridge before the goroutine is launched: a fast
				// frontend can write its callback PublicationAck after the request
				// frame has been consumed but before beginLogicalOperation gets a
				// turn. Every logical operation is reserved here, including
				// read-only publications. The bounded release at operation
				// retirement prevents those nonmutation reservations accumulating
				// on a long-lived mount, while also covering a later mutation
				// continuation without maintaining a second request classifier.
				if a := c.currentAttach(); a != nil {
					if bridge := a.v3CoherenceBridge(); bridge != nil {
						bridge.reserveFrontendPublication(env.OperationID)
					}
				}
			}
			c.handlerWG.Add(1)
			go func(
				a *attach,
				requestID uint64,
				operationID uint64,
				sourcePhaseQueueable bool,
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
					sourcePhaseQueueable,
					initializeOperation,
					body,
				)
			}(c.currentAttach(), env.RequestID, env.OperationID, env.SourcePhaseQueueable, initializeOperation, req)
		}
	}
}

func (c *frontendConn) close() {
	c.closeOnce.Do(func() {
		// A closing transport is not a live native FSKit witness. Retire the
		// witness before any handler join or publication cleanup can block, so
		// mount readiness never observes a connection whose teardown has begun.
		if a := c.currentAttach(); a != nil {
			a.removeNativeFrontendWitness(c)
		}
		// A resource-bearing reply remains owned by this connection until the
		// VolumeCore ownership disposition arrives. Once the connection is gone no
		// such verdict can arrive, so every provisional handle/item is abandoned.
		// Close and detach the table before scanning publications: a handler
		// crossing this point sees the closed verdict and compensates its newly
		// created resources instead of installing another unreachable entry. Do
		// not APPLY abandonment yet. A visible Create/Mkdir/Symlink abandonment is
		// terminal on its own; letting that generic cause run before the exact lost
		// PublicationAck verdict would steal the data plane's one-shot terminal
		// cause and hide why this incarnation became unprovable.
		c.resourceMu.Lock()
		orphanedResources := c.closeProvisionalResourceTableLocked()
		// Freeze publication bookkeeping before joining handlers. Once an
		// exposed reply loses its connection without an acknowledgement, the
		// kernel view is unprovable. Retire and wake the handoff gate before
		// publishing the terminal session verdict: a handler can be waiting behind
		// the very handoff that is waiting for this operation, so handlerWG cannot
		// be joined safely until that cycle has been broken.
		c.publicationMu.Lock()
		c.publicationClosed = true
		orphaned := make([]*frontendOperation, 0, len(c.operations))
		lostPublications := 0
		for _, entry := range c.operations {
			if entry.op == nil {
				continue
			}
			if entry.replyExposed && !entry.ackPending {
				lostPublications++
			}
			orphaned = append(orphaned, entry.op)
		}
		c.publicationMu.Unlock()
		// DEFINITIVE RESOLUTION OF EVERY OUTSTANDING PUBLICATION ACK.
		//
		// Retire every gate member before fencing or joining handlers. A handler
		// may be waiting behind a handoff that is itself waiting for this exact
		// publication; retiring first wakes that cycle. Retirement does not claim
		// the kernel cache is sound. An exposed reply without its acknowledgement
		// is terminal immediately below, because the mount outlives this socket and
		// the daemon cannot prove whether FSKit installed or discarded the frame.
		for _, op := range orphaned {
			op.attach.finishFrontendOperation(op)
		}
		if lostPublications > 0 {
			cause := fmt.Errorf(
				"%w: frontend disconnected after exposing %d publishing reply(s) without PublicationAck",
				errFrontendPublicationUnprovable, lostPublications,
			)
			if a := c.currentAttach(); a != nil {
				a.fenceV3(cause)
			}
			log.Printf("portablefsd: attach %s fenced: %v", c.currentAttachRef(), cause)
		}
		// A handler that reached resource registration during the publication
		// scan has been blocked on resourceMu. Release it only after the exact
		// publication verdict owns failOnce; it will then observe resourceClosed
		// and synchronously abandon without being able to replace that cause.
		c.resourceMu.Unlock()
		if cleanups := abandonV3ProvisionalResources(orphanedResources); len(cleanups) != 0 {
			go func() {
				for _, cleanup := range cleanups {
					if err := cleanup.finish(); err != nil {
						_ = cleanup.d.fail(err)
						return
					}
				}
			}()
		}
		// Only after publication retirement and its exact terminal verdict may
		// connection cancellation race the visibility subscriber's own
		// disconnect failure. Doing this first let a generic context.Canceled win
		// the data plane's one-shot terminal cause before the missing
		// PublicationAck was recorded. Closing the transport now unblocks handlers
		// writing replies; admission and release waits observe the canceled
		// connection context.
		if c.cancel != nil {
			c.cancel()
		}
		_ = c.conn.Close()
		// A handler may still be completing a local syscall or mutation after
		// cancellation. Joining it here keeps connection teardown ordered
		// behind its own handlers; it no longer gates any delegation handoff.
		c.handlerWG.Wait()
		c.publicationMu.Lock()
		pending := c.operations
		c.operations = nil
		c.publicationMu.Unlock()
		for operationID, entry := range pending {
			<-entry.ready
			c.finishLogicalOperation(entry)
			c.releaseFrontendPublication(operationID)
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
		c.v3Events = false
		c.eventsMu.Unlock()
	})
}

// currentAttachRef names this connection's attach for logging. It answers "-"
// for a connection that never resolved one.
func (c *frontendConn) currentAttachRef() string {
	if a := c.currentAttach(); a != nil {
		return a.ref
	}
	return "-"
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

func (c *frontendConn) reply(req uint64, body any) bool {
	return c.replyWithPublication(req, 0, body, false)
}

func resourceBearingV3Reply(body any, collected *v3ReplyResourceCollector) (bool, error) {
	items, handles := 0, 0
	if collected != nil {
		items, handles = len(collected.items), len(collected.handles)
	}
	switch body.(type) {
	case *pfslocal.OpenReply:
		if items != 0 || handles != 1 {
			return true, errors.New("portablefsd: OpenReply did not collect exactly one handle")
		}
	case *pfslocal.CreateReply:
		if collected != nil {
			collected.visible = true
		}
		if items != 1 || handles != 1 {
			return true, errors.New("portablefsd: CreateReply did not collect exactly one item and handle")
		}
	case *pfslocal.LookupReply:
		if items != 1 || handles != 0 {
			return true, fmt.Errorf("portablefsd: %T did not collect exactly one item", body)
		}
	case *pfslocal.MkdirReply, *pfslocal.SymlinkReply:
		if collected != nil {
			collected.visible = true
		}
		if items != 1 || handles != 0 {
			return true, fmt.Errorf("portablefsd: %T did not collect exactly one item", body)
		}
	case *pfslocal.EnumerateReply:
		if handles != 0 {
			return true, errors.New("portablefsd: EnumerateReply unexpectedly collected a handle")
		}
	default:
		if items != 0 || handles != 0 {
			return false, fmt.Errorf("portablefsd: %T collected resources but has no disposition contract", body)
		}
		return false, nil
	}
	return true, nil
}

func (c *frontendConn) registerProvisionalResource(requestID uint64, resources *v3ProvisionalResources) bool {
	if requestID == 0 || resources == nil {
		return false
	}
	c.resourceMu.Lock()
	defer c.resourceMu.Unlock()
	if c.resourceClosed || len(c.provisional) >= maxProvisionalResourcesPerConnection {
		return false
	}
	if c.provisional == nil {
		c.provisional = make(map[uint64]*v3ProvisionalResources)
	}
	if c.provisional[requestID] != nil {
		return false
	}
	c.provisional[requestID] = resources
	return true
}

// registerProvisionalResourceOrAbandon closes the race between a successful
// resource allocation and connection teardown. A failed registration means no
// future disposition can name the reply, so local ownership is withdrawn
// synchronously before the caller closes the transport. Only the authority
// round trips in the returned cleanup may run asynchronously.
func (c *frontendConn) registerProvisionalResourceOrAbandon(
	requestID uint64,
	resources *v3ProvisionalResources,
) (*v3ResourceCleanup, bool, error) {
	if c.registerProvisionalResource(requestID, resources) {
		return nil, true, nil
	}
	cleanup, err := resources.d.applyReplyResourceDisposition(resources, false, 0)
	return cleanup, false, err
}

// closeProvisionalResourceTableLocked prevents any later reply from
// transferring ownership and returns the resources whose disposition can no
// longer arrive. The caller holds resourceMu and decides when registrations
// may resume. It deliberately performs no data-plane transition: close() must
// first record an exact lost-publication verdict before a visible-resource
// abandonment can attempt to fail the same one-shot session with a less
// specific cause.
func (c *frontendConn) closeProvisionalResourceTableLocked() []*v3ProvisionalResources {
	c.resourceClosed = true
	orphaned := make([]*v3ProvisionalResources, 0, len(c.provisional))
	for _, resources := range c.provisional {
		orphaned = append(orphaned, resources)
	}
	c.provisional = nil
	return orphaned
}

func (c *frontendConn) closeProvisionalResourceTable() []*v3ProvisionalResources {
	c.resourceMu.Lock()
	defer c.resourceMu.Unlock()
	return c.closeProvisionalResourceTableLocked()
}

// abandonV3ProvisionalResources performs the synchronous in-memory ownership
// transition and returns only the authority round trips that remain. Keeping
// this transition before handler teardown prevents a later request from
// observing an orphaned handle or item after the connection is already dead.
func abandonV3ProvisionalResources(orphaned []*v3ProvisionalResources) []*v3ResourceCleanup {
	cleanups := make([]*v3ResourceCleanup, 0, len(orphaned))
	for _, resources := range orphaned {
		cleanup, err := resources.d.applyReplyResourceDisposition(resources, false, 0)
		if err != nil {
			_ = resources.d.fail(err)
			continue
		}
		cleanups = append(cleanups, cleanup)
	}
	return cleanups
}

// abandonProvisionalResources is the one-step form for callers that do not
// also own a publication ledger. frontendConn.close uses the split form above
// because its exact missing-ack cause must win before visible abandonment.
func (c *frontendConn) abandonProvisionalResources() []*v3ResourceCleanup {
	return abandonV3ProvisionalResources(c.closeProvisionalResourceTable())
}

func (c *frontendConn) settleProvisionalResource(disposition *pfslocal.ResourceReplyDisposition) bool {
	if disposition == nil || disposition.TargetRequestID == 0 {
		return false
	}
	c.resourceMu.Lock()
	resources := c.provisional[disposition.TargetRequestID]
	if resources != nil {
		delete(c.provisional, disposition.TargetRequestID)
	}
	c.resourceMu.Unlock()
	if resources == nil {
		return false
	}
	cleanup, err := resources.d.applyReplyResourceDisposition(
		resources, disposition.AcceptHandles, disposition.AcceptedItemCount,
	)
	if err != nil {
		_ = resources.d.fail(err)
		return false
	}
	if cleanup.required() {
		go func() {
			if err := cleanup.finish(); err != nil {
				_ = resources.d.fail(err)
			}
		}()
	}
	return true
}

// replyWithPublication writes one reply frame and reports whether that frame
// was delivered without a retraction. A publishing frame is written only after
// markPublicationReplyExposed has pinned its acknowledgement obligation; if
// that callback already acknowledged, the attach is fenced and no frame is
// written.
func (c *frontendConn) replyWithPublication(
	req uint64,
	operationID uint64,
	body any,
	ackRequired bool,
) (delivered bool) {
	if ackRequired && !c.markPublicationReplyExposed(operationID) {
		_ = c.conn.Close()
		return false
	}
	// THE VERDICT AND THE FRAME ARE ONE GATE TRANSITION.
	//
	// The retraction is read under the same lock a crossing takes, and — when it
	// answers "not retracted" — this frame is registered as a carrier the
	// crossing must wait for until the bytes are out. Sampling the verdict and
	// then writing left a gap a handoff fitted into exactly: the frame was built
	// before the crossing and delivered after it, so the frontend installed a
	// view the daemon had already decided to retract, with the only carrier the
	// retraction had already spent. See attach.captureRetractionCarrier.
	retracted, releaseCarrier := c.captureRetraction(operationID)
	defer releaseCarrier()
	if c.testAfterRetractionCapture != nil {
		c.testAfterRetractionCapture(operationID)
	}
	if err := c.write(&pfslocal.Envelope{
		RequestID:              req,
		PublicationAckRequired: ackRequired,
		Body:                   body,
		// THE RETRACTION RIDES THE REPLY, AND THAT IS THE WHOLE ORDERING.
		//
		// A handoff that crossed this operation needs the frontend to discard
		// what the operation collected BEFORE the framework installs it, and
		// the install happens the instant the callback returns. Stamping the
		// verdict on the reply the callback is waiting for makes that ordering
		// a property of the byte stream rather than of anything the two sides
		// have to agree about: one frame, delivered once, and the callback
		// cannot proceed past it.
		//
		// It is read on EVERY reply of the operation, not only publishing ones.
		// The reply that unblocks the callback is the initiator's — the request
		// parked inside the delegation release — and whether that request
		// happens to publish is unrelated to whether it is the last one the
		// callback is waiting for.
		PublicationRetracted: retracted,
	}); err != nil {
		log.Printf("frontend write reply: %v", err)
		_ = c.conn.Close()
		return false
	}
	return !retracted
}

// publicationRetracted answers whether a delegation handoff has crossed this
// operation, so its reply must tell the frontend to install nothing.
//
// ── THE INVARIANT THE FRONTEND DEPENDS ON, CHECKED HERE ─────────────────────
//
// A retraction is only ever carried on an operation that has ALREADY written an
// acknowledgement-required reply on this connection. The frontend relies on
// that: it learns which connection owes the acknowledgement from the earlier
// ack-required reply, so a retraction arriving as an operation's FIRST reply
// would leave it holding no connection to acknowledge on, and the daemon would
// wait out its settle window for an acknowledgement nobody could send.
//
// The invariant is structural — op.retracted is set only by a crossing, and
// publicationBlockersLocked only ever nominates an operation with op.published
// set, which notePublicationExposed sets from markPublicationReplyExposed, i.e.
// from a written ack-required reply on this same connection. An operation never
// spans connections either: it is created per connection and every operation is
// retired when its connection closes.
//
// It is checked rather than assumed anyway, because the failure it prevents is
// a silent hang rather than a wrong answer, and because "structural" is a claim
// about code that has now been rearranged several times. A retraction that
// somehow reached an unexposed operation is DROPPED and announced, which fails
// towards the behaviour that existed before retractions did.
func (c *frontendConn) publicationRetracted(operationID uint64) bool {
	retracted, release := c.captureRetraction(operationID)
	release()
	return retracted
}

// captureRetraction is publicationRetracted for the reply that will CARRY the
// verdict: it takes the gate transition rather than a sample, and the returned
// release must run once the frame is on the wire. See
// attach.captureRetractionCarrier.
func (c *frontendConn) captureRetraction(operationID uint64) (bool, func()) {
	noop := func() {}
	if operationID == 0 {
		return false, noop
	}
	c.publicationMu.Lock()
	entry := c.operations[operationID]
	var (
		op      *frontendOperation
		exposed bool
	)
	if entry != nil {
		op, exposed = entry.op, entry.replyExposed
	}
	c.publicationMu.Unlock()
	if op == nil {
		return false, noop
	}
	// publicationMu is released first. The gate lock is taken from this
	// connection's side in exactly one other place
	// (markPublicationReplyExposed) and with the same discipline, so the two
	// stay unordered rather than newly nested.
	retracted, release := op.attach.captureRetractionCarrier(op)
	if !retracted {
		return false, release
	}
	release()
	if !exposed {
		log.Printf(
			"portablefsd: attach %s retracted logical operation %d before it had "+
				"exposed any reply; the retraction is dropped because the frontend "+
				"would have no connection to acknowledge it on",
			op.attach.ref, operationID,
		)
		return false, noop
	}
	return true, noop
}

func (c *frontendConn) markPublicationReplyExposed(operationID uint64) bool {
	c.publicationMu.Lock()
	entry := c.operations[operationID]
	if c.publicationClosed ||
		entry == nil ||
		entry.op == nil {
		c.publicationMu.Unlock()
		return false
	}
	if entry.ackPending {
		// The callback has ended, so this frame cannot be installed and cannot
		// acquire a second acknowledgement. If the request was a visible mutation,
		// its authority result may already be durable while the source kernel still
		// holds its pre-mutation cache. Refuse to write the frame and fence before
		// any caller can treat it as a successful publication.
		op := entry.op
		c.publicationMu.Unlock()
		op.attach.finishFrontendOperation(op)
		op.attach.fenceV3(fmt.Errorf(
			"%w: logical operation %d produced a publishing reply after its callback acknowledged",
			errFrontendPublicationUnprovable, operationID,
		))
		return false
	}
	entry.replyExposed = true
	op := entry.op
	c.publicationMu.Unlock()
	// PUBLISH THE OBLIGATION TO THE HANDOFF GATE BEFORE THE BYTES GO OUT.
	//
	// replyWithPublication calls this and only then writes the frame, so the
	// gate learns that this logical operation owes an acknowledgement while the
	// daemon can still decide what a delegation handoff is allowed to do about
	// it. Recording it after the write would leave a window in which the reply
	// is on the wire and the barrier does not know — which is precisely the
	// state finding 5 describes, reached by a different route.
	//
	// The gate lock is taken with publicationMu RELEASED. That direction is the
	// established one (beginLogicalOperation drops publicationMu before every
	// reserve/activate call), and nothing under frontendGateMu ever reaches
	// back into a connection's publication table, so the two locks stay
	// unordered with respect to each other rather than newly nested.
	op.attach.notePublicationExposed(op)
	return true
}

func (c *frontendConn) errorReply(req uint64, eno int32, msg string) {
	c.reply(req, &pfslocal.ErrorReply{Errno: eno, Message: msg})
}

// errorReplyForOperation is errorReply for a request that belongs to a logical
// operation but does not publish. It exists only so the reply can carry a
// retraction: a non-publishing request is very often the LAST one a framework
// callback is waiting for, and a retraction that misses that reply misses the
// only carrier it had.
func (c *frontendConn) errorReplyForOperation(req, operationID uint64, eno int32, msg string) {
	_ = c.replyWithPublication(
		req, operationID, &pfslocal.ErrorReply{Errno: eno, Message: msg}, false,
	)
}

// admitLaneRequestID enforces per-lane replay protection. Request IDs are
// allocated in one increasing sequence but written on two lanes, and the
// control lane (visibility acknowledgments, liveness) deliberately overtakes
// queued ordinary requests — so a control frame may legally arrive carrying a
// lower ID than an ordinary frame already received. Each lane is FIFO with
// increasing IDs within itself; that per-lane monotonicity is the replay
// protection, and enforcing it globally once killed healthy mounts the
// moment a barrier acknowledgment overtook a request burst.
func admitLaneRequestID(body any, id uint64, lastRequest, lastControl *uint64) (lane string, ok bool) {
	watermark := lastRequest
	lane = "request"
	switch body.(type) {
	case *pfslocal.VisibilityAckRequest, *pfslocal.V3LivenessRequest:
		watermark = lastControl
		lane = "control"
	}
	if id == 0 || id <= *watermark {
		return lane, false
	}
	*watermark = id
	return lane, true
}

// acknowledgePublication retires the logical operation the frontend has
// finished with.
//
// ── AN ACKNOWLEDGEMENT MAY ARRIVE BEFORE THE REPLY IS EXPOSED ───────────────
//
// It used to refuse an operation with no exposed reply, treating that as a
// protocol violation and killing the connection. That was right when the
// frontend created its acknowledgement obligation on RECEIVING an ack-required
// reply; it is wrong now that the obligation is created when the operation ID is
// STAMPED ON A REQUEST, which is also the moment the daemon creates the
// operation. The two now agree on when the obligation begins, and the honest
// consequence is that a frontend can finish a callback — and say so — for a
// request this daemon has not answered yet.
//
// That is not a violation, it is the case that used to strand: the frontend gave
// up on a reply (its own deadline, a dropped frame) while a handler here was
// still running. Accepting the acknowledgement is also the SAFER reading of it,
// because it says the callback installed nothing it has not already accounted
// for — and a reply the frontend never observed installed nothing at all.
//
// markPublicationReplyExposed completes the pair: a publishing reply that
// arrives after this point cannot be delivered to the finished callback, so it
// fences the attach instead of pretending the earlier acknowledgement covers a
// frame the frontend never observed.
func (c *frontendConn) acknowledgePublication(operationID uint64) bool {
	c.publicationMu.Lock()
	entry := c.operations[operationID]
	if entry == nil ||
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
		c.finishLogicalOperation(entry)
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
	inactive := entry.activeRequests == 0
	finish := entry.ackPending && inactive
	if finish {
		delete(c.operations, operationID)
	}
	c.publicationMu.Unlock()
	if inactive {
		c.releaseFrontendPublication(operationID)
	}
	if finish {
		c.finishLogicalOperation(entry)
	}
}

func (c *frontendConn) finishLogicalOperation(entry *frontendOperationEntry) {
	if entry != nil && entry.op != nil {
		entry.op.attach.finishFrontendOperation(entry.op)
	}
}

// releaseFrontendPublication closes the authority bridge's serial-reader
// reservation when activeRequests reaches zero. That point proves no handler
// can still enter registerMutation. A state with no mutation ticket is therefore
// a read-only publication or a pre-dispatch refusal and is safe to discard; a
// visible mutation ticket keeps the channel through source COMPLETE.
func (c *frontendConn) releaseFrontendPublication(operationID uint64) {
	if a := c.currentAttach(); a != nil {
		if bridge := a.v3CoherenceBridge(); bridge != nil {
			bridge.releaseFrontendPublication(operationID)
		}
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
	if entry == nil {
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
	sourcePhaseQueueable bool,
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
	// An authority-v3 attach is served by the v3 data plane through its own
	// handler: it keeps the logical-operation/PublicationAck ledger this
	// connection owns but never enters the clientcore admission, mirror, or
	// delegation machinery below (see v3attach.go).
	c.handleV3Attached(
		ctx, a, requestID, operationID, sourcePhaseQueueable,
		initializeOperation, body,
	)
}

func (c *frontendConn) handleVisibilityAck(ctx context.Context, requestID uint64, request *pfslocal.VisibilityAckRequest) {
	a := c.currentAttach()
	if a == nil {
		c.errorReply(requestID, darwinENXIO, "v3 attach is unavailable")
		return
	}
	bridge := a.v3CoherenceBridge()
	if bridge == nil {
		c.errorReply(requestID, darwinENOTSUP, "attach does not use v3 visibility")
		return
	}
	if err := bridge.acknowledge(ctx, request); err != nil {
		errno := darwinEIO
		if errors.Is(err, syscall.EINVAL) {
			errno = darwinEINVAL
		}
		c.errorReply(requestID, errno, err.Error())
		return
	}
	c.reply(requestID, &pfslocal.VisibilityAckReply{})
}

func (c *frontendConn) subscribeEvents(a *attach) error {
	c.eventsMu.Lock()
	defer c.eventsMu.Unlock()
	if c.v3Events {
		return nil
	}
	bridge := a.v3CoherenceBridge()
	if bridge == nil {
		return fmt.Errorf("attach has no visibility stream")
	}
	c.v3Events = true
	go func() {
		err := bridge.run(c.connCtx, func(event *pfslocal.Event) error {
			return c.write(&pfslocal.Envelope{RequestID: 0, Body: event})
		})
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			log.Printf("portablefsd: attach %s v3 visibility stream failed: %v", a.ref, err)
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
