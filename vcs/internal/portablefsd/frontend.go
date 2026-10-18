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
	v3Events bool

	publicationMu     sync.Mutex
	operations        map[uint64]*frontendOperationEntry
	lastOperationID   uint64
	publicationClosed bool
	connectionClosed  atomic.Bool
	closeOnce         sync.Once
	inFlight          atomic.Int32
	handlerWG         sync.WaitGroup

	resourceMu     sync.Mutex
	provisional    map[uint64]*v3ProvisionalResources
	resourceClosed bool

	// testBeforeReplyWrite pauses a candidate before its eligibility check.
	// Nil in production.
	testBeforeReplyWrite func(operationID uint64)
}

type frontendOperationEntry struct {
	ready          chan struct{}
	attach         *attach
	err            error
	activeRequests int
	replyExposed   bool
	ackPending     bool
}

var errFrontendPublicationUnprovable = errors.New(
	"portablefsd: FSKit frontend publication is unprovable",
)

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
			if req.OperationID == 0 ||
				(req.SemanticCommit != pfslocal.PublicationSemanticCommitPublished &&
					req.SemanticCommit != pfslocal.PublicationSemanticCommitNotPublished) {
				log.Printf(
					"portablefsd frontend: closing connection: malformed publication ack (operationID=%d semanticCommit=%d)",
					req.OperationID, req.SemanticCommit,
				)
				return
			}
			if a := c.currentAttach(); a != nil {
				if bridge := a.v3CoherenceBridge(); bridge != nil {
					known, err := bridge.acknowledgePublication(c.callback(req.OperationID), req.SemanticCommit)
					if err != nil {
						// The source coordinator made the terminal decision while it
						// still owned the exact lease. Fence the attach before any
						// frontend publication bookkeeping can release a broader gate.
						a.stopV3Serving(err)
						log.Printf("portablefsd frontend: closing connection: publication semantic commit failed for operation %d: %v", req.OperationID, err)
						return
					}
					if !known {
						log.Printf("portablefsd frontend: closing connection: publication ack for unknown or already-acknowledged operation %d", req.OperationID)
						return
					}
				}
			}
			if !c.acknowledgePublication(req.OperationID) {
				log.Printf("portablefsd frontend: closing connection: publication ack for unknown or already-acknowledged operation %d", req.OperationID)
				return
			}
			continue
		} else {
			lane, ok := admitRequestID(env.RequestID, &lastRequestID)
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
				c.helloClientName == shippingFSKitFrontendClientName {
				a.registerFrontendWitness(c)
			}
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
						bridge.reserveFrontendPublication(c.callback(env.OperationID))
					}
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
					context.WithValue(connCtx, v3CallbackContextKey{}, c.origin),
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
		c.connectionClosed.Store(true)
		// A closing transport is not a live native FSKit witness. Retire the
		// witness before any handler join or publication cleanup can block, so
		// mount readiness never observes a connection whose teardown has begun.
		if a := c.currentAttach(); a != nil {
			a.removeFrontendWitness(c)
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
		// An exposed reply without its ack leaves the kernel view unproven.
		// Publish this exact cause before cancellation races other terminal paths.
		c.publicationMu.Lock()
		c.publicationClosed = true
		lostPublications := 0
		for _, entry := range c.operations {
			if entry.attach != nil && entry.replyExposed && !entry.ackPending {
				lostPublications++
			}
		}
		c.publicationMu.Unlock()
		if lostPublications > 0 {
			cause := fmt.Errorf(
				"%w: frontend disconnected after exposing %d publishing reply(s) without PublicationAck",
				errFrontendPublicationUnprovable, lostPublications,
			)
			log.Printf("portablefsd: attach %s stopped serving: %v", c.currentAttachRef(), cause)
			if a := c.currentAttach(); a != nil {
				a.stopV3Serving(cause)
			}
		}
		// A handler that reached resource registration during the publication
		// scan has been blocked on resourceMu. Release it only after the exact
		// publication verdict owns failOnce; it will then observe resourceClosed
		// and synchronously abandon without being able to replace that cause.
		c.resourceMu.Unlock()
		if cleanups := abandonV3ProvisionalResources(orphanedResources); len(cleanups) != 0 {
			go func() {
				// Every orphaned cleanup finishes, even after one fails, so its
				// share of the cleanup debt settles; a failure is terminal and
				// the rest then send nothing.
				for _, cleanup := range cleanups {
					_ = cleanup.finish()
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
		if a := c.currentAttach(); a != nil {
			if b := a.v3CoherenceBridge(); b != nil {
				b.frontendClosing(c.origin)
			}
		}
		if c.cancel != nil {
			c.cancel()
		}
		_ = c.conn.Close()
		for _, resources := range orphanedResources {
			consumeV3ProvisionalResponses(resources)
		}
		// A handler may still be completing a local syscall or mutation after
		// cancellation. Joining it here keeps connection teardown ordered
		// behind its own handlers.
		c.handlerWG.Wait()
		c.publicationMu.Lock()
		pending := c.operations
		c.operations = nil
		c.publicationMu.Unlock()
		for operationID, entry := range pending {
			<-entry.ready
			// No byte of an unexposed callback reached FSKit. Retire its own
			// nonpublication verdict; an applied mutation still terminals the mount.
			if !entry.replyExposed && !entry.ackPending && entry.attach != nil {
				if bridge := entry.attach.v3CoherenceBridge(); bridge != nil {
					_, _ = bridge.acknowledgePublication(c.callback(operationID), pfslocal.PublicationSemanticCommitNotPublished)
				}
			}
			c.finishLogicalOperation(operationID, entry)
		}
		if a := c.currentAttach(); a != nil {
			a.removeConn(c.conn)
		}
		c.eventsMu.Lock()
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

	if c.origin == 0 {
		c.origin = a.newOrigin()
		if c.origin == 0 {
			c.attachMu.Unlock()
			return false
		}
	}
	c.attach = a
	c.attachMu.Unlock()
	a.addConn(c.conn)
	return true
}

func (c *frontendConn) write(env *pfslocal.Envelope) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return pfslocal.WriteFrame(c.conn, env)
}

// writeCommitted writes env unless commit, evaluated under the frame write
// lock, refuses it. Every terminal revocation of this connection takes the
// same lock, so a reply commit admits is either written before a revocation
// or commit has already observed it. commit may take the source-publication
// coordinator and d.mu (writeMu → coordinator → d.mu); it must not wait.
func (c *frontendConn) writeCommitted(env *pfslocal.Envelope, commit func() bool) (bool, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if commit != nil && !commit() {
		return false, nil
	}
	return true, pfslocal.WriteFrame(c.conn, env)
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
	default:
		if items != 0 || handles != 0 {
			return false, fmt.Errorf("portablefsd: %T collected resources but has no disposition contract", body)
		}
		return false, nil
	}
	return true, nil
}

func (c *frontendConn) registerProvisionalResource(requestID uint64, resources *v3ProvisionalResources) bool {
	if requestID == 0 || resources == nil || resources.d == nil {
		return false
	}
	c.resourceMu.Lock()
	defer c.resourceMu.Unlock()
	// Abandoned resources still awaiting authority cleanup share the bound. It
	// is a terminal capacity guard, not backpressure: a refused registration
	// makes the handler abandon the reply and stop serving the mount.
	if c.resourceClosed ||
		len(c.provisional)+resources.d.outstandingCleanup() >= maxProvisionalResourcesPerConnection {
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
		// Validation failed before applyReplyResourceDisposition could transfer
		// or retire anything. The table entry is already detached, so explicitly
		// abandon the exact provisional reply before revoking the connection;
		// otherwise its handle/item capabilities would become unreachable until
		// whole-attach teardown.
		abandonCleanup, abandonErr := resources.d.applyReplyResourceDisposition(resources, false, 0)
		if abandonErr != nil {
			err = errors.Join(err, abandonErr)
		}
		c.revokeV3ResponseConsumption(c.currentAttach(), err)
		consumeV3ProvisionalResponses(resources)
		if abandonCleanup.required() {
			go func() {
				_ = abandonCleanup.finish()
			}()
		}
		return false
	}
	consumeV3ProvisionalResponses(resources)
	if cleanup.required() {
		go func() {
			_ = cleanup.finish()
		}()
	}
	return true
}

// replyWithPublication writes one reply frame and reports whether that frame
// was delivered. A publishing frame is written only after
// markPublicationReplyExposed has pinned its acknowledgement obligation; if
// that callback already acknowledged, the attach is fenced and no frame is
// written.
func (c *frontendConn) replyWithPublication(
	req uint64,
	operationID uint64,
	body any,
	ackRequired bool,
) (delivered bool) {
	delivered, _ = c.replyWithPublicationWriteStatus(req, operationID, body, ackRequired)
	return delivered
}

func (c *frontendConn) replyWithPublicationWriteStatus(
	req uint64,
	operationID uint64,
	body any,
	ackRequired bool,
) (delivered bool, written bool) {
	delivered, written, _ = c.replyWithPublicationDisposition(
		req, operationID, body, ackRequired, false,
	)
	return delivered, written
}

// replyWithPublicationDisposition reports a third outcome for a response
// which arrived after its callback had already acknowledged NOT_PUBLISHED (or
// had already published another response in the same logical operation). A
// proven read-only/definite-no-apply response is discarded without a frame;
// an applied mutation is never eligible for this path.
func (c *frontendConn) replyWithPublicationDisposition(
	req uint64,
	operationID uint64,
	body any,
	ackRequired bool,
	lateDiscardable bool,
) (delivered bool, written bool, discarded bool) {
	delivered, written, discarded, _ = c.replyWithPublicationCommit(req, operationID, body, ackRequired, lateDiscardable, nil)
	return delivered, written, discarded
}

// replyWithPublicationCommit adds a fourth outcome for a reply computed from
// the daemon cache: commit, run at the physical write boundary, may refuse
// it. Nothing is written then, and the caller settles the unexposed candidate
// and takes the coherent authority path inside the same operation.
func (c *frontendConn) replyWithPublicationCommit(
	req uint64,
	operationID uint64,
	body any,
	ackRequired bool,
	lateDiscardable bool,
	commit func() bool,
) (delivered bool, written bool, discarded bool, refused bool) {
	if ackRequired {
		exposed, lateDiscarded := c.markPublicationReplyExposedForV3(operationID, lateDiscardable)
		if !exposed {
			if !lateDiscarded {
				_ = c.conn.Close()
			}
			return false, false, lateDiscarded, false
		}
	}
	if c.testBeforeReplyWrite != nil {
		c.testBeforeReplyWrite(operationID)
	}
	admitted, err := c.writeCommitted(&pfslocal.Envelope{
		RequestID: req, PublicationAckRequired: ackRequired,
		OperationID: operationID, Body: body,
	}, commit)
	if err != nil {
		log.Printf("frontend write reply: %v", err)
		_ = c.conn.Close()
		return false, false, false, false
	}
	if !admitted {
		return false, false, false, true
	}
	return true, true, false, false
}

func (c *frontendConn) markPublicationReplyExposed(operationID uint64) bool {
	exposed, _ := c.markPublicationReplyExposedForV3(operationID, false)
	return exposed
}

func (c *frontendConn) markPublicationReplyExposedForV3(
	operationID uint64,
	lateDiscardable bool,
) (exposed bool, discarded bool) {
	c.publicationMu.Lock()
	entry := c.operations[operationID]
	if c.publicationClosed ||
		entry == nil ||
		entry.attach == nil {
		c.publicationMu.Unlock()
		return false, false
	}
	if entry.ackPending {
		if lateDiscardable {
			c.publicationMu.Unlock()
			return false, true
		}
		// The callback has ended, so this frame cannot be installed and cannot
		// acquire a second acknowledgement. If the request was a visible mutation,
		// its authority result may already be durable while the source kernel still
		// holds its pre-mutation cache. Refuse to write the frame and fence before
		// any caller can treat it as a successful publication.
		a := entry.attach
		c.publicationMu.Unlock()
		a.stopV3Serving(fmt.Errorf(
			"%w: logical operation %d produced a publishing reply after its callback acknowledged",
			errFrontendPublicationUnprovable, operationID,
		))
		return false, false
	}
	entry.replyExposed = true
	c.publicationMu.Unlock()
	return true, false
}

func (c *frontendConn) errorReply(req uint64, eno int32, msg string) {
	c.reply(req, &pfslocal.ErrorReply{Errno: eno, Message: msg})
}

// errorReplyForOperation preserves the callback identity on a nonpublishing error.
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
		c.finishLogicalOperation(operationID, entry)
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
	if finish {
		c.finishLogicalOperation(operationID, entry)
	}
}

func (c *frontendConn) finishLogicalOperation(operationID uint64, entry *frontendOperationEntry) {
	if entry != nil && entry.attach != nil {
		if bridge := entry.attach.v3CoherenceBridge(); bridge != nil {
			// One reservation covers the entire callback, including gaps between
			// requests; finalization waits for every handler and PublicationAck.
			bridge.releaseFrontendPublication(c.callback(operationID))
			_ = bridge.finishFrontendPublication(c.callback(operationID))
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
	ctx context.Context, a *attach, operationID uint64, initialize bool, body any,
) (bool, error) {
	publishes := frontendRequestPublishes(body)
	if operationID == 0 {
		if publishes {
			return false, fmt.Errorf("invalid frontend operation id")
		}
		return false, nil
	}
	if initialize && !publishes {
		return false, fmt.Errorf("frontend operation id began with a nonpublishing request")
	}
	c.publicationMu.Lock()
	entry := c.operations[operationID]
	if c.publicationClosed {
		if initialize && entry != nil {
			entry.err = net.ErrClosed
			close(entry.ready)
		}
		c.publicationMu.Unlock()
		return false, net.ErrClosed
	}
	if entry == nil {
		c.publicationMu.Unlock()
		return false, fmt.Errorf("frontend operation was not reserved")
	}
	if initialize {
		entry.attach = a
		close(entry.ready)
		c.publicationMu.Unlock()
		return publishes, nil
	}
	c.publicationMu.Unlock()
	select {
	case <-entry.ready:
		return publishes, entry.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (c *frontendConn) handleAttached(
	ctx context.Context,
	a *attach,
	requestID uint64,
	operationID uint64,
	initializeOperation bool,
	body any,
) {
	c.handleV3Attached(
		ctx, a, requestID, operationID,
		initializeOperation, body,
	)
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
	if err := bridge.bind(); err != nil {
		return err
	}
	bridge.mu.Lock()
	if c.helloClientName == shippingFSKitFrontendClientName {
		bridge.frontendOrigin = c.origin
	}
	bridge.mu.Unlock()
	c.v3Events = true
	go func() {
		err := bridge.runBound(c.connCtx, func(event *pfslocal.Event) error {
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

func admitRequestID(id uint64, last *uint64) (string, bool) {
	if id == 0 || id <= *last {
		return "request", false
	}
	*last = id
	return "request", true
}
func (c *frontendConn) callback(operation uint64) v3CallbackID {
	return v3CallbackID{origin: c.origin, operation: operation}
}
