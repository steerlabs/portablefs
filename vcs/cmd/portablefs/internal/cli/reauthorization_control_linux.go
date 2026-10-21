//go:build linux

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
)

const maxLocalReauthorizationRequestBytes = mountcontrol.MaxOrdinaryRequest
const maxFuseMountControlConnections = 8

const fuseReauthorizationSocketPrefix = "@portablefs-reauthorization-"

type localReauthorizationRequest = mountcontrol.Request
type localReauthorizationResponse = mountcontrol.Response

// Workspace handlers stay nil until the real lifecycle, kernel and clock
// owners exist. A seeded supervisor alone never enables managed mounts.
type workspaceControlConfig struct {
	Supervisor mountcontrol.Peer
	Owner      mountcontrol.Owner
}

type unixReauthorizationControl struct {
	workspace                            *workspaceControlConfig
	workspaceConnections                 map[*net.UnixConn]bool
	workspacePhase, workspaceObservation bool
	done                                 chan struct{}
	ctx                                  context.Context
	cancel                               context.CancelFunc
	handler                              fuseReauthorizationHandler
	lossSnapshot                         fuseLossSnapshotHandler
	listener                             *net.UnixListener
	mu                                   sync.Mutex
	connections                          map[*net.UnixConn]uint64
	nextArrival                          uint64
	changed                              chan struct{}
	workers                              sync.WaitGroup
	closed                               bool
	closeErr                             error
	once                                 sync.Once
	path                                 string
}

func startFuseReauthorizationControl(handler fuseReauthorizationHandler, lossSnapshot fuseLossSnapshotHandler) (fuseReauthorizationControl, error) {
	return startFuseMountControl(handler, lossSnapshot, nil)
}
func startFuseMountControl(handler fuseReauthorizationHandler, lossSnapshot fuseLossSnapshotHandler, workspace *workspaceControlConfig) (fuseReauthorizationControl, error) {
	if handler == nil && lossSnapshot == nil && workspace == nil {
		return nil, errors.New("mount control handler is required")
	}
	path, err := newFuseReauthorizationSocketName()
	if err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on reauthorization control socket: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	control := &unixReauthorizationControl{
		done: make(chan struct{}), ctx: ctx, cancel: cancel, workspace: workspace, workspaceConnections: make(map[*net.UnixConn]bool),
		handler: handler, lossSnapshot: lossSnapshot, listener: listener,
		connections: make(map[*net.UnixConn]uint64), changed: make(chan struct{}), path: path,
	}
	go control.serve()
	return control, nil
}

// newFuseReauthorizationSocketName allocates a lifetime-scoped Linux abstract
// Unix socket. This control endpoint belongs to the live mount supervisor, not
// to durable mount state: an abstract address disappears with its listener and
// cannot leave a stale filesystem node after a crash. A cryptographic nonce
// prevents another process from predicting and pre-binding the address, while
// SO_PEERCRED supplies the UID authorization boundary after connect.
//
// Keeping the address independent of stateDir is also correctness-critical:
// sockaddr_un.sun_path is bounded even when a valid home or XDG state path is
// not. The complete address below is always far inside that kernel bound.
func newFuseReauthorizationSocketName() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("allocate reauthorization control identity: %w", err)
	}
	return fmt.Sprintf("%s%d-%x", fuseReauthorizationSocketPrefix, os.Geteuid(), nonce), nil
}

func validReauthorizationControlAddress(address string) bool {
	prefix := fmt.Sprintf("%s%d-", fuseReauthorizationSocketPrefix, os.Geteuid())
	nonce := strings.TrimPrefix(address, prefix)
	if nonce == address || len(nonce) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(nonce)
	return err == nil && len(decoded) == 16
}

func (c *unixReauthorizationControl) SocketPath() string { return c.path }

func (c *unixReauthorizationControl) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancel()
		c.closeErr = c.listener.Close()
		for connection := range c.connections {
			_ = connection.Close()
		}
		c.mu.Unlock()
		<-c.done
		if c.workspace != nil {
			c.workspace.Owner.Close()
		}
	})
	if errors.Is(c.closeErr, net.ErrClosed) {
		return nil
	}
	return c.closeErr
}

func (c *unixReauthorizationControl) serve() {
	defer func() {
		c.workers.Wait()
		close(c.done)
	}()
	for {
		connection, err := c.listener.AcceptUnix()
		if err != nil {
			return
		}
		// Peer identity is classified before either capacity pool is reserved.
		peer, peerErr := mountcontrol.Credentials(connection)
		var supervisor *mountcontrol.Peer
		if c.workspace != nil {
			supervisor = &c.workspace.Supervisor
		}
		// Only the seeded root candidate needs a process-start witness. Ordinary
		// same-UID peers may legitimately be outside our /proc PID namespace.
		if peerErr == nil && supervisor != nil && peer.UID == 0 && peer.PID == supervisor.PID {
			peer.Start, peerErr = mountcontrol.ProcessStart(peer.PID)
		}
		class := mountcontrol.Classify(peer, uint32(os.Geteuid()), supervisor)
		if peerErr != nil || class == mountcontrol.Refused {
			_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
			writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "peer refused"})
			_ = connection.Close()
			continue
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = connection.Close()
			return
		}
		if class == mountcontrol.WorkspacePeer && len(c.workspaceConnections) >= 2 || class == mountcontrol.Ordinary && len(c.connections)-len(c.workspaceConnections) >= maxFuseMountControlConnections {
			c.mu.Unlock()
			_ = connection.Close()
			continue
		}
		if c.nextArrival == ^uint64(0) {
			c.mu.Unlock()
			_ = connection.Close()
			continue
		}
		// Accept order fixes renewal order even when an earlier peer has only
		// sent a partial request. Snapshots may still pass those waiting peers.
		c.nextArrival++
		arrival := c.nextArrival
		c.connections[connection] = arrival
		if class == mountcontrol.WorkspacePeer {
			c.workspaceConnections[connection] = true
		}
		c.workers.Add(1)
		c.mu.Unlock()
		go func() {
			defer c.workers.Done()
			c.handlePeer(connection, arrival, class, peer)
			c.mu.Lock()
			delete(c.connections, connection)
			delete(c.workspaceConnections, connection)
			close(c.changed)
			c.changed = make(chan struct{})
			c.mu.Unlock()
		}()
	}
}

func (c *unixReauthorizationControl) waitForEarlierConnections(ctx context.Context, arrival uint64) error {
	for {
		c.mu.Lock()
		var earlier bool
		for connection, accepted := range c.connections {
			if accepted < arrival && !c.workspaceConnections[connection] {
				earlier = true
				break
			}
		}
		if !earlier {
			c.mu.Unlock()
			return ctx.Err()
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (c *unixReauthorizationControl) handlePeer(connection *net.UnixConn, arrival uint64, class mountcontrol.PeerClass, peer mountcontrol.Peer) {
	defer connection.Close()
	attemptStarted := time.Now()
	socketBudget := 35 * time.Second
	limit := mountcontrol.MaxOrdinaryRequest
	if class == mountcontrol.WorkspacePeer {
		limit = mountcontrol.MaxWorkspaceRequest
		socketBudget = 45 * time.Second
	}
	_ = connection.SetDeadline(attemptStarted.Add(socketBudget))
	body, rights, err := mountcontrol.Receive(connection, limit)
	defer rights.Close()
	if err != nil {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "invalid request"})
		return
	}
	request, err := mountcontrol.DecodeRequest(body)
	if err != nil {
		if class == mountcontrol.WorkspacePeer {
			gone, pollErr := mountcontrol.FullHangup(connection)
			if pollErr != nil || gone {
				return
			}
		}
		if class == mountcontrol.WorkspacePeer && c.workspace.Owner.CloseAdmission != nil {
			c.workspace.Owner.CloseAdmission()
		}
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "invalid request"})
		return
	}
	if request.Workspace != nil {
		if class != mountcontrol.WorkspacePeer || c.workspace == nil {
			writeLocalReauthorizationResponse(connection, mountcontrol.WorkspaceRefusal(request, mountcontrol.ErrPeerRefused))
			return
		}
		// A complete authenticated Close survives root death; partial frames do
		// not establish one. Admission closure does not accept a job.
		if err := c.workspace.Owner.AdmitFrame(request, rights); err != nil {
			writeLocalReauthorizationResponse(connection, mountcontrol.WorkspaceRefusal(request, err))
			return
		}
		gone, pollErr := mountcontrol.FullHangup(connection)
		if pollErr != nil || gone {
			return
		}
		c.mu.Lock()
		lane := &c.workspacePhase
		if request.Operation == "workspace-observe" {
			lane = &c.workspaceObservation
		}
		if *lane {
			c.mu.Unlock()
			writeLocalReauthorizationResponse(connection, mountcontrol.WorkspaceRefusal(request, mountcontrol.ErrOccupied))
			return
		}
		*lane = true
		c.mu.Unlock()
		defer func() { c.mu.Lock(); *lane = false; c.mu.Unlock() }()
		budget, _ := strconv.ParseUint(request.Workspace.BudgetNanos, 10, 64)
		deadline := attemptStarted.Add(time.Duration(budget))
		_ = connection.SetDeadline(deadline)
		ctx, cancel := context.WithDeadline(c.ctx, deadline)
		defer cancel()
		if ctx.Err() != nil {
			return
		}
		stop := mountcontrol.WatchDisconnect(ctx, connection, peer, cancel)
		defer stop()
		response, err := c.workspace.Owner.DoAdmitted(ctx, request, rights, attemptStarted)
		if err != nil {
			writeLocalReauthorizationResponse(connection, mountcontrol.WorkspaceRefusal(request, err))
			return
		}
		writeLocalReauthorizationResponse(connection, response)
		return
	}
	if class != mountcontrol.Ordinary || rights.Validate(request.Operation) != nil {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "invalid ordinary peer or descriptors"})
		return
	}
	if request.Operation == "loss-snapshot" {
		if c.lossSnapshot == nil || !mountid.ValidMountInstance(request.MountInstanceID) || request.Sequence != 0 || request.Capability != "" || request.ClientCertificatePEM != "" {
			writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "invalid loss snapshot request"})
			return
		}
		snapshot, err := c.lossSnapshot()
		if err != nil || snapshot.MountInstanceID != request.MountInstanceID || !validLossSequence(snapshot.LossSequence) {
			writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "exact live mount loss snapshot unavailable"})
			return
		}
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{OK: true, MountInstanceID: snapshot.MountInstanceID, LossSequence: snapshot.LossSequence})
		return
	}
	if request.Operation != "" || request.MountInstanceID != "" || c.handler == nil || request.Sequence == 0 || request.Capability == "" || len(request.Capability) > 32<<10 || request.ClientCertificatePEM == "" || len(request.ClientCertificatePEM) > maxClientIdentityBytes {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "reauthorization unavailable or invalid request"})
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	if err := c.waitForEarlierConnections(ctx, arrival); err != nil {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "reauthorization unavailable", OK: false})
		return
	}
	if c.workspace != nil {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "managed manual reauthorization is unavailable; the renewal owner is exclusive"})
		return
	}
	deadline, err := c.handler(ctx, request.Capability, request.Sequence, []byte(request.ClientCertificatePEM))
	if err != nil {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "authority refused reauthorization", OK: false})
		return
	}
	writeLocalReauthorizationResponse(connection, localReauthorizationResponse{
		AuthorizationDeadlineUnixMs: deadline.UnixMilli(), OK: true, Sequence: request.Sequence,
	})
}

func writeLocalReauthorizationResponse(writer io.Writer, response localReauthorizationResponse) {
	_ = mountcontrol.WriteResponse(writer, response)
}

func reauthorizeFuseMount(ctx context.Context, state *mountState, token string, sequence uint64, certificatePEM []byte) (time.Time, error) {
	if state == nil || state.ReauthorizationControlSocket == "" {
		return time.Time{}, errors.New("FUSE mount has no reauthorization control socket")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", state.ReauthorizationControlSocket)
	if err != nil {
		return time.Time{}, fmt.Errorf("connect to mount reauthorization control: %w", err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := json.NewEncoder(connection).Encode(localReauthorizationRequest{
		Capability: token, ClientCertificatePEM: string(certificatePEM), Sequence: sequence,
	}); err != nil {
		return time.Time{}, err
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return time.Time{}, errors.New("reauthorization control is not a Unix connection")
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return time.Time{}, err
	}
	responseBody, responseRights, err := mountcontrol.Receive(unixConnection, mountcontrol.MaxOrdinaryResponse)
	defer responseRights.Close()
	if responseRights.Validate("") != nil {
		return time.Time{}, errors.New("mount reauthorization response carried descriptors")
	}
	if err != nil || len(responseBody) > 4096 {
		return time.Time{}, errors.New("mount reauthorization response exceeded its bound")
	}
	response, err := mountcontrol.DecodeResponse(responseBody, false)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode mount reauthorization response: %w", err)
	}
	if !response.OK || response.Error != "" || response.Sequence != sequence || response.AuthorizationDeadlineUnixMs <= time.Now().UnixMilli() {
		return time.Time{}, errors.New("mount supervisor refused reauthorization")
	}
	return time.UnixMilli(response.AuthorizationDeadlineUnixMs), nil
}

// mountLoss reads one exact supervisor, not mount inventory or a sampled log.
func readFuseMountLoss(ctx context.Context, state *mountState, instance string) (mountLossSnapshot, error) {
	if state == nil || state.Strategy != "fuse" || state.MountInstanceID != instance || !mountid.ValidMountInstance(instance) || !validReauthorizationControlAddress(state.ReauthorizationControlSocket) {
		return mountLossSnapshot{}, errors.New("exact FUSE mount has no live loss snapshot endpoint")
	}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", state.ReauthorizationControlSocket)
	if err != nil {
		return mountLossSnapshot{}, fmt.Errorf("connect to exact mount loss snapshot: %w", err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := json.NewEncoder(connection).Encode(localReauthorizationRequest{Operation: "loss-snapshot", MountInstanceID: instance}); err != nil {
		return mountLossSnapshot{}, err
	}
	if err := connection.(*net.UnixConn).CloseWrite(); err != nil {
		return mountLossSnapshot{}, err
	}
	body, responseRights, err := mountcontrol.Receive(connection.(*net.UnixConn), mountcontrol.MaxOrdinaryResponse)
	defer responseRights.Close()
	if responseRights.Validate("") != nil {
		return mountLossSnapshot{}, errors.New("mount loss snapshot response carried descriptors")
	}
	if err != nil || len(body) > 4096 {
		return mountLossSnapshot{}, errors.New("mount loss snapshot response unavailable or oversized")
	}
	response, err := mountcontrol.DecodeResponse(body, false)
	if err != nil {
		return mountLossSnapshot{}, fmt.Errorf("decode mount loss snapshot: %w", err)
	}
	if !response.OK || response.Error != "" || response.MountInstanceID != instance || !validLossSequence(response.LossSequence) || response.Sequence != 0 || response.AuthorizationDeadlineUnixMs != 0 {
		return mountLossSnapshot{}, errors.New("exact live mount loss snapshot refused")
	}
	return mountLossSnapshot{MountInstanceID: response.MountInstanceID, LossSequence: response.LossSequence}, nil
}

func validLossSequence(value string) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && strconv.FormatUint(n, 10) == value
}
