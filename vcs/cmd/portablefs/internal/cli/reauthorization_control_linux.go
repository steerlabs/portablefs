//go:build linux

package cli

import (
	"bytes"
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

	"github.com/steerlabs/portablefs/vcs/internal/mountid"

	"golang.org/x/sys/unix"
)

const maxLocalReauthorizationRequestBytes = (32 << 10) + maxClientIdentityBytes + 4096
const maxFuseMountControlConnections = 8

const fuseReauthorizationSocketPrefix = "@portablefs-reauthorization-"

type localReauthorizationRequest struct {
	Operation            string `json:"operation,omitempty"`
	MountInstanceID      string `json:"mountInstanceId,omitempty"`
	Capability           string `json:"capability"`
	ClientCertificatePEM string `json:"clientCertificatePem"`
	Sequence             uint64 `json:"sequence"`
}

type localReauthorizationResponse struct {
	MountInstanceID             string `json:"mountInstanceId,omitempty"`
	LossSequence                string `json:"lossSequence,omitempty"`
	AuthorizationDeadlineUnixMs int64  `json:"authorizationDeadlineUnixMs,omitempty"`
	Error                       string `json:"error,omitempty"`
	OK                          bool   `json:"ok"`
	Sequence                    uint64 `json:"sequence,omitempty"`
}

type unixReauthorizationControl struct {
	done         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	handler      fuseReauthorizationHandler
	lossSnapshot fuseLossSnapshotHandler
	listener     *net.UnixListener
	mu           sync.Mutex
	connections  map[*net.UnixConn]uint64
	nextArrival  uint64
	changed      chan struct{}
	workers      sync.WaitGroup
	closed       bool
	closeErr     error
	once         sync.Once
	path         string
}

func startFuseReauthorizationControl(handler fuseReauthorizationHandler, lossSnapshot fuseLossSnapshotHandler) (fuseReauthorizationControl, error) {
	if handler == nil && lossSnapshot == nil {
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
		done: make(chan struct{}), ctx: ctx, cancel: cancel,
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
// requireSameUserPeer remains the authorization boundary after connect.
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
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = connection.Close()
			return
		}
		if len(c.connections) >= maxFuseMountControlConnections {
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
		c.workers.Add(1)
		c.mu.Unlock()
		go func() {
			defer c.workers.Done()
			c.handle(connection, arrival)
			c.mu.Lock()
			delete(c.connections, connection)
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
		for _, accepted := range c.connections {
			if accepted < arrival {
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

func (c *unixReauthorizationControl) handle(connection *net.UnixConn, arrival uint64) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	if err := requireSameUserPeer(connection); err != nil {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "peer refused", OK: false})
		return
	}
	body, err := io.ReadAll(io.LimitReader(connection, maxLocalReauthorizationRequestBytes+1))
	if err != nil || len(body) > maxLocalReauthorizationRequestBytes {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "invalid request", OK: false})
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var request localReauthorizationRequest
	if err := decoder.Decode(&request); err != nil {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "invalid request", OK: false})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "invalid request", OK: false})
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
	deadline, err := c.handler(ctx, request.Capability, request.Sequence, []byte(request.ClientCertificatePEM))
	if err != nil {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "authority refused reauthorization", OK: false})
		return
	}
	writeLocalReauthorizationResponse(connection, localReauthorizationResponse{
		AuthorizationDeadlineUnixMs: deadline.UnixMilli(), OK: true, Sequence: request.Sequence,
	})
}

func requireSameUserPeer(connection *net.UnixConn) error {
	return requireUserPeer(connection, uint32(os.Geteuid()))
}

func requireUserPeer(connection *net.UnixConn, uid uint32) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var credential *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if controlErr != nil {
		return controlErr
	}
	if credential == nil || credential.Uid != uid {
		return errors.New("reauthorization peer uid mismatch")
	}
	return nil
}

func writeLocalReauthorizationResponse(writer io.Writer, response localReauthorizationResponse) {
	_ = json.NewEncoder(writer).Encode(response)
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
	responseBody, err := io.ReadAll(io.LimitReader(connection, 4097))
	if err != nil || len(responseBody) > 4096 {
		return time.Time{}, errors.New("mount reauthorization response exceeded its bound")
	}
	var response localReauthorizationResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
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
	body, err := io.ReadAll(io.LimitReader(connection, 4097))
	if err != nil || len(body) > 4096 {
		return mountLossSnapshot{}, errors.New("mount loss snapshot response unavailable or oversized")
	}
	var response localReauthorizationResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return mountLossSnapshot{}, fmt.Errorf("decode mount loss snapshot: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return mountLossSnapshot{}, errors.New("trailing mount loss snapshot response")
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
