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
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const maxLocalReauthorizationRequestBytes = (32 << 10) + maxClientIdentityBytes + 4096

const fuseReauthorizationSocketPrefix = "@portablefs-reauthorization-"

type localReauthorizationRequest struct {
	Capability           string `json:"capability"`
	ClientCertificatePEM string `json:"clientCertificatePem"`
	Sequence             uint64 `json:"sequence"`
}

type localReauthorizationResponse struct {
	AuthorizationDeadlineUnixMs int64  `json:"authorizationDeadlineUnixMs,omitempty"`
	Error                       string `json:"error,omitempty"`
	OK                          bool   `json:"ok"`
	Sequence                    uint64 `json:"sequence,omitempty"`
}

type unixReauthorizationControl struct {
	done     chan struct{}
	handler  fuseReauthorizationHandler
	listener *net.UnixListener
	once     sync.Once
	path     string
}

func startFuseReauthorizationControl(handler fuseReauthorizationHandler) (fuseReauthorizationControl, error) {
	if handler == nil {
		return nil, errors.New("reauthorization handler is required")
	}
	path, err := newFuseReauthorizationSocketName()
	if err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on reauthorization control socket: %w", err)
	}
	control := &unixReauthorizationControl{
		done: make(chan struct{}), handler: handler, listener: listener, path: path,
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
	var closeErr error
	c.once.Do(func() {
		closeErr = c.listener.Close()
		<-c.done
	})
	if errors.Is(closeErr, net.ErrClosed) {
		return nil
	}
	return closeErr
}

func (c *unixReauthorizationControl) serve() {
	defer close(c.done)
	for {
		connection, err := c.listener.AcceptUnix()
		if err != nil {
			return
		}
		c.handle(connection)
	}
}

func (c *unixReauthorizationControl) handle(connection *net.UnixConn) {
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
	if err := decoder.Decode(&request); err != nil || request.Sequence == 0 || request.Capability == "" || len(request.Capability) > 32<<10 || request.ClientCertificatePEM == "" || len(request.ClientCertificatePEM) > maxClientIdentityBytes {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "invalid request", OK: false})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeLocalReauthorizationResponse(connection, localReauthorizationResponse{Error: "invalid request", OK: false})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
	if credential == nil || credential.Uid != uint32(os.Geteuid()) {
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
