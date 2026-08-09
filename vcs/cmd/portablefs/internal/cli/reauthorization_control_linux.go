//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const maxLocalReauthorizationRequestBytes = (32 << 10) + maxClientIdentityBytes + 4096

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
	identity os.FileInfo
	listener *net.UnixListener
	once     sync.Once
	path     string
}

func startFuseReauthorizationControl(stateDir, mountPath string, handler fuseReauthorizationHandler) (fuseReauthorizationControl, error) {
	if handler == nil {
		return nil, errors.New("reauthorization handler is required")
	}
	path := reauthorizationSocketPath(stateDir, mountPath)
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("reauthorization control socket already exists at %s", path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect reauthorization control socket: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on reauthorization control socket: %w", err)
	}
	cleanup := func(cause error) (fuseReauthorizationControl, error) {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, cause
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return cleanup(fmt.Errorf("protect reauthorization control socket: %w", err))
	}
	identity, err := os.Lstat(path)
	if err != nil || identity.Mode()&os.ModeSocket == 0 {
		return cleanup(fmt.Errorf("pin reauthorization control socket identity: %w", err))
	}
	control := &unixReauthorizationControl{
		done: make(chan struct{}), handler: handler, identity: identity, listener: listener, path: path,
	}
	go control.serve()
	return control, nil
}

func (c *unixReauthorizationControl) SocketPath() string { return c.path }

func (c *unixReauthorizationControl) Close() error {
	var closeErr error
	c.once.Do(func() {
		closeErr = c.listener.Close()
		<-c.done
		if current, err := os.Lstat(c.path); err == nil && os.SameFile(c.identity, current) {
			if removeErr := os.Remove(c.path); removeErr != nil {
				closeErr = errors.Join(closeErr, removeErr)
			}
		} else if err != nil && !os.IsNotExist(err) {
			closeErr = errors.Join(closeErr, err)
		}
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
