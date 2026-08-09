//go:build linux

package cellhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"golang.org/x/sys/unix"
)

type Server struct {
	SocketPath string
	SocketGID  int
	AgentUID   uint32
	Reconciler *Reconciler
}

func (server *Server) Serve(ctx context.Context) error {
	if server.Reconciler == nil || server.AgentUID == 0 || server.SocketGID <= 0 || !filepath.IsAbs(server.SocketPath) || filepath.Clean(server.SocketPath) != server.SocketPath {
		return ErrInvalid
	}
	directoryPath := filepath.Dir(server.SocketPath)
	if err := os.MkdirAll(directoryPath, 0o750); err != nil {
		return err
	}
	directory, err := os.Lstat(directoryPath)
	if err != nil {
		return err
	}
	stat, ok := directory.Sys().(*syscall.Stat_t)
	if !ok || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || directory.Mode().Perm()&0o022 != 0 {
		return errors.New("cellhelper: socket directory must be a root-owned non-writable real directory")
	}
	if err := os.Chown(directoryPath, 0, server.SocketGID); err != nil {
		return err
	}
	if err := os.Chmod(directoryPath, 0o750); err != nil {
		return err
	}
	if existing, err := os.Lstat(server.SocketPath); err == nil {
		stat, ok := existing.Sys().(*syscall.Stat_t)
		if !ok || existing.Mode()&os.ModeSocket == 0 || existing.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 {
			return errors.New("cellhelper: refuses to replace a non-root or non-socket helper path")
		}
		if err := os.Remove(server.SocketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", server.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chown(server.SocketPath, 0, server.SocketGID); err != nil {
		return err
	}
	if err := os.Chmod(server.SocketPath, 0o660); err != nil {
		return err
	}
	verified := &peerListener{Listener: listener, uid: server.AgentUID}
	httpServer := &http.Server{Handler: http.HandlerFunc(server.handle), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	err = httpServer.Serve(verified)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (server *Server) handle(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != "/v1/reconcile" {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	defer request.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(request.Body, (4<<20)+1))
	if err != nil || len(payload) > 4<<20 {
		writeHelperError(writer, http.StatusRequestEntityTooLarge, "signed plan envelope exceeds four MiB")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope cellplan.Envelope
	if err := decoder.Decode(&envelope); err != nil {
		writeHelperError(writer, http.StatusBadRequest, "invalid signed plan envelope")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeHelperError(writer, http.StatusBadRequest, "trailing request data")
		return
	}
	result, err := server.Reconciler.Reconcile(request.Context(), envelope)
	if err != nil {
		writeHelperError(writer, http.StatusConflict, err.Error())
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(result)
}

type peerListener struct {
	net.Listener
	uid uint32
}

func (listener *peerListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok {
			_ = connection.Close()
			continue
		}
		raw, err := unixConnection.SyscallConn()
		if err != nil {
			_ = connection.Close()
			continue
		}
		var credential *unix.Ucred
		controlErr := raw.Control(func(fd uintptr) {
			credential, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		})
		if controlErr == nil && err == nil && credential != nil && credential.Uid == listener.uid {
			return connection, nil
		}
		_ = connection.Close()
	}
}

func writeHelperError(writer http.ResponseWriter, status int, detail string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": detail})
}
