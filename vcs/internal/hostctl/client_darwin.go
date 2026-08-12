//go:build darwin

package hostctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Session struct {
	mu          sync.Mutex
	conn        *net.UnixConn
	token       string
	hostWitness ProcessWitness
	old         ReleaseIdentity
	target      ReleaseIdentity
	done        bool
}

type ActivationSession struct {
	mu        sync.Mutex
	conn      *net.UnixConn
	token     string
	hostPID   int
	operation string
	release   ReleaseIdentity
	state     string
	done      bool
}

type ActivationFencedError struct {
	Operation string
	Detail    string
	HostPID   int
}

func (e *ActivationFencedError) Error() string {
	return fmt.Sprintf("PortableFS host %s failed and fenced its service: %s", e.Operation, e.Detail)
}

// ActivationRequestAmbiguousError means a request reached an authenticated
// host connection but the client could not validate the resulting readiness
// reply. The exact peer PID is retained so callers can wait for the server's
// mandatory ready-session fence instead of guessing from a socket name.
type ActivationRequestAmbiguousError struct {
	Operation string
	HostPID   int
	Cause     error
}

func (e *ActivationRequestAmbiguousError) Error() string {
	return fmt.Sprintf("PortableFS host %s readiness is ambiguous for pid %d: %v", e.Operation, e.HostPID, e.Cause)
}

func (e *ActivationRequestAmbiguousError) Unwrap() error { return e.Cause }

func Prepare(
	ctx context.Context,
	path string,
	expectedOld ReleaseIdentity,
	target ReleaseIdentity,
) (*Session, error) {
	if err := ValidateReleaseIdentity(expectedOld); err != nil {
		return nil, fmt.Errorf("invalid expected old release: %w", err)
	}
	request, err := NewPrepareRequest(target)
	if err != nil {
		return nil, err
	}
	conn, peerWitness, err := connectExactHost(ctx, path)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	if err := writeJSONFrame(ctx, conn, request); err != nil {
		return nil, fmt.Errorf("request host update preparation: %w", err)
	}
	frame, err := readFrame(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("read host update preparation: %w", err)
	}
	reply, err := DecodeExact[PreparedReply](frame)
	if err != nil {
		return nil, fmt.Errorf("decode host update preparation: %w", err)
	}
	if err := ValidatePrepared(reply, peerWitness.PID, expectedOld, target); err != nil {
		return nil, err
	}
	success = true
	return &Session{
		conn:        conn,
		token:       reply.Token,
		hostWitness: peerWitness,
		old:         reply.OldRelease,
		target:      reply.TargetRelease,
	}, nil
}

func Activate(
	ctx context.Context,
	path, operation, token string,
	release ReleaseIdentity,
) (*ActivationSession, error) {
	request, err := NewActivationRequest(operation, token, release)
	if err != nil {
		return nil, err
	}
	conn, peerWitness, err := connectExactHost(ctx, path)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	if err := writeJSONFrame(ctx, conn, request); err != nil {
		return nil, &ActivationRequestAmbiguousError{
			Operation: operation,
			HostPID:   peerWitness.PID,
			Cause:     fmt.Errorf("request host activation: %w", err),
		}
	}
	frame, err := readFrame(ctx, conn)
	if err != nil {
		return nil, &ActivationRequestAmbiguousError{
			Operation: operation,
			HostPID:   peerWitness.PID,
			Cause:     fmt.Errorf("read host readiness: %w", err),
		}
	}
	reply, err := DecodeExact[ActivationReply](frame)
	if err != nil {
		return nil, &ActivationRequestAmbiguousError{
			Operation: operation,
			HostPID:   peerWitness.PID,
			Cause:     fmt.Errorf("decode host readiness: %w", err),
		}
	}
	ready, err := ValidateActivationReply(reply, operation, token, peerWitness.PID, release)
	if err != nil {
		return nil, &ActivationRequestAmbiguousError{
			Operation: operation,
			HostPID:   peerWitness.PID,
			Cause:     err,
		}
	}
	if !ready {
		return nil, &ActivationFencedError{
			Operation: operation,
			Detail:    reply.Error,
			HostPID:   peerWitness.PID,
		}
	}
	success = true
	return &ActivationSession{
		conn:      conn,
		token:     token,
		hostPID:   peerWitness.PID,
		operation: operation,
		release:   release,
		state:     "ready",
	}, nil
}

// ResumeActive recovers the exact completion session for an already durable
// target-active or rollback-active lease. The plaintext token remains only in
// the caller's memory; the host independently validates its hash, both release
// identities, its sealed release, and the live service before replying.
func ResumeActive(
	ctx context.Context,
	path, operation, token string,
	release, oldRelease, targetRelease ReleaseIdentity,
) (*ActivationSession, error) {
	request, err := NewActivationResumeRequest(
		operation, token, release, oldRelease, targetRelease,
	)
	if err != nil {
		return nil, err
	}
	conn, peerWitness, err := connectExactHost(ctx, path)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	if err := writeJSONFrame(ctx, conn, request); err != nil {
		return nil, fmt.Errorf("request host %s: %w", operation, err)
	}
	frame, err := readFrame(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("read host %s proof: %w", operation, err)
	}
	reply, err := DecodeExact[ActivationResumeReply](frame)
	if err != nil {
		return nil, fmt.Errorf("decode host %s proof: %w", operation, err)
	}
	if err := ValidateActivationResumeReply(
		reply, operation, token, peerWitness.PID, release,
	); err != nil {
		return nil, err
	}
	activationOperation := "activate-target"
	if operation == "resume-rollback" {
		activationOperation = "activate-rollback"
	}
	success = true
	return &ActivationSession{
		conn:      conn,
		token:     token,
		hostPID:   peerWitness.PID,
		operation: activationOperation,
		release:   release,
		state:     "active",
	}, nil
}

func connectExactHost(
	ctx context.Context,
	path string,
) (*net.UnixConn, ProcessWitness, error) {
	before, err := validateNamedSocket(path)
	if err != nil {
		return nil, ProcessWitness{}, err
	}
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, ProcessWitness{}, fmt.Errorf("connect installed PortableFS host at %s: %w", path, err)
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		raw.Close()
		return nil, ProcessWitness{}, fmt.Errorf("host update connection is not a Unix stream")
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	peerWitness, err := exactPeer(conn)
	if err != nil {
		return nil, ProcessWitness{}, err
	}
	after, err := validateNamedSocket(path)
	if err != nil {
		return nil, ProcessWitness{}, err
	}
	if !os.SameFile(before, after) {
		return nil, ProcessWitness{}, fmt.Errorf("installed PortableFS host socket changed while connecting")
	}
	success = true
	return conn, peerWitness, nil
}

func validateNamedSocket(path string) (os.FileInfo, error) {
	parentInfo, err := validateHostDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	_ = parentInfo
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect host update socket %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 ||
		stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0o600 || stat.Nlink != 1 {
		return nil, fmt.Errorf("host update socket %s is not an owned 0600 single-link Unix socket", path)
	}
	return info, nil
}

func validateHostDirectory(parent string) (os.FileInfo, error) {
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		return nil, fmt.Errorf("host update directory must be absolute and clean: %q", parent)
	}
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, fmt.Errorf("resolve host update socket directory %s: %w", parent, err)
	}
	if realParent != parent {
		return nil, fmt.Errorf("host update socket directory %s traverses a symlink", parent)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect host update socket directory %s: %w", parent, err)
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentStat.Uid != uint32(os.Geteuid()) || parentInfo.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("host update socket directory %s is not an owned 0700 real directory", parent)
	}
	return parentInfo, nil
}

func RequireLease(
	path, token, phase string,
	oldRelease, targetRelease ReleaseIdentity,
) error {
	if filepath.Base(path) != LeaseName {
		return fmt.Errorf("activation lease path has unexpected name %s", path)
	}
	if _, err := validateHostDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect activation lease %s: %w", path, err)
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Mode().Perm() != 0o600 || beforeStat.Uid != uint32(os.Geteuid()) ||
		beforeStat.Nlink != 1 || before.Size() <= 0 || before.Size() > MaxFrameBytes {
		return fmt.Errorf("activation lease %s is not an owned 0600 bounded single-link regular file", path)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open activation lease %s without following symlinks: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("open activation lease %s: invalid file descriptor", path)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, MaxFrameBytes+1))
	if err != nil || len(contents) == 0 || len(contents) > MaxFrameBytes {
		return fmt.Errorf("read bounded activation lease %s: %w", path, err)
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return fmt.Errorf("inspect pinned activation lease %s: %w", path, err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("recheck activation lease %s: %w", path, err)
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || opened.Dev != beforeStat.Dev || opened.Ino != beforeStat.Ino ||
		afterStat.Dev != beforeStat.Dev || afterStat.Ino != beforeStat.Ino ||
		!os.SameFile(before, after) {
		return fmt.Errorf("activation lease %s changed while pinned", path)
	}
	contents = bytes.TrimSpace(contents)
	lease, err := DecodeExact[ActivationLease](contents)
	if err != nil {
		return fmt.Errorf("decode activation lease %s: %w", path, err)
	}
	if err := ValidateActivationLease(lease, time.Now()); err != nil {
		return fmt.Errorf("validate activation lease %s: %w", path, err)
	}
	if lease.Phase != phase || lease.OldRelease != oldRelease ||
		lease.TargetRelease != targetRelease ||
		!TokenMatchesSHA256(token, lease.TokenSHA256) {
		return fmt.Errorf("activation lease %s does not match the authenticated update session", path)
	}
	return nil
}

func (s *Session) HostPID() int { return s.hostWitness.PID }

func (s *Session) HostProcessWitness() ProcessWitness { return s.hostWitness }

func (s *Session) Token() string { return s.token }

func (s *Session) OldRelease() ReleaseIdentity { return s.old }

func (s *Session) TargetRelease() ReleaseIdentity { return s.target }

func (s *Session) Commit(ctx context.Context) error {
	return s.finish(ctx, "commit-exit", "exiting")
}

func (s *Session) Cancel(ctx context.Context) error {
	return s.finish(ctx, "cancel", "cancelled")
}

func (s *Session) finish(ctx context.Context, operation, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.conn == nil {
		return fmt.Errorf("host update session is already closed")
	}
	request, err := NewFinishRequest(operation, s.token)
	if err != nil {
		return err
	}
	if err := writeJSONFrame(ctx, s.conn, request); err != nil {
		_ = s.conn.Close()
		s.done = true
		return fmt.Errorf("send host update %s: %w", operation, err)
	}
	frame, err := readFrame(ctx, s.conn)
	if err != nil {
		_ = s.conn.Close()
		s.done = true
		return fmt.Errorf("read host update %s: %w", operation, err)
	}
	reply, err := DecodeExact[FinishReply](frame)
	if err == nil {
		err = ValidateFinish(reply, state, s.token)
	}
	closeErr := s.conn.Close()
	s.done = true
	if err != nil {
		return err
	}
	return closeErr
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.conn == nil {
		return nil
	}
	s.done = true
	return s.conn.Close()
}

func (s *ActivationSession) HostPID() int { return s.hostPID }

func (s *ActivationSession) Release() ReleaseIdentity { return s.release }

func (s *ActivationSession) Accept(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.conn == nil || s.state != "ready" {
		return fmt.Errorf("host activation session is not ready")
	}
	operation := "accept-target"
	wantState := "target-active"
	if s.operation == "activate-rollback" {
		operation = "accept-rollback"
		wantState = "rollback-active"
	}
	if err := s.exchangeDecision(ctx, operation, wantState); err != nil {
		return err
	}
	s.state = "active"
	return nil
}

func (s *ActivationSession) Fence(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.conn == nil || s.state != "ready" {
		return fmt.Errorf("host activation session is not ready")
	}
	operation := "fence-target"
	wantState := "target-fenced"
	if s.operation == "activate-rollback" {
		operation = "fence-rollback"
		wantState = "rollback-fenced"
	}
	err := s.exchangeDecision(ctx, operation, wantState)
	closeErr := s.conn.Close()
	s.done = true
	if err != nil {
		return err
	}
	return closeErr
}

func (s *ActivationSession) Complete(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.conn == nil || s.state != "active" {
		return fmt.Errorf("host activation session is not active")
	}
	operation := "complete-target"
	if s.operation == "activate-rollback" {
		operation = "complete-rollback"
	}
	request, err := NewCompletionRequest(operation, s.token)
	if err != nil {
		return err
	}
	if err := writeJSONFrame(ctx, s.conn, request); err != nil {
		_ = s.conn.Close()
		s.done = true
		return fmt.Errorf("send host %s: %w", operation, err)
	}
	frame, err := readFrame(ctx, s.conn)
	if err != nil {
		_ = s.conn.Close()
		s.done = true
		return fmt.Errorf("read host %s: %w", operation, err)
	}
	reply, err := DecodeExact[CompletionReply](frame)
	if err == nil {
		err = ValidateCompletionReply(reply, s.token)
	}
	closeErr := s.conn.Close()
	s.done = true
	if err != nil {
		return err
	}
	return closeErr
}

func (s *ActivationSession) exchangeDecision(
	ctx context.Context,
	operation, wantState string,
) error {
	request, err := NewActivationDecision(operation, s.token)
	if err != nil {
		return err
	}
	if err := writeJSONFrame(ctx, s.conn, request); err != nil {
		_ = s.conn.Close()
		s.done = true
		return fmt.Errorf("send host %s: %w", operation, err)
	}
	frame, err := readFrame(ctx, s.conn)
	if err != nil {
		_ = s.conn.Close()
		s.done = true
		return fmt.Errorf("read host %s: %w", operation, err)
	}
	reply, err := DecodeExact[ActivationDecisionReply](frame)
	if err != nil {
		_ = s.conn.Close()
		s.done = true
		return fmt.Errorf("decode host %s: %w", operation, err)
	}
	if err := ValidateActivationDecisionReply(reply, wantState, s.token); err != nil {
		_ = s.conn.Close()
		s.done = true
		return err
	}
	return nil
}

func (s *ActivationSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.conn == nil {
		return nil
	}
	s.done = true
	return s.conn.Close()
}

func exactPeer(conn *net.UnixConn) (ProcessWitness, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return ProcessWitness{}, fmt.Errorf("access host update socket descriptor: %w", err)
	}
	var witness ProcessWitness
	var peerUID uint32
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		witness, peerUID, socketErr = captureSocketPeerProcessWitness(int(fd))
		if socketErr == nil && peerUID != credential.Uid {
			socketErr = fmt.Errorf(
				"LOCAL_PEERCRED uid %d does not match LOCAL_PEERTOKEN uid %d",
				credential.Uid,
				peerUID,
			)
		}
	}); err != nil {
		return ProcessWitness{}, fmt.Errorf("inspect host update socket peer: %w", err)
	}
	if socketErr != nil {
		return ProcessWitness{}, fmt.Errorf("inspect host update socket peer credentials: %w", socketErr)
	}
	if peerUID != uint32(os.Geteuid()) || witness.PID <= 0 {
		return ProcessWitness{}, fmt.Errorf("host update peer uid/pid %d/%d does not match installer uid %d", peerUID, witness.PID, os.Geteuid())
	}
	return witness, nil
}

func writeJSONFrame(ctx context.Context, conn *net.UnixConn, value any) error {
	frame, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(frame)+1 > MaxFrameBytes {
		return fmt.Errorf("host update request exceeds %d bytes", MaxFrameBytes)
	}
	frame = append(frame, '\n')
	if err := applyDeadline(ctx, conn); err != nil {
		return err
	}
	for len(frame) != 0 {
		written, err := conn.Write(frame)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		frame = frame[written:]
	}
	return nil
}

func readFrame(ctx context.Context, conn *net.UnixConn) ([]byte, error) {
	if err := applyDeadline(ctx, conn); err != nil {
		return nil, err
	}
	frame := make([]byte, 0, 256)
	var one [1]byte
	for len(frame) < MaxFrameBytes {
		read, err := conn.Read(one[:])
		if read == 1 {
			if one[0] == '\n' {
				if len(frame) == 0 {
					return nil, fmt.Errorf("host update sent an empty frame")
				}
				return frame, nil
			}
			frame = append(frame, one[0])
		}
		if err != nil {
			return nil, err
		}
		if read == 0 {
			return nil, io.ErrUnexpectedEOF
		}
	}
	return nil, fmt.Errorf("host update frame exceeds %d bytes", MaxFrameBytes)
}

func applyDeadline(ctx context.Context, conn *net.UnixConn) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(20 * time.Second)
	}
	return conn.SetDeadline(deadline)
}
