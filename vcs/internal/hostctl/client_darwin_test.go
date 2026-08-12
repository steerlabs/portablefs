//go:build darwin

package hostctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientUsesOneCredentialedTokenBoundSession(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-hostctl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "host")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, SocketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	oldRelease := testReleaseIdentity("a", "1.0.0")
	targetRelease := testReleaseIdentity("b", "2.0.0")
	prepareRequest, err := NewPrepareRequest(targetRelease)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		prepare, err := reader.ReadBytes('\n')
		if err != nil {
			serverDone <- err
			return
		}
		request, err := DecodeExact[PrepareRequest](prepare[:len(prepare)-1])
		if err != nil {
			serverDone <- err
			return
		}
		if request != prepareRequest {
			serverDone <- fmt.Errorf("prepare request = %+v", request)
			return
		}
		if err := json.NewEncoder(connection).Encode(PreparedReply{
			SchemaVersion: SchemaVersion,
			State:         "prepared",
			Token:         token,
			HostPID:       os.Getpid(),
			OldRelease:    oldRelease,
			TargetRelease: targetRelease,
		}); err != nil {
			serverDone <- err
			return
		}
		finish, err := reader.ReadBytes('\n')
		if err != nil {
			serverDone <- err
			return
		}
		finishRequest, err := DecodeExact[FinishRequest](finish[:len(finish)-1])
		if err != nil {
			serverDone <- err
			return
		}
		if finishRequest.SchemaVersion != SchemaVersion ||
			finishRequest.Operation != "commit-exit" || finishRequest.Token != token {
			serverDone <- fmt.Errorf("finish request = %+v", finishRequest)
			return
		}
		serverDone <- json.NewEncoder(connection).Encode(FinishReply{
			SchemaVersion: SchemaVersion,
			State:         "exiting",
			Token:         token,
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, err := Prepare(ctx, path, oldRelease, targetRelease)
	if err != nil {
		t.Fatal(err)
	}
	if session.HostPID() != os.Getpid() {
		t.Fatalf("host pid = %d, want %d", session.HostPID(), os.Getpid())
	}
	witness := session.HostProcessWitness()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	if witness.PIDVersion <= 0 || witness.ExecutablePath != executable {
		t.Fatalf("host witness = %+v, want pidversion and path %s", witness, executable)
	}
	if err := witness.RequireCurrentExecutable(executable); err != nil {
		t.Fatalf("re-prove current host execution: %v", err)
	}
	if err := witness.RequireCurrentExecutable(executable + ".wrong"); err == nil {
		t.Fatal("host witness accepted a wrong executable path")
	}
	tampered := witness
	tampered.PIDVersion++
	if err := tampered.RequireCurrentExecutable(executable); err == nil {
		t.Fatal("host witness accepted a different pidversion")
	}
	if err := session.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestCommitReplyLossRetainsAuthenticatedSessionProofs(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-hostctl-commit-loss-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "host")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, SocketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("f", 64)
	oldRelease := testReleaseIdentity("a", "1.0.0")
	targetRelease := testReleaseIdentity("b", "2.0.0")
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		reader := bufio.NewReader(connection)
		if _, err := reader.ReadBytes('\n'); err != nil {
			_ = connection.Close()
			serverDone <- err
			return
		}
		if err := json.NewEncoder(connection).Encode(PreparedReply{
			SchemaVersion: SchemaVersion,
			State:         "prepared",
			Token:         token,
			HostPID:       os.Getpid(),
			OldRelease:    oldRelease,
			TargetRelease: targetRelease,
		}); err != nil {
			_ = connection.Close()
			serverDone <- err
			return
		}
		finish, err := reader.ReadBytes('\n')
		if err != nil {
			_ = connection.Close()
			serverDone <- err
			return
		}
		request, err := DecodeExact[FinishRequest](finish[:len(finish)-1])
		if err != nil {
			_ = connection.Close()
			serverDone <- err
			return
		}
		if request.Operation != "commit-exit" || request.Token != token {
			_ = connection.Close()
			serverDone <- fmt.Errorf("finish request = %+v", request)
			return
		}
		// The host crossed the durable commit edge but its acknowledgement was
		// lost. The client must retain the exact token and release tuple so its
		// caller can reconcile the durable phase rather than guess from EOF.
		serverDone <- connection.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, err := Prepare(ctx, path, oldRelease, targetRelease)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Commit(ctx); err == nil {
		t.Fatal("lost commit reply was accepted")
	}
	if session.Token() != token || session.OldRelease() != oldRelease ||
		session.TargetRelease() != targetRelease || session.HostPID() != os.Getpid() {
		t.Fatalf(
			"commit error discarded authenticated session proofs: token=%q old=%+v target=%+v pid=%d",
			session.Token(), session.OldRelease(), session.TargetRelease(), session.HostPID(),
		)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestActivationClientAcceptsAndCompletesOnOneCredentialedConnection(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-hostctl-activate-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "host")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, SocketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("b", 64)
	target := testReleaseIdentity("c", "2.0.0")
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		activation, err := reader.ReadBytes('\n')
		if err != nil {
			serverDone <- err
			return
		}
		request, err := DecodeExact[ActivationRequest](activation[:len(activation)-1])
		if err != nil {
			serverDone <- err
			return
		}
		wantRequest, _ := NewActivationRequest("activate-target", token, target)
		if request != wantRequest {
			serverDone <- fmt.Errorf("activation request = %+v", request)
			return
		}
		if err := json.NewEncoder(connection).Encode(ActivationReply{
			SchemaVersion: SchemaVersion,
			State:         PhaseTargetReady,
			Token:         token,
			HostPID:       os.Getpid(),
			Release:       target,
		}); err != nil {
			serverDone <- err
			return
		}
		decision, err := reader.ReadBytes('\n')
		if err != nil {
			serverDone <- err
			return
		}
		gotDecision, err := DecodeExact[ActivationDecision](decision[:len(decision)-1])
		if err != nil {
			serverDone <- err
			return
		}
		wantDecision, _ := NewActivationDecision("accept-target", token)
		if gotDecision != wantDecision {
			serverDone <- fmt.Errorf("activation decision = %+v", gotDecision)
			return
		}
		if err := json.NewEncoder(connection).Encode(ActivationDecisionReply{
			SchemaVersion: SchemaVersion,
			State:         PhaseTargetActive,
			Token:         token,
		}); err != nil {
			serverDone <- err
			return
		}
		completion, err := reader.ReadBytes('\n')
		if err != nil {
			serverDone <- err
			return
		}
		gotCompletion, err := DecodeExact[CompletionRequest](completion[:len(completion)-1])
		if err != nil {
			serverDone <- err
			return
		}
		wantCompletion, _ := NewCompletionRequest("complete-target", token)
		if gotCompletion != wantCompletion {
			serverDone <- fmt.Errorf("activation completion = %+v", gotCompletion)
			return
		}
		serverDone <- json.NewEncoder(connection).Encode(CompletionReply{
			SchemaVersion: SchemaVersion,
			State:         "complete",
			Token:         token,
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, err := Activate(ctx, path, "activate-target", token, target)
	if err != nil {
		t.Fatal(err)
	}
	if session.HostPID() != os.Getpid() || session.Release() != target {
		t.Fatalf("activation session peer/release = %d/%+v", session.HostPID(), session.Release())
	}
	if err := session.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	if err := session.Complete(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestActivationClientResumesLostAcceptAcknowledgementAndCompletes(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-hostctl-resume-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "host")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, SocketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("e", 64)
	oldRelease := testReleaseIdentity("a", "1.0.0")
	targetRelease := testReleaseIdentity("b", "2.0.0")
	serverDone := make(chan error, 1)
	go func() {
		first, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		reader := bufio.NewReader(first)
		if _, err := reader.ReadBytes('\n'); err != nil {
			_ = first.Close()
			serverDone <- err
			return
		}
		if err := json.NewEncoder(first).Encode(ActivationReply{
			SchemaVersion: SchemaVersion,
			State:         PhaseTargetReady,
			Token:         token,
			HostPID:       os.Getpid(),
			Release:       targetRelease,
		}); err != nil {
			_ = first.Close()
			serverDone <- err
			return
		}
		if _, err := reader.ReadBytes('\n'); err != nil {
			_ = first.Close()
			serverDone <- err
			return
		}
		// The active phase is durable, but its acknowledgement is lost.
		if err := first.Close(); err != nil {
			serverDone <- err
			return
		}

		resumed, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer resumed.Close()
		reader = bufio.NewReader(resumed)
		frame, err := reader.ReadBytes('\n')
		if err != nil {
			serverDone <- err
			return
		}
		request, err := DecodeExact[ActivationResumeRequest](frame[:len(frame)-1])
		if err != nil {
			serverDone <- err
			return
		}
		want, _ := NewActivationResumeRequest(
			"resume-target", token, targetRelease, oldRelease, targetRelease,
		)
		if request != want {
			serverDone <- fmt.Errorf("resume request = %+v, want %+v", request, want)
			return
		}
		if err := json.NewEncoder(resumed).Encode(ActivationResumeReply{
			SchemaVersion: SchemaVersion,
			State:         PhaseTargetActive,
			Token:         token,
			HostPID:       os.Getpid(),
			Release:       targetRelease,
		}); err != nil {
			serverDone <- err
			return
		}
		completion, err := reader.ReadBytes('\n')
		if err != nil {
			serverDone <- err
			return
		}
		got, err := DecodeExact[CompletionRequest](completion[:len(completion)-1])
		if err != nil {
			serverDone <- err
			return
		}
		wantCompletion, _ := NewCompletionRequest("complete-target", token)
		if got != wantCompletion {
			serverDone <- fmt.Errorf("completion after resume = %+v", got)
			return
		}
		serverDone <- json.NewEncoder(resumed).Encode(CompletionReply{
			SchemaVersion: SchemaVersion,
			State:         "complete",
			Token:         token,
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first, err := Activate(ctx, path, "activate-target", token, targetRelease)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Accept(ctx); err == nil {
		t.Fatal("lost accept acknowledgement was accepted")
	}
	resumed, err := ResumeActive(
		ctx, path, "resume-target", token, targetRelease, oldRelease, targetRelease,
	)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.HostPID() != os.Getpid() || resumed.Release() != targetRelease {
		t.Fatalf("resumed session peer/release = %d/%+v", resumed.HostPID(), resumed.Release())
	}
	if err := resumed.Complete(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestInvalidAcceptAcknowledgementClosesOriginalBeforeResume(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-hostctl-invalid-accept-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "host")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, SocketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("d", 64)
	oldRelease := testReleaseIdentity("a", "1.0.0")
	targetRelease := testReleaseIdentity("b", "2.0.0")
	serverDone := make(chan error, 1)
	go func() {
		first, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		reader := bufio.NewReader(first)
		if _, err := reader.ReadBytes('\n'); err != nil {
			serverDone <- err
			return
		}
		if err := json.NewEncoder(first).Encode(ActivationReply{
			SchemaVersion: SchemaVersion, State: PhaseTargetReady, Token: token,
			HostPID: os.Getpid(), Release: targetRelease,
		}); err != nil {
			serverDone <- err
			return
		}
		if _, err := reader.ReadBytes('\n'); err != nil {
			serverDone <- err
			return
		}
		// The active transition is durable, but the acknowledgement is invalid.
		// A sequential host cannot accept ResumeActive until the client closes
		// this original session.
		if _, err := first.Write([]byte("{}\n")); err != nil {
			serverDone <- err
			return
		}
		if _, err := reader.ReadByte(); err == nil {
			serverDone <- fmt.Errorf("original activation session remained open after invalid acknowledgement")
			return
		}
		_ = first.Close()

		resumed, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer resumed.Close()
		reader = bufio.NewReader(resumed)
		if _, err := reader.ReadBytes('\n'); err != nil {
			serverDone <- err
			return
		}
		serverDone <- json.NewEncoder(resumed).Encode(ActivationResumeReply{
			SchemaVersion: SchemaVersion, State: PhaseTargetActive, Token: token,
			HostPID: os.Getpid(), Release: targetRelease,
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first, err := Activate(ctx, path, "activate-target", token, targetRelease)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Accept(ctx); err == nil {
		t.Fatal("invalid accept acknowledgement was accepted")
	}
	resumed, err := ResumeActive(
		ctx, path, "resume-target", token, targetRelease, oldRelease, targetRelease,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = resumed.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestActivationClientAbortBeforeDecisionClosesCredentialedSession(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-hostctl-abort-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "host")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, SocketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("d", 64)
	target := testReleaseIdentity("e", "2.0.0")
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		if _, err := reader.ReadBytes('\n'); err != nil {
			serverDone <- err
			return
		}
		if err := json.NewEncoder(connection).Encode(ActivationReply{
			SchemaVersion: SchemaVersion,
			State:         PhaseTargetReady,
			Token:         token,
			HostPID:       os.Getpid(),
			Release:       target,
		}); err != nil {
			serverDone <- err
			return
		}
		_, err = reader.ReadByte()
		if err != io.EOF {
			serverDone <- fmt.Errorf("activation abort read = %v, want EOF", err)
			return
		}
		serverDone <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, err := Activate(ctx, path, "activate-target", token, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestActivationReadinessLossRetainsExactAuthenticatedPeer(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-hostctl-ready-loss-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "host")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, SocketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		reader := bufio.NewReader(connection)
		_, readErr := reader.ReadBytes('\n')
		closeErr := connection.Close()
		serverDone <- errors.Join(readErr, closeErr)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = Activate(
		ctx,
		path,
		"activate-target",
		strings.Repeat("f", 64),
		testReleaseIdentity("a", "1.0.0"),
	)
	var ambiguous *ActivationRequestAmbiguousError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("readiness loss = %v, want typed ambiguity", err)
	}
	if ambiguous.HostPID != os.Getpid() || ambiguous.Operation != "activate-target" {
		t.Fatalf("ambiguous peer/operation = %d/%q", ambiguous.HostPID, ambiguous.Operation)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestRequireLeasePinsExactOwnedTokenBoundState(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-hostctl-lease-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "host")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	tokenHash, err := TokenSHA256(token)
	if err != nil {
		t.Fatal(err)
	}
	oldRelease := testReleaseIdentity("b", "1.0.0")
	targetRelease := testReleaseIdentity("c", "2.0.0")
	now := time.Now()
	lease := ActivationLease{
		SchemaVersion:   SchemaVersion,
		Phase:           PhaseOldAbsent,
		TokenSHA256:     tokenHash,
		OldRelease:      oldRelease,
		TargetRelease:   targetRelease,
		CreatedAtUnixMS: now.UnixMilli(),
		DeadlineUnixMS:  now.Add(LeaseLifetime).UnixMilli(),
	}
	contents, err := json.Marshal(lease)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, LeaseName)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RequireLease(
		path,
		token,
		PhaseOldAbsent,
		oldRelease,
		targetRelease,
	); err != nil {
		t.Fatal(err)
	}
	if err := RequireLease(
		path,
		strings.Repeat("d", 64),
		PhaseOldAbsent,
		oldRelease,
		targetRelease,
	); err == nil {
		t.Fatal("wrong plaintext token was accepted")
	}
	if err := RequireLease(
		path,
		token,
		PhaseTargetActive,
		oldRelease,
		targetRelease,
	); err == nil {
		t.Fatal("wrong lease phase was accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RequireLease(
		path,
		token,
		PhaseOldAbsent,
		oldRelease,
		targetRelease,
	); err == nil {
		t.Fatal("world-readable activation lease was accepted")
	}
}

func TestRequireLeaseRequiresPersistentExactCompletedMarker(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-hostctl-complete-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "host")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, LeaseName)
	token := strings.Repeat("a", 64)
	oldRelease := testReleaseIdentity("b", "1.0.0")
	targetRelease := testReleaseIdentity("c", "2.0.0")
	if err := RequireLease(
		path, token, PhaseTargetComplete, oldRelease, targetRelease,
	); err == nil {
		t.Fatal("missing completed marker was accepted")
	}
	tokenHash, err := TokenSHA256(token)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().Add(-24 * time.Hour)
	contents, err := json.Marshal(ActivationLease{
		SchemaVersion:   SchemaVersion,
		Phase:           PhaseTargetComplete,
		TokenSHA256:     tokenHash,
		OldRelease:      oldRelease,
		TargetRelease:   targetRelease,
		CreatedAtUnixMS: created.UnixMilli(),
		DeadlineUnixMS:  created.Add(LeaseLifetime).UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RequireLease(
		path, token, PhaseTargetComplete, oldRelease, targetRelease,
	); err != nil {
		t.Fatalf("expired but terminal exact marker was rejected: %v", err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := RequireLease(
		path, token, PhaseTargetComplete, oldRelease, targetRelease,
	); err == nil {
		t.Fatal("completed marker under a non-private directory was accepted")
	}
}
