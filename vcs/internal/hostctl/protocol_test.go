package hostctl

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testReleaseIdentity(hexDigit, version string) ReleaseIdentity {
	return ReleaseIdentity{
		CodeDirectoryHash: strings.Repeat(hexDigit, 40),
		ExecutableSHA256:  strings.Repeat(hexDigit, 64),
		DaemonVersion:     version,
		IdentitySchema:    1,
		ControlProtocol:   1,
		PFSLocalMajor:     1,
		PFSLocalMinor:     15,
	}
}

func TestProtocolIsExactAndTokenBound(t *testing.T) {
	token := strings.Repeat("a", 64)
	oldRelease := testReleaseIdentity("a", "1.0.0")
	targetRelease := testReleaseIdentity("b", "2.0.0")
	payload, err := json.Marshal(PreparedReply{
		SchemaVersion: SchemaVersion,
		State:         "prepared",
		Token:         token,
		HostPID:       42,
		OldRelease:    oldRelease,
		TargetRelease: targetRelease,
	})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := DecodeExact[PreparedReply](payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrepared(reply, 42, oldRelease, targetRelease); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeExact[PreparedReply]([]byte(
		`{"schemaVersion":1,"state":"prepared","token":"` + token + `","hostPid":42,"extra":true}`,
	)); err == nil {
		t.Fatal("unknown reply key was accepted")
	}
	if _, err := NewFinishRequest("commit-exit", strings.Repeat("A", 64)); err == nil {
		t.Fatal("uppercase token was accepted")
	}
}

func TestActivationLeaseRejectsWrongTokenAndStalePhase(t *testing.T) {
	token := strings.Repeat("c", 64)
	hash, err := TokenSHA256(token)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	lease := ActivationLease{
		SchemaVersion:   SchemaVersion,
		Phase:           PhaseOldAbsent,
		TokenSHA256:     hash,
		OldRelease:      testReleaseIdentity("a", "1.0.0"),
		TargetRelease:   testReleaseIdentity("b", "2.0.0"),
		CreatedAtUnixMS: now.UnixMilli(),
		DeadlineUnixMS:  now.Add(LeaseLifetime).UnixMilli(),
	}
	if err := ValidateActivationLease(lease, now); err != nil {
		t.Fatal(err)
	}
	if !TokenMatchesSHA256(token, hash) {
		t.Fatal("exact token did not match its persisted hash")
	}
	if TokenMatchesSHA256(strings.Repeat("d", 64), hash) {
		t.Fatal("wrong token matched persisted hash")
	}
	stale := lease
	stale.Phase = "retired"
	if err := ValidateActivationLease(stale, now); err == nil {
		t.Fatal("unknown stale phase was accepted")
	}
	if err := ValidateActivationLease(lease, now.Add(LeaseLifetime)); err == nil {
		t.Fatal("expired lease was accepted")
	}
	lease.Phase = PhaseTargetComplete
	if err := ValidateActivationLease(lease, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("persistent terminal marker was rejected after its transaction deadline: %v", err)
	}
	lease.Phase = PhaseRollbackComplete
	if err := ValidateActivationLease(lease, now.Add(365*24*time.Hour)); err != nil {
		t.Fatalf("persistent rollback marker was rejected after its transaction deadline: %v", err)
	}
	lease.CreatedAtUnixMS = now.Add(2 * time.Minute).UnixMilli()
	lease.DeadlineUnixMS = now.Add(2*time.Minute + LeaseLifetime).UnixMilli()
	if err := ValidateActivationLease(lease, now); err == nil {
		t.Fatal("future terminal marker beyond the bounded clock skew was accepted")
	}
}

func TestActivationFramesRejectWrongTargetAndReplayState(t *testing.T) {
	token := strings.Repeat("a", 64)
	target := testReleaseIdentity("b", "2.0.0")
	reply := ActivationReply{
		SchemaVersion: SchemaVersion,
		State:         PhaseTargetReady,
		Token:         token,
		HostPID:       42,
		Release:       target,
	}
	ready, err := ValidateActivationReply(reply, "activate-target", token, 42, target)
	if err != nil || !ready {
		t.Fatalf("valid target readiness = %t, %v", ready, err)
	}
	if _, err := ValidateActivationReply(
		reply,
		"activate-target",
		token,
		42,
		testReleaseIdentity("c", "3.0.0"),
	); err == nil {
		t.Fatal("wrong target release was accepted")
	}
	reply.State = PhaseTargetActive
	if _, err := ValidateActivationReply(reply, "activate-target", token, 42, target); err == nil {
		t.Fatal("replayed active phase was accepted as readiness")
	}
}

func TestActivationResumeFramesBindBothReleasesAndExactActiveSide(t *testing.T) {
	token := strings.Repeat("d", 64)
	oldRelease := testReleaseIdentity("a", "1.0.0")
	targetRelease := testReleaseIdentity("b", "2.0.0")
	request, err := NewActivationResumeRequest(
		"resume-target", token, targetRelease, oldRelease, targetRelease,
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.OldRelease != oldRelease || request.TargetRelease != targetRelease ||
		request.Release != targetRelease {
		t.Fatalf("resume request lost exact release tuple: %+v", request)
	}
	if _, err := NewActivationResumeRequest(
		"resume-target", token, oldRelease, oldRelease, targetRelease,
	); err == nil {
		t.Fatal("target resume accepted the old release as active")
	}
	if _, err := NewActivationResumeRequest(
		"resume-rollback", token, targetRelease, oldRelease, targetRelease,
	); err == nil {
		t.Fatal("rollback resume accepted the target release as active")
	}
	reply := ActivationResumeReply{
		SchemaVersion: SchemaVersion,
		State:         PhaseTargetActive,
		Token:         token,
		HostPID:       42,
		Release:       targetRelease,
	}
	if err := ValidateActivationResumeReply(
		reply, "resume-target", token, 42, targetRelease,
	); err != nil {
		t.Fatal(err)
	}
	reply.State = PhaseRollbackActive
	if err := ValidateActivationResumeReply(
		reply, "resume-target", token, 42, targetRelease,
	); err == nil {
		t.Fatal("rollback-active reply was accepted for a target resume")
	}
}

func TestDecodeExactRejectsEveryTrailingNonWhitespaceByte(t *testing.T) {
	for _, suffix := range []string{"{}", "x", " \n\tx", "{}x"} {
		frame := []byte(`{"schemaVersion":1,"operation":"cancel","token":"` +
			strings.Repeat("a", 64) + `"}` + suffix)
		if _, err := DecodeExact[FinishRequest](frame); err == nil {
			t.Fatalf("trailing suffix %q was accepted", suffix)
		}
	}
	frame := []byte(`{"schemaVersion":1,"operation":"cancel","token":"` +
		strings.Repeat("a", 64) + `"}` + " \n\t")
	if _, err := DecodeExact[FinishRequest](frame); err != nil {
		t.Fatalf("JSON whitespace was rejected: %v", err)
	}
}

func TestDecodeExactRejectsDuplicateAndEscapedEquivalentKeysAtEveryDepth(t *testing.T) {
	for name, frame := range map[string]string{
		"prepare top level":             `{"schemaVersion":1,"schemaVersion":1}`,
		"activation escaped equivalent": `{"schemaVersion":1,"\u0073chemaVersion":1}`,
		"nested release":                `{"targetRelease":{"daemonVersion":"1","daemonVersion":"2"}}`,
		"nested escaped release":        `{"oldRelease":{"executableSHA256":"a","executable\u0053HA256":"b"}}`,
		"lease top level":               `{"phase":"old-absent","phase":"target-active"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExact[map[string]any]([]byte(frame)); err == nil {
				t.Fatal("duplicate JSON key was accepted")
			}
		})
	}
}

func TestReleaseIdentityAllowsProtocolMinorZero(t *testing.T) {
	identity := testReleaseIdentity("a", "2.0.0")
	identity.PFSLocalMajor = 2
	identity.PFSLocalMinor = 0
	if err := ValidateReleaseIdentity(identity); err != nil {
		t.Fatalf("valid 2.0 protocol identity rejected: %v", err)
	}
}

func TestSocketPathIsOutsideDaemonAndAppGroupRoots(t *testing.T) {
	got := SocketPath("/Users/example")
	want := "/Users/example/.local/state/portablefs/host/update.sock"
	if got != want {
		t.Fatalf("socket path = %q, want %q", got, want)
	}
	lease := LeasePath("/Users/example")
	if lease != "/Users/example/.local/state/portablefs/host/activation.json" {
		t.Fatalf("lease path = %q", lease)
	}
}
