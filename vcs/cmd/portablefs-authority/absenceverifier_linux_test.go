//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func writeVerifierScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "verify")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// The command's exit status is the whole verdict, and everything variable
// travels on stdin — no argument quoting, no environment, no shell between the
// authority and the operator's program.
func TestCommandAbsenceVerifierVerdicts(t *testing.T) {
	proof := volumeserver.MountAbsenceProof{ObservedUnixNanos: 42, Component: "getfsstat", Observation: []byte("mount-table")}
	id := volumeserver.SessionID{1, 2, 3}

	capture := filepath.Join(t.TempDir(), "claim.json")
	accept := writeVerifierScript(t, "cat > "+capture+"\nexit 0\n")
	if err := (commandAbsenceVerifier{command: accept, timeout: 5 * time.Second}).VerifyMountAbsence(id, proof); err != nil {
		t.Fatalf("accepting verifier = %v", err)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	var claim mountAbsenceClaim
	if err := json.Unmarshal(raw, &claim); err != nil {
		t.Fatalf("claim is not one JSON document: %v", err)
	}
	if claim.ObservedUnixNanos != 42 || claim.Component != "getfsstat" || !strings.HasPrefix(claim.SessionID, "010203") {
		t.Fatalf("claim = %+v, want the exact proof forwarded", claim)
	}

	refuse := writeVerifierScript(t, "exit 3\n")
	if err := (commandAbsenceVerifier{command: refuse, timeout: 5 * time.Second}).VerifyMountAbsence(id, proof); err == nil {
		t.Fatal("a nonzero exit did not refuse the claim")
	}

	hang := writeVerifierScript(t, "sleep 30\n")
	start := time.Now()
	if err := (commandAbsenceVerifier{command: hang, timeout: 200 * time.Millisecond}).VerifyMountAbsence(id, proof); err == nil {
		t.Fatal("a hung verifier did not refuse the claim")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the timeout did not bound the verification run")
	}

	if err := (commandAbsenceVerifier{command: filepath.Join(t.TempDir(), "missing"), timeout: time.Second}).VerifyMountAbsence(id, proof); err == nil {
		t.Fatal("a missing verifier program did not refuse the claim")
	}
}
