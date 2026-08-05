//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// commandAbsenceVerifier delegates mount-absence authentication to deployment
// infrastructure. The authority itself has no way to observe a remote kernel's
// mount table, and the proof bytes arrive from the very frontend whose absence
// they claim, so the only honest verifier is one the operator supplies: a
// program that checks the claim against evidence the frontend does not control
// (a host agent's own mount scan, an infrastructure fence record, a signed
// attestation). The program receives one JSON document on stdin and its exit
// status is the whole verdict — exit 0 verifies, anything else refuses. There
// is no partial credit and no retry here: a refusal leaves the session to end
// fenced, exactly as if no verifier were configured.
type commandAbsenceVerifier struct {
	command string
	timeout time.Duration
}

// mountAbsenceClaim is the document the verification command receives. The
// observation bytes are the frontend's claim, forwarded verbatim (base64) for
// the verifier to corroborate — never trusted by the authority itself.
type mountAbsenceClaim struct {
	SessionID         string `json:"sessionId"`
	ObservedUnixNanos int64  `json:"observedUnixNanos"`
	Component         string `json:"component"`
	ObservationBase64 string `json:"observationBase64"`
}

func (v commandAbsenceVerifier) VerifyMountAbsence(id volumeserver.SessionID, proof volumeserver.MountAbsenceProof) error {
	payload, err := json.Marshal(mountAbsenceClaim{
		SessionID:         hex.EncodeToString(id[:]),
		ObservedUnixNanos: proof.ObservedUnixNanos,
		Component:         proof.Component,
		ObservationBase64: base64.StdEncoding.EncodeToString(proof.Observation),
	})
	if err != nil {
		return fmt.Errorf("encode mount-absence claim: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()
	// The command is executed directly, not through a shell: the operator
	// names one program, and everything variable travels on stdin where no
	// quoting can reinterpret it.
	cmd := exec.CommandContext(ctx, v.command)
	cmd.Stdin = bytes.NewReader(payload)
	// Without WaitDelay a verifier that spawned its own child would keep the
	// output pipe open past the timeout and Wait would block on it; the delay
	// makes the context bound the whole run, orphaned children included.
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("mount-absence verification command exceeded %s", v.timeout)
		}
		return fmt.Errorf("mount-absence verification refused: %w (output: %s)", err, truncateForError(output))
	}
	return nil
}

func truncateForError(output []byte) string {
	const bound = 512
	if len(output) > bound {
		output = output[:bound]
	}
	return string(output)
}
