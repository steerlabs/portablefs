//go:build linux

package cellhost

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/cellhelper"
	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

type quiesceFenceRunner struct {
	active bool
	calls  []recordedCommand
}

func (runner *quiesceFenceRunner) Run(_ context.Context, executable string, arguments ...string) ([]byte, error) {
	runner.calls = append(runner.calls, recordedCommand{executable: executable, arguments: append([]string(nil), arguments...)})
	if len(arguments) == 0 {
		return nil, nil
	}
	switch arguments[0] {
	case "is-active":
		if runner.active && strings.HasSuffix(arguments[len(arguments)-1], ".service") {
			return nil, nil
		}
		return nil, errors.New("inactive")
	case "stop":
		runner.active = false
	}
	return nil, nil
}

func quiesceRequestPath(fixture *placementFixture) string {
	return filepath.Join(fixture.configRoot, testVolumeID, quiesceRequestName)
}

func quiesceProofPath(fixture *placementFixture) string {
	return filepath.Join(fixture.stateRoot, testVolumeID, quiesceProofName)
}

// writeProof stands in for the authority half of the handshake, which lives in
// another lane. It writes the record the way the authority will: as the owner
// of its StateRoot, private.
func writeProof(t *testing.T, fixture *placementFixture, proof QuiesceProof, mode os.FileMode) {
	t.Helper()
	payload, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	path := quiesceProofPath(fixture)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func answeredProof(nonce string) QuiesceProof {
	return QuiesceProof{
		VolumeID:            testVolumeID,
		AuthorityEpoch:      7,
		WireSessionEpochHex: hex.EncodeToString([]byte("0123456789abcdef")),
		Nonce:               nonce,
		MembershipEmpty:     true,
		WrittenUnix:         1_760_000_000,
	}
}

// TestQuiesceRequestIsFreshAndReadableByTheAuthority: the authority sees the
// ConfigRoot read-only as the service user, so a request it cannot read is a
// request that can never be answered.
func TestQuiesceRequestIsFreshAndReadableByTheAuthority(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("handing the request to the service group needs chown privilege, as the helper has")
	}
	fixture := newPlacementFixture(t)
	first, err := fixture.host.WriteQuiesceRequest(testVolumeID, 210000)
	if err != nil {
		t.Fatal(err)
	}
	if !validQuiesceNonce(first) {
		t.Fatalf("nonce %q is not 32 bytes of lowercase hex", first)
	}
	info, err := os.Lstat(quiesceRequestPath(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o440 {
		t.Fatalf("quiesce request mode = %#o, want 0440", info.Mode().Perm())
	}
	var request quiesceRequest
	payload, err := os.ReadFile(quiesceRequestPath(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	if request.Nonce != first || request.RequestedUnix <= 0 {
		t.Fatalf("quiesce request = %+v, want the returned nonce and a timestamp", request)
	}

	// A second request supersedes the first: a proof answering the old nonce
	// must not satisfy the new attempt.
	second, err := fixture.host.WriteQuiesceRequest(testVolumeID, 210000)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("a repeated quiesce request reused its nonce")
	}
	if err := fixture.host.ClearQuiesceRequest(testVolumeID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(quiesceRequestPath(fixture)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleared quiesce request survived: %v", err)
	}
	if err := fixture.host.ClearQuiesceRequest(testVolumeID); err != nil {
		t.Fatalf("clearing an absent quiesce request is not idempotent: %v", err)
	}
	for _, gid := range []uint32{0, 999} {
		if _, err := fixture.host.WriteQuiesceRequest(testVolumeID, gid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("WriteQuiesceRequest with gid %d = %v, want ErrInvalid", gid, err)
		}
	}
	if _, err := fixture.host.WriteQuiesceRequest("not-a-uuid", 210000); !errors.Is(err, ErrInvalid) {
		t.Fatal("an invalid volume ID was accepted")
	}
}

// TestReadQuiesceProofRoundTripsTheAuthorityAnswer, including the sentinel for
// the ordinary "not written yet" state that the archive gate waits on.
func TestReadQuiesceProofRoundTripsTheAuthorityAnswer(t *testing.T) {
	fixture := newPlacementFixture(t)
	if _, err := fixture.host.ReadQuiesceProof(testVolumeID); !errors.Is(err, ErrQuiesceProofAbsent) {
		t.Fatalf("missing proof error = %v, want ErrQuiesceProofAbsent", err)
	}
	// The nonce is written here rather than through WriteQuiesceRequest so the
	// read path is testable without the chown privilege the write path needs.
	nonce := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	writeProof(t, fixture, answeredProof(nonce), 0o600)
	proof, err := fixture.host.ReadQuiesceProof(testVolumeID)
	if err != nil {
		t.Fatal(err)
	}
	if proof != answeredProof(nonce) {
		t.Fatalf("proof = %+v, want %+v", proof, answeredProof(nonce))
	}
	if !proof.Proves(testVolumeID, 7, nonce) {
		t.Fatal("a matching proof was not accepted")
	}
}

// TestReadQuiesceProofFailsClosed: this record is what lets the manager stop a
// serving authority and then destroy the data, so anything that is not exactly
// a well-formed proof for this volume is refused.
func TestReadQuiesceProofFailsClosed(t *testing.T) {
	nonce := hex.EncodeToString(make([]byte, quiesceNonceBytes))
	for name, mutate := range map[string]func(*QuiesceProof){
		"other volume": func(proof *QuiesceProof) { proof.VolumeID = "22222222-2222-4222-8222-222222222223" },
		"no volume":    func(proof *QuiesceProof) { proof.VolumeID = "" },
		"no epoch":     func(proof *QuiesceProof) { proof.AuthorityEpoch = 0 },
		"no timestamp": func(proof *QuiesceProof) { proof.WrittenUnix = 0 },
		"short nonce":  func(proof *QuiesceProof) { proof.Nonce = hex.EncodeToString(make([]byte, 8)) },
		"no nonce":     func(proof *QuiesceProof) { proof.Nonce = "" },
		"bad wire epoch": func(proof *QuiesceProof) {
			proof.WireSessionEpochHex = hex.EncodeToString(make([]byte, 8))
		},
	} {
		fixture := newPlacementFixture(t)
		proof := answeredProof(nonce)
		mutate(&proof)
		writeProof(t, fixture, proof, 0o600)
		if _, err := fixture.host.ReadQuiesceProof(testVolumeID); err == nil {
			t.Fatalf("%s: a malformed quiesce proof was accepted", name)
		}
	}

	trailing := newPlacementFixture(t)
	writeProof(t, trailing, answeredProof(nonce), 0o600)
	appended, err := os.ReadFile(quiesceProofPath(trailing))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(quiesceProofPath(trailing), append(appended, []byte("{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := trailing.host.ReadQuiesceProof(testVolumeID); err == nil {
		t.Fatal("a quiesce proof with trailing data was accepted")
	}

	writable := newPlacementFixture(t)
	writeProof(t, writable, answeredProof(nonce), 0o666)
	if _, err := writable.host.ReadQuiesceProof(testVolumeID); err == nil {
		t.Fatal("a world-writable quiesce proof was accepted")
	}

	unknown := newPlacementFixture(t)
	writeTestFile(t, quiesceProofPath(unknown), `{"volume_id":"`+testVolumeID+`","surprise":1}`)
	if _, err := unknown.host.ReadQuiesceProof(testVolumeID); err == nil {
		t.Fatal("a quiesce proof with unknown fields was accepted")
	}

	linked := newPlacementFixture(t)
	writeProof(t, linked, answeredProof(nonce), 0o600)
	elsewhere := filepath.Join(linked.stateRoot, testVolumeID, "elsewhere.json")
	if err := os.Rename(quiesceProofPath(linked), elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, quiesceProofPath(linked)); err != nil {
		t.Fatal(err)
	}
	if _, err := linked.host.ReadQuiesceProof(testVolumeID); err == nil {
		t.Fatal("a symlinked quiesce proof path was followed")
	}
}

func TestApplyQuiesceFenceAcceptsMatchingProofAndFencesAuthority(t *testing.T) {
	fixture := newPlacementFixture(t)
	runner := &quiesceFenceRunner{active: true}
	fixture.host.cfg.Runner = runner
	nonce := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	writeProof(t, fixture, answeredProof(nonce), 0o600)
	writeMembership(t, fixture, membershipDocument(testVolumeID), 0o600)
	plan := cellplan.VolumePlan{VolumeID: testVolumeID, Phase: cellplan.PhaseQuiesce, AuthorityGeneration: 7, ServiceGID: 210000}
	previous := cellhelper.Assignment{LastPhase: cellplan.PhaseQuiesce, LastQuiesceNonce: nonce}

	observed, update := fixture.host.Apply(context.Background(), plan, previous)
	if observed.Error != "" || !observed.AuthorityAbsent || !observed.QuiesceProven || update.LastQuiesceNonce != "" {
		t.Fatalf("quiesce observation = %+v, update = %+v", observed, update)
	}
	if runner.active {
		t.Fatal("matching quiesce proof did not stop the authority")
	}
}

func TestApplyQuiesceFenceRefusesStaleProof(t *testing.T) {
	fixture := newPlacementFixture(t)
	runner := &quiesceFenceRunner{active: true}
	fixture.host.cfg.Runner = runner
	requested := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	stale := hex.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	writeProof(t, fixture, answeredProof(stale), 0o600)
	plan := cellplan.VolumePlan{VolumeID: testVolumeID, Phase: cellplan.PhaseQuiesce, AuthorityGeneration: 7, ServiceGID: 210000}
	previous := cellhelper.Assignment{LastPhase: cellplan.PhaseQuiesce, LastQuiesceNonce: requested}

	observed, _ := fixture.host.Apply(context.Background(), plan, previous)
	if !strings.Contains(observed.Error, "does not match the current request") || observed.AuthorityAbsent || observed.QuiesceProven {
		t.Fatalf("stale proof observation = %+v", observed)
	}
	if !runner.active {
		t.Fatal("stale quiesce proof stopped the authority")
	}
}

func TestApplyQuiesceFenceHandlesAuthorityAlreadyAbsent(t *testing.T) {
	t.Run("matching persisted proof converges", func(t *testing.T) {
		fixture := newPlacementFixture(t)
		fixture.host.cfg.Runner = &quiesceFenceRunner{}
		nonce := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
		writeProof(t, fixture, answeredProof(nonce), 0o600)
		writeMembership(t, fixture, membershipDocument(testVolumeID), 0o600)
		plan := cellplan.VolumePlan{VolumeID: testVolumeID, Phase: cellplan.PhaseQuiesce, AuthorityGeneration: 7, ServiceGID: 210000}
		previous := cellhelper.Assignment{LastPhase: cellplan.PhaseQuiesce, LastQuiesceNonce: nonce}

		observed, _ := fixture.host.Apply(context.Background(), plan, previous)
		if observed.Error != "" || !observed.AuthorityAbsent || !observed.QuiesceProven {
			t.Fatalf("already-absent observation = %+v", observed)
		}
	})

	t.Run("missing proof fails without restart", func(t *testing.T) {
		fixture := newPlacementFixture(t)
		runner := &quiesceFenceRunner{}
		fixture.host.cfg.Runner = runner
		nonce := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
		plan := cellplan.VolumePlan{VolumeID: testVolumeID, Phase: cellplan.PhaseQuiesce, AuthorityGeneration: 7, ServiceGID: 210000}
		previous := cellhelper.Assignment{LastPhase: cellplan.PhaseQuiesce, LastQuiesceNonce: nonce}

		observed, _ := fixture.host.Apply(context.Background(), plan, previous)
		if !strings.Contains(observed.Error, "disappeared before writing its quiesce proof") || observed.AuthorityAbsent || observed.QuiesceProven {
			t.Fatalf("missing-proof observation = %+v", observed)
		}
		for _, call := range runner.calls {
			if len(call.arguments) > 0 && (call.arguments[0] == "start" || call.arguments[0] == "restart") {
				t.Fatalf("already-absent authority was restarted: %+v", call)
			}
		}
	})
}
