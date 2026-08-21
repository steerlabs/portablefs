//go:build linux

package tierede2e

// The decisive end-to-end proof of tiered storage: one volume goes through the
// entire lifecycle on real XFS with project quotas, behind a real kernel FUSE
// mount, driven by the real archiver, the real hydrator, the real
// authority-side restore mode, and the Manager's own independent verifier.
//
//	archive -> verify -> destroy -> restore -> serve while cold -> converge
//
// Every component is the shipping one. The only fakes are the object store
// (an in-process S3, because the cell has no credentials in CI) and the drain
// parking lever, which reports entries unlinked so that a read this test calls
// cold is provably cold rather than racing a background sweep.
//
// What each stage is for:
//
//   - ArchiveAndVerify proves the seal describes what was uploaded and that the
//     Manager's independent verifier — which trusts nothing the cell reported —
//     accepts it.
//   - DestroyAndReprovision removes the source outright and restores into a
//     different XFS directory, so nothing downstream can be satisfied by
//     surviving placement state.
//   - RestoreNamespace proves the instant namespace: every name, mode,
//     nanosecond mtime, xattr, symlink target, hardlink relation and logical
//     size is present with zero allocated blocks.
//   - ServeWhileCold proves reads, writes, truncates and holes through the
//     kernel while the content is still in the archive.
//   - RestrictedModesAreCarried proves the two halves of a mode that denies its
//     own owner: the archiver reads such an inode under CAP_DAC_READ_SEARCH,
//     and the restore then carries the exact mode and hydrates bytes into it
//     with no capability at all.
//   - RestoreBlockedAndRecovers proves the named degraded state: a dead
//     hydrator fails content reads volume-wide with the restore class, not with
//     a hang and not with fatal storage, and clears when it returns.
//   - ColdTreeMatchesTheArchive reads the whole tree through the mount and
//     compares it byte for byte and attribute for attribute with the tree that
//     no longer exists.
//   - Converge waits on the real convergence record, then restarts the
//     authority with restore mode off and re-verifies everything — the volume
//     is now behaviourally identical to one that was never archived.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archiver"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
	"github.com/steerlabs/portablefs/vcs/internal/archiveverify"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"github.com/steerlabs/portablefs/vcs/internal/hydrator"
	"github.com/steerlabs/portablefs/vcs/internal/restoremode"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

const (
	lifecycleVolumeID = "0f0e0d0c-0b0a-4908-8706-050403020100"
	lifecycleCellID   = "22222222-3333-4444-8555-666666666666"
	lifecycleAttempt  = "11111111-2222-4333-8444-555555555555"
	lifecycleEpoch    = uint64(7)
	// lifecycleAuthorityEpoch is the generation of the authority that serves the
	// restore. It is deliberately different from the sealed epoch: the
	// convergence record names the serving authority, the manifest names the
	// authority that sealed.
	lifecycleAuthorityEpoch = uint64(9)
	lifecycleKeyVersion     = "v1"
)

func TestTieredVolumeLifecycleOnXFS(t *testing.T) {
	env := requirePrivilegedEnvironment(t)
	client, objects := newTestStore(t)

	// Everything with a lifetime — directories, the state root, the hydrator,
	// the authority, the mount — is constructed against the top-level test, so
	// that a subtest finishing never tears down what the next stage needs. The
	// subtests carry assertions only.
	sourceRoot := newVolumeDirectory(t, env, "source")
	tree := buildSourceTree(t, sourceRoot)
	tree.facts = snapshotTree(t, sourceRoot)

	sealed := runArchiver(t, client, sourceRoot)
	manifest := loadManifest(t, client, sealed)
	stage(t, "ArchiveAndVerify", func(t *testing.T) {
		checkSealDescribesTheManifest(t, sealed, manifest, len(tree.facts))
		checkArchiveShape(t, manifest)
	})

	// The cell-side destroy. The archive is now the only copy of this tree, and
	// the restore target is a different directory inside the provisioned XFS
	// project — a different placement, with its own inherited project quota, so
	// nothing below can be satisfied by surviving source state.
	if err := os.RemoveAll(sourceRoot); err != nil {
		t.Fatalf("destroy the source placement: %v", err)
	}
	targetRoot := newVolumeDirectory(t, env, "target")
	stateDir := shortStateDir(t, "pfs-tiered-state-")
	restoreNamespace(t, client, sealed, targetRoot, stateDir)
	namespace := snapshotTree(t, targetRoot)
	stage(t, "InstantNamespaceOnANewPlacement", func(t *testing.T) {
		if _, err := os.Lstat(sourceRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the source placement survived the destroy: %v", err)
		}
		if !fileExists(filepath.Join(stateDir, hydrator.ReadyName)) {
			t.Fatal("the hydrator reported no namespace-ready marker")
		}
		if !fileExists(filepath.Join(stateDir, hydrator.BindingsName)) {
			t.Fatal("the hydrator wrote no restore-bindings table")
		}
		active, err := restoremode.Active(stateDir)
		if err != nil || !active {
			t.Fatalf("restore activation is state-driven and reads %v (%v), want active", active, err)
		}
		compareNamespace(t, tree.facts, namespace, "after the namespace restore")
	})

	serve := startHydrator(t, client, sealed, stateDir)
	var wiring *restoreWiring
	live := startServing(t, env, lifecycleVolumeID, targetRoot, func(t *testing.T, store *xfsstore.Volume) *restoreWiring {
		wiring = openRestoreMode(t, store, stateDir)
		return wiring
	})
	mutations := map[string]expectation{}
	created := map[string][]byte{}
	stage(t, "ServeWhileCold", func(t *testing.T) {
		if got := wiring.mode.ChunkSize(); got != lifecycleChunkSize {
			t.Fatalf("INFO crossed the wire with chunk size %d, want %d", got, lifecycleChunkSize)
		}
		serveWhileCold(t, live, objects, tree, mutations, created)
	})

	stage(t, "RestrictedModesAreCarried", func(t *testing.T) {
		checkRestrictedModes(t, live, targetRoot, tree, namespace, manifest)
	})

	// The failure surface, with content still cold: the hydrator dies.
	serve.stop(t)
	stage(t, "RestoreBlockedIsUniformAndNonFatal", func(t *testing.T) {
		checkRestoreBlocked(t, live)
	})
	serve = startHydrator(t, client, sealed, stateDir)
	stage(t, "RestoreBlockedClearsWhenTheHydratorReturns", func(t *testing.T) {
		checkRestoreRecovers(t, live, tree)
	})

	stage(t, "ColdTreeMatchesTheArchive", func(t *testing.T) {
		before := objects.rangeGets()
		compareTrees(t, tree.facts, snapshotTree(t, live.mountPath), mutations, created,
			"reading the whole tree cold through the mount")
		if objects.rangeGets() <= before {
			t.Fatal("reading the whole tree cold issued no ranged GET, so nothing was recalled from the archive")
		}
	})

	wiring.park.park(false)
	stage(t, "Converge", func(t *testing.T) {
		waitFor(t, 3*time.Minute, "the drain to converge", func() bool {
			if wiring.mode.Active() {
				return false
			}
			active, err := restoremode.Active(stateDir)
			return err == nil && !active
		})
		checkConvergedRecord(t, stateDir)
		waitFor(t, 30*time.Second, "the progress record to report full hydration", func() bool {
			progress, err := readProgress(stateDir)
			return err == nil && progress.ProgressPermille == 1000 && progress.State == ""
		})
	})

	// Converged means the helper stops the hydrator unit and the next signed
	// plan is plain SERVE. Both are done here: the archive and the hydrator are
	// gone, and the authority is restarted with restore mode off.
	live.stop()
	serve.stop(t)
	before := objects.rangeGets()
	plain := startServing(t, env, lifecycleVolumeID, targetRoot, nil)
	stage(t, "PlainServingAfterConvergence", func(t *testing.T) {
		active, err := restoremode.Active(stateDir)
		if err != nil || active {
			t.Fatalf("restore activation after convergence reads %v (%v), want inactive", active, err)
		}
		compareTrees(t, tree.facts, snapshotTree(t, plain.mountPath), mutations, created,
			"after restarting the authority with restore mode off")
		checkSparseHoleReadsZeroes(t, plain.mountPath)
		if after := objects.rangeGets(); after != before {
			t.Fatalf("a converged volume issued %d ranged GETs; it must be authoritative in XFS alone", after-before)
		}
	})
	plain.stop()

	// The Manager's own independent verification of the archive that the whole
	// lifecycle above was restored from. It is read-only over immutable objects,
	// so it is placed last on purpose: it belongs to the control plane rather
	// than to the data plane, and a defect there must be attributable on its own
	// rather than masking the cell-side proof it gates.
	stage(t, "ManagerIndependentVerification", func(t *testing.T) {
		verifyLikeTheManager(t, client, sealed)
	})
}

// stage runs one step of the single lifecycle. The steps are strictly ordered —
// there is no meaning to "restore" without "archive" — so a failed step ends the
// test rather than letting later steps report confusing secondary failures.
func stage(t *testing.T, name string, fn func(*testing.T)) {
	t.Helper()
	if !t.Run(name, fn) {
		t.Fatalf("lifecycle stage %q failed; the remaining stages cannot be evaluated", name)
	}
}

// ---------------------------------------------------------------------------
// Serve while cold.
// ---------------------------------------------------------------------------

func serveWhileCold(t *testing.T, live *serving, objects *fakeStore, tree *sourceTree,
	mutations map[string]expectation, created map[string][]byte) {
	t.Helper()
	chunk := int64(lifecycleChunkSize)
	big := tree.bytes[pathBig]

	// Scattered ranges of the multi-chunk file, including one that straddles a
	// chunk boundary and one at the partial tail. Each is a demand recall
	// through the kernel, the authority, the hydrator, and a ranged GET.
	before := objects.rangeGets()
	for _, span := range []struct {
		offset int64
		length int
	}{
		{0, 4096},
		{chunk + 13, 5000},
		{2*chunk - 7, 9000},
		{int64(len(big)) - 1000, 1000},
	} {
		got := mustReadAt(t, live.join(pathBig), span.offset, span.length, "cold scattered read")
		want := big[span.offset : span.offset+int64(span.length)]
		if string(got) != string(want) {
			t.Fatalf("cold read of %s at [%d,%d) is %s, want %s",
				pathBig, span.offset, span.offset+int64(span.length), describeBytes(got), describeBytes(want))
		}
	}
	if objects.rangeGets() <= before {
		t.Fatal("the scattered cold reads issued no ranged GET, so they were not served from the archive")
	}

	// Small files that share one pack frame.
	for _, path := range []string{pathSmallA, pathSmallB, pathSmallC} {
		got := mustReadFile(t, live.join(path), "cold read of "+path)
		if string(got) != string(tree.bytes[path]) {
			t.Fatalf("cold read of %s does not match the archived bytes", path)
		}
	}

	// Hydration is invisible base-byte movement, so an inode the user has not
	// mutated keeps its archived mtime across a recall.
	for _, path := range []string{pathBig, pathSmallA} {
		info, err := os.Stat(live.join(path))
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got, want := info.ModTime().UnixNano(), tree.facts[path].mtimeNS; got != want {
			t.Fatalf("recall moved the mtime of %s to %d; the archive says %d", path, got, want)
		}
	}

	// A cold whole-hole chunk: the archive stores nothing for it, the restore
	// created it as a hole, and reading it must return zeroes without fetching.
	beforeHole := objects.rangeGets()
	checkSparseHoleReadsZeroes(t, live.mountPath)
	if after := objects.rangeGets(); after != beforeHole {
		t.Fatalf("reading a hole issued %d ranged GETs; a whole-hole chunk is born hydrated", after-beforeHole)
	}

	// A partial write inside a cold chunk: the authority must recall the base
	// bytes, apply the mutation on top, and from then on let the user's mtime
	// win over every later hydration write.
	patch := []byte("a user mutation lands on recalled base bytes")
	writeMePath := live.join(pathWriteMe)
	handle, err := os.OpenFile(writeMePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s for writing: %v", pathWriteMe, err)
	}
	if _, err := handle.WriteAt(patch, 700); err != nil {
		_ = handle.Close()
		t.Fatalf("write into %s: %v", pathWriteMe, err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("close %s: %v", pathWriteMe, err)
	}
	expectedWrite := append([]byte(nil), tree.bytes[pathWriteMe]...)
	copy(expectedWrite[700:], patch)
	got := mustReadFile(t, writeMePath, "read back "+pathWriteMe)
	if string(got) != string(expectedWrite) {
		t.Fatalf("%s does not carry the archived bytes with the mutation applied", pathWriteMe)
	}
	info, err := os.Stat(writeMePath)
	if err != nil {
		t.Fatalf("stat %s: %v", pathWriteMe, err)
	}
	if info.ModTime().UnixNano() <= tree.facts[pathWriteMe].mtimeNS {
		t.Fatalf("%s was written through the mount but its mtime is still the archived %d",
			pathWriteMe, tree.facts[pathWriteMe].mtimeNS)
	}
	mutations[pathWriteMe] = expectation{content: expectedWrite, mtimeMoved: true}

	// A shortening truncate that lands inside the first chunk of a three-chunk
	// file: the boundary chunk must be recalled before it is shortened, and
	// everything beyond the new end must simply disappear.
	newSize := int64(lifecycleChunkSize)/2 + 3
	truncatePath := live.join(pathTruncateMe)
	if err := os.Truncate(truncatePath, newSize); err != nil {
		t.Fatalf("truncate %s: %v", pathTruncateMe, err)
	}
	expectedTruncate := append([]byte(nil), tree.bytes[pathTruncateMe][:newSize]...)
	got = mustReadFile(t, truncatePath, "read back "+pathTruncateMe)
	if string(got) != string(expectedTruncate) {
		t.Fatalf("%s does not carry the archived prefix after the truncate", pathTruncateMe)
	}
	info, err = os.Stat(truncatePath)
	if err != nil {
		t.Fatalf("stat %s: %v", pathTruncateMe, err)
	}
	if info.Size() != newSize {
		t.Fatalf("%s is %d bytes after truncating to %d", pathTruncateMe, info.Size(), newSize)
	}
	if info.ModTime().UnixNano() <= tree.facts[pathTruncateMe].mtimeNS {
		t.Fatalf("%s was truncated through the mount but its mtime is still the archived %d",
			pathTruncateMe, tree.facts[pathTruncateMe].mtimeNS)
	}
	mutations[pathTruncateMe] = expectation{content: expectedTruncate, mtimeMoved: true}

	// A brand new file in a restoring volume: it has no manifest entry, no
	// binding, and no hydration state, and it must simply work.
	fresh := []byte("a file created while the volume was still draining")
	if err := os.WriteFile(live.join("newly-created.txt"), fresh, 0o644); err != nil {
		t.Fatalf("create a new file through the mount: %v", err)
	}
	roundTrip := mustReadFile(t, live.join("newly-created.txt"), "read back the new file")
	if string(roundTrip) != string(fresh) {
		t.Fatal("the new file does not read back what was written to it")
	}
	created["newly-created.txt"] = fresh
	// Creating a child moves its parent's mtime — ordinary filesystem semantics
	// that restore mode neither suspends nor should. The volume root is also
	// where the serving authority materializes its own protected namespace, so
	// its mtime is expected to be newer than the archive's rather than equal to
	// it; every other directory in the tree still has to match exactly.
	mutations["."] = expectation{mtimeMoved: true}
}

// checkSparseHoleReadsZeroes reads inside the sparse file's whole-hole chunks.
// The archive records no bytes there, so the restored file must answer zeroes
// out of its own holes.
func checkSparseHoleReadsZeroes(t *testing.T, root string) {
	t.Helper()
	offset := int64(lifecycleChunkSize) + int64(lifecycleChunkSize)/2
	got := mustReadAt(t, filepath.Join(root, pathSparse), offset, 4096, "read a cold hole")
	for index, value := range got {
		if value != 0 {
			t.Fatalf("byte %d of the hole at offset %d is %#x, want zero", int64(index)+offset, offset, value)
		}
	}
}

// ---------------------------------------------------------------------------
// The named degraded state.
// ---------------------------------------------------------------------------

// checkRestoreBlocked runs with the hydrator already stopped and content still
// cold. RESTORE_BLOCKED is volume-wide, uniform, non-fatal, and bounded.
func checkRestoreBlocked(t *testing.T, live *serving) {
	t.Helper()
	// A file nothing has touched yet, so its content is provably still in the
	// archive, and one that was already recalled.
	coldPath := live.join(pathUnicode)
	hotPath := live.join(pathBig)

	// A cold read fails with the restore class. The authority maps that class
	// to EIO — deliberately not EAGAIN, which parks poll-driven runtimes on a
	// pollable FUSE file — while FAILURE_CLASS_RESTORE keeps it out of the
	// fatal-storage classification, so the store is never fenced. The read is
	// bounded here because "does not hang" is half the claim.
	done := make(chan error, 1)
	go func() {
		_, err := rawReadAt(coldPath, 0, 4096)
		done <- err
	}()
	select {
	case err := <-done:
		checkRestoreClass(t, err, "a cold read with the hydrator gone")
	case <-time.After(60 * time.Second):
		t.Fatal("a cold read with the hydrator gone hung instead of failing with the restore class")
	}

	// The state is volume-wide and uniform by design: an already-recalled file
	// fails the same way, so a client never sees hydrated-versus-cold roulette.
	_, err := rawReadAt(hotPath, 0, 4096)
	checkRestoreClass(t, err, "a previously recalled read with the hydrator gone")

	// Namespace and attribute operations are unaffected, and the mount's session
	// is still alive: RESTORE_BLOCKED is a content state, not a mount failure.
	if _, err := os.Lstat(coldPath); err != nil {
		t.Fatalf("lstat failed while the volume was restore-blocked: %v", err)
	}
	if _, err := os.ReadDir(live.join("docs")); err != nil {
		t.Fatalf("readdir failed while the volume was restore-blocked: %v", err)
	}
	select {
	case <-live.client.SessionDone():
		t.Fatalf("the authority session ended during a restore-blocked window: %v", live.client.SessionError())
	default:
	}
}

// checkRestoreRecovers runs after the hydrator has been restarted. The state
// auto-clears on the authority's own health probe, so the read is retried
// against that real signal until it succeeds within bound.
func checkRestoreRecovers(t *testing.T, live *serving, tree *sourceTree) {
	t.Helper()
	coldPath := live.join(pathUnicode)
	want := tree.bytes[pathUnicode]
	var recovered []byte
	waitFor(t, 90*time.Second, "the restore-blocked state to clear after the hydrator returned", func() bool {
		payload, err := rawReadAt(coldPath, 0, len(want))
		if err != nil {
			return false
		}
		recovered = payload
		return true
	})
	if string(recovered) != string(want) {
		t.Fatalf("%s does not match the archived bytes after recovery", pathUnicode)
	}
}

func checkRestoreClass(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s succeeded; a volume with no hydrator cannot serve content", what)
	}
	if errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("%s failed with EAGAIN, which parks poll-driven runtimes on a pollable FUSE file: %v", what, err)
	}
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("%s failed with %v, want the restore class errno (EIO)", what, err)
	}
}

// ---------------------------------------------------------------------------
// Driving the real archiver, hydrator, and restore mode.
// ---------------------------------------------------------------------------

func archiverLaunchConfig(volumeID, attempt string) archiver.LaunchConfig {
	return archiver.LaunchConfig{
		Version:           archiver.LaunchConfigVersion,
		VolumeID:          volumeID,
		CellID:            lifecycleCellID,
		AuthorityEpoch:    lifecycleEpoch,
		PlacementSequence: 1,
		Attempt:           attempt,
		KeyVersion:        lifecycleKeyVersion,
		ChunkSizeBytes:    lifecycleChunkSize,
	}
}

// archiveTree runs the real ARCHIVE phase over a volume tree and returns the
// seal, or the error the phase refused with.
func archiveTree(t *testing.T, client *archivestore.Client, root string, config archiver.LaunchConfig) (archiver.Sealed, error) {
	t.Helper()
	resultDir := t.TempDir()
	if err := archiver.Run(context.Background(), archiver.Options{
		LaunchConfigPath: writeJSONFile(t, t.TempDir(), archiver.LaunchConfigName, config),
		VolumeRoot:       root,
		ResultDir:        resultDir,
		Client:           client,
		Now:              func() time.Time { return time.Unix(1_700_000_100, 0) },
		Logf:             t.Logf,
	}); err != nil {
		return archiver.Sealed{}, err
	}
	return archiver.ReadSealed(filepath.Join(resultDir, archiver.SealedName))
}

func runArchiver(t *testing.T, client *archivestore.Client, root string) archiver.Sealed {
	t.Helper()
	sealed, err := archiveTree(t, client, root, archiverLaunchConfig(lifecycleVolumeID, lifecycleAttempt))
	if err != nil {
		t.Fatalf("archive the source volume: %v", err)
	}
	return sealed
}

func hydratorLaunchConfig(sealed archiver.Sealed, mode string) hydrator.LaunchConfig {
	return hydrator.LaunchConfig{
		Version:           hydrator.LaunchConfigVersion,
		VolumeID:          sealed.VolumeID,
		CellID:            sealed.CellID,
		SealedEpoch:       sealed.SealedEpoch,
		Attempt:           sealed.Attempt,
		Mode:              mode,
		ManifestSHA256:    sealed.Manifest.SHA256,
		ManifestSizeBytes: sealed.Manifest.SizeBytes,
		ManifestCRC64NVME: sealed.Manifest.CRC64NVME,
		ChunkSizeBytes:    sealed.ChunkSizeBytes,
	}
}

func restoreNamespaceInto(t *testing.T, client *archivestore.Client, sealed archiver.Sealed, root, stateDir string) error {
	t.Helper()
	return hydrator.Run(context.Background(), hydrator.Options{
		LaunchConfigPath: writeJSONFile(t, t.TempDir(), hydrator.LaunchConfigName,
			hydratorLaunchConfig(sealed, hydrator.ModeRestoreNamespace)),
		VolumeRoot: root,
		StateDir:   stateDir,
		Client:     client,
		Now:        func() time.Time { return time.Unix(1_700_000_200, 0) },
		Logf:       t.Logf,
	})
}

func restoreNamespace(t *testing.T, client *archivestore.Client, sealed archiver.Sealed, root, stateDir string) {
	t.Helper()
	if err := restoreNamespaceInto(t, client, sealed, root, stateDir); err != nil {
		t.Fatalf("restore the namespace into the new placement: %v", err)
	}
}

// hydratorProcess is one serve-mode hydrator, started and stopped the way the
// helper starts and stops its unit.
type hydratorProcess struct {
	cancel  context.CancelFunc
	done    chan error
	stopped atomic.Bool
	socket  string
}

func startHydrator(t *testing.T, client *archivestore.Client, sealed archiver.Sealed, stateDir string) *hydratorProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	process := &hydratorProcess{cancel: cancel, done: make(chan error, 1),
		socket: filepath.Join(stateDir, hydrator.SocketName)}
	options := hydrator.Options{
		LaunchConfigPath: writeJSONFile(t, t.TempDir(), hydrator.LaunchConfigName,
			hydratorLaunchConfig(sealed, hydrator.ModeServe)),
		StateDir: stateDir,
		Client:   client,
		Logf:     t.Logf,
	}
	go func() { process.done <- hydrator.Run(ctx, options) }()
	t.Cleanup(func() { process.stop(t) })
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(process.socket); err == nil {
			return process
		}
		if time.Now().After(deadline) {
			t.Fatal("the hydrator never created its serve socket")
		}
		select {
		case err := <-process.done:
			t.Fatalf("the hydrator exited before it listened: %v", err)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// stop ends the hydrator and waits for it, so that "the hydrator is gone" is a
// fact rather than a hope when the next assertion runs.
func (h *hydratorProcess) stop(t *testing.T) {
	t.Helper()
	if h == nil || !h.stopped.CompareAndSwap(false, true) {
		return
	}
	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			t.Errorf("the hydrator returned %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the hydrator did not stop when its context was cancelled")
	}
	// "The hydrator is gone" has to be a fact, not a hope, before the blocked
	// assertions run: the socket it listened on must no longer exist.
	waitFor(t, 10*time.Second, "the hydrator to remove its serve socket", func() bool {
		_, err := os.Lstat(h.socket)
		return errors.Is(err, os.ErrNotExist)
	})
}

// openRestoreMode assembles the authority-side restore stack exactly as
// cmd/portablefs-authority does: activation is decided by the state markers,
// the bindings come from the hydrator's own table, the inode identities are
// resolved by walking the materialized namespace, and the Mode is opened over
// the result.
func openRestoreMode(t *testing.T, store *xfsstore.Volume, stateDir string) *restoreWiring {
	t.Helper()
	active, err := restoremode.Active(stateDir)
	if err != nil {
		t.Fatalf("inspect restore activation markers: %v", err)
	}
	if !active {
		t.Fatal("restore mode is not active, so this authority would serve an unhydrated tree as canonical")
	}
	bindings, err := restoremode.LoadBindings(filepath.Join(stateDir, restoremode.BindingsFilename), 1<<24)
	if err != nil {
		t.Fatalf("load the restore bindings: %v", err)
	}
	files, err := store.ResolveRestoreFiles(bindings.IdentityMap(), uint64(bindings.Len())*2+1024)
	if err != nil {
		t.Fatalf("bind restored namespace identities: %v", err)
	}
	park := newParkableStore(files)
	mode, err := restoremode.Open(context.Background(), restoremode.Config{
		StateRoot: stateDir, VolumeID: lifecycleVolumeID, AuthorityEpoch: lifecycleAuthorityEpoch,
		Store: park, Bindings: bindings,
		// Bounded well inside the connection write timeout, and fast enough that
		// a stalled stage fails the test rather than the CI job's wall clock.
		// RecallLimit is above the mount's in-flight bound on purpose: recall
		// saturation is a distinct named failure with its own coverage, and this
		// test asserts the blocked state, so a burst of parallel kernel reads
		// must not be able to answer with the wrong one.
		RecallDeadline: 15 * time.Second, RecallLimit: 96, PoolSize: 8, DrainWorkers: 4,
		DrainHysteresis: 100 * time.Millisecond, ProgressInterval: 100 * time.Millisecond,
	})
	if err != nil {
		_ = files.Close()
		t.Fatalf("start restore mode: %v", err)
	}
	return &restoreWiring{mode: mode, files: files, park: park}
}

// ---------------------------------------------------------------------------
// Assertions about the seal, the manifest, and the Manager's verification.
// ---------------------------------------------------------------------------

func loadManifest(t *testing.T, client *archivestore.Client, sealed archiver.Sealed) *archive.Manifest {
	t.Helper()
	payload, err := client.GetObject(context.Background(), sealed.Manifest.Key, int64(sealed.Manifest.SizeBytes))
	if err != nil {
		t.Fatalf("fetch the sealed manifest: %v", err)
	}
	manifest, err := archive.Decode(payload)
	if err != nil {
		t.Fatalf("decode the sealed manifest: %v", err)
	}
	return manifest
}

func checkSealDescribesTheManifest(t *testing.T, sealed archiver.Sealed, manifest *archive.Manifest, entries int) {
	t.Helper()
	switch {
	case sealed.RootDigest != archive.RootDigestHex(manifest):
		t.Fatal("the sealed root digest does not describe the sealed manifest")
	case sealed.ChunkSizeBytes != lifecycleChunkSize || manifest.Header.ChunkSizeBytes != lifecycleChunkSize:
		t.Fatalf("the archive was built at chunk size %d/%d, want %d",
			sealed.ChunkSizeBytes, manifest.Header.ChunkSizeBytes, lifecycleChunkSize)
	case sealed.SealedEpoch != lifecycleEpoch || manifest.Header.SealedEpoch != lifecycleEpoch:
		t.Fatal("the archive does not name the sealing epoch")
	case sealed.LogicalBytes != manifest.Header.LogicalBytes,
		sealed.LogicalInodes != manifest.Header.LogicalInodes,
		sealed.SealedAllocatedBytes != manifest.Header.SealedAllocatedBytes,
		sealed.SealedInodes != manifest.Header.SealedInodes:
		t.Fatal("the seal's totals disagree with the manifest they claim to describe")
	case len(sealed.Packs) != len(manifest.Header.Packs) || len(sealed.Packs) == 0:
		t.Fatalf("the seal names %d pack objects, the manifest has %d", len(sealed.Packs), len(manifest.Header.Packs))
	case len(manifest.Entries) != entries:
		t.Fatalf("the manifest carries %d entries, the source tree had %d", len(manifest.Entries), entries)
	}
}

// checkArchiveShape proves the archive actually exercises what this test claims:
// a multi-chunk file, a chunk lying wholly inside a hole, a partially sparse
// chunk, small files sharing one frame, and a hardlink group.
func checkArchiveShape(t *testing.T, manifest *archive.Manifest) {
	t.Helper()
	var multiChunk, wholeHole, partial, group bool
	frameUsers := map[uint32]map[int]struct{}{}
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		if entry.HardlinkGroup != 0 {
			group = true
		}
		if entry.Type != archive.TypeRegular {
			continue
		}
		if len(entry.Chunks) > 1 {
			multiChunk = true
		}
		for position, chunk := range entry.Chunks {
			span := uint64(manifest.Header.ChunkSizeBytes)
			if remaining := entry.Size - uint64(position)*span; remaining < span {
				span = remaining
			}
			if !chunk.Stored() {
				wholeHole = true
				continue
			}
			if chunk.Length < span {
				partial = true
			}
			if frameUsers[chunk.FrameIndex] == nil {
				frameUsers[chunk.FrameIndex] = map[int]struct{}{}
			}
			frameUsers[chunk.FrameIndex][index] = struct{}{}
		}
	}
	shared := false
	for _, users := range frameUsers {
		if len(users) > 1 {
			shared = true
		}
	}
	switch {
	case !multiChunk:
		t.Fatal("the archived tree has no multi-chunk file")
	case !wholeHole:
		t.Fatal("the archived tree has no chunk lying wholly inside a hole")
	case !partial:
		t.Fatal("the archived tree has no partially sparse chunk")
	case !shared:
		t.Fatal("the archived tree has no small files sharing a frame")
	case !group:
		t.Fatal("the archived tree has no hardlink group")
	}
}

// verifyLikeTheManager runs the Manager's own independent verification: it
// trusts nothing the cell reported, refetches the manifest, re-derives every
// object key from the identities inside it, and cross-checks the observation.
// The observation is produced the way the helper produces it — by re-marshalling
// the seal — rather than by hand-translating fields here.
func verifyLikeTheManager(t *testing.T, client *archivestore.Client, sealed archiver.Sealed) {
	t.Helper()
	payload, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("encode the seal: %v", err)
	}
	var observation controlplane.ArchiveSealedObservation
	if err := json.Unmarshal(payload, &observation); err != nil {
		t.Fatalf("the seal does not decode as an ArchiveSealedObservation: %v", err)
	}
	record := controlplane.ArchiveRecord{
		FormatVersion: observation.FormatVersion, ChunkSizeBytes: observation.ChunkSizeBytes,
		Attempt: observation.Attempt, SealedEpoch: sealed.SealedEpoch, SealedUnix: sealed.WrittenUnix,
		Manifest: observation.Manifest, Packs: observation.Packs, RootDigest: observation.RootDigest,
		LogicalBytes: observation.LogicalBytes, LogicalInodes: observation.LogicalInodes,
		SealedAllocatedBytes: observation.SealedAllocatedBytes, SealedInodes: observation.SealedInodes,
		KeyVersion: observation.KeyVersion,
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("the Manager would refuse this seal outright: %v", err)
	}
	verifier, err := archiveverify.New(client)
	if err != nil {
		t.Fatalf("build the archive verifier: %v", err)
	}
	if err := verifier.Verify(record); err != nil {
		t.Fatalf("the Manager's independent verification refused an archive the archiver sealed "+
			"and the hydrator restored successfully: %v\n"+
			"The seal names its pack objects %q; verification derives its own key for the same pack. "+
			"A disagreement here is a control-plane defect, not a defect in this archive: "+
			"verification gates DESTROY, so no archived volume could ever be reclaimed.",
			err, sealed.Packs[0].Key)
	}
}

// ---------------------------------------------------------------------------
// The convergence record and the progress record.
// ---------------------------------------------------------------------------

type convergedRecord struct {
	Version        uint32 `json:"version"`
	VolumeID       string `json:"volume_id"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	Attempt        string `json:"attempt"`
	DrainedBytes   uint64 `json:"drained_bytes"`
	DrainedChunks  uint64 `json:"drained_chunks"`
	WrittenUnix    int64  `json:"written_unix"`
}

type progressRecord struct {
	Version          uint32 `json:"version"`
	ProgressPermille uint32 `json:"progress_permille"`
	State            string `json:"state"`
	RecalledBytes    uint64 `json:"recalled_bytes"`
	DrainedBytes     uint64 `json:"drained_bytes"`
	UpdatedUnix      int64  `json:"updated_unix"`
}

func checkConvergedRecord(t *testing.T, stateDir string) {
	t.Helper()
	var record convergedRecord
	readJSONFile(t, filepath.Join(stateDir, restoremode.ConvergedFilename), &record)
	switch {
	case record.Version != 1:
		t.Fatalf("the convergence record is version %d", record.Version)
	case record.VolumeID != lifecycleVolumeID:
		t.Fatalf("the convergence record names volume %s", record.VolumeID)
	case record.AuthorityEpoch != lifecycleAuthorityEpoch:
		t.Fatalf("the convergence record names authority epoch %d, want %d", record.AuthorityEpoch, lifecycleAuthorityEpoch)
	case record.Attempt != lifecycleAttempt:
		t.Fatalf("the convergence record names attempt %s", record.Attempt)
	case record.DrainedChunks == 0:
		t.Fatal("the convergence record claims no drained chunks")
	case record.WrittenUnix <= 0:
		t.Fatal("the convergence record has no write time")
	}
}

func readProgress(stateDir string) (progressRecord, error) {
	payload, err := os.ReadFile(filepath.Join(stateDir, restoremode.ProgressFilename))
	if err != nil {
		return progressRecord{}, err
	}
	var record progressRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return progressRecord{}, err
	}
	return record, nil
}

// ---------------------------------------------------------------------------
// Restricted modes.
// ---------------------------------------------------------------------------

// checkRestrictedModes is the proof that an archive round-trips inodes whose
// modes deny the identity that owns them. Two capabilities are separated here,
// and the separation is the point:
//
//   - The archiver reads a file its owner may not read. That is the one place
//     in the cell that is granted CAP_DAC_READ_SEARCH, and reaching this stage
//     at all means it worked: an archiver without it cannot open sealed.bin,
//     and every stage downstream of ArchiveAndVerify would have failed first.
//   - The restore serves those modes with no capability whatsoever. The
//     hydrator materializes each inode at its exact archived mode, and the
//     authority hydrates the bytes through descriptors its binding walk opened
//     before it began serving - which is why a 0444 file can be filled in by a
//     process that could not open it for writing now.
//
// The reads below are cold on purpose: each one has to fetch from the archive
// and land in an inode whose mode forbids the write. The proof that it did is
// the placement's own block accounting - the restore materialized every regular
// file fully sparse, so a non-zero allocated block count afterwards is a
// hydration write that reached this inode and nothing else. Mode and archived
// mtime must both be exactly as they were.
func checkRestrictedModes(t *testing.T, live *serving, targetRoot string, tree *sourceTree,
	namespace map[string]nodeFacts, manifest *archive.Manifest) {
	t.Helper()
	for _, restricted := range []struct {
		path string
		mode os.FileMode
	}{
		{pathReadOnly, 0o444},
		{pathSealed, 0o000},
		{pathClosedDir, os.ModeDir | 0o444},
	} {
		entry, ok := manifestEntryByName(t, manifest, restricted.path)
		if !ok {
			t.Fatalf("the archive carries no entry named %q", restricted.path)
		}
		if got := manifest.Entries[entry].Mode; got != uint32(restricted.mode.Perm()) {
			t.Fatalf("the archive records %q at mode %#o, not the %#o it was archived from",
				restricted.path, got, uint32(restricted.mode.Perm()))
		}
		info, err := os.Lstat(live.join(restricted.path))
		if err != nil {
			t.Fatalf("stat the restored %q: %v", restricted.path, err)
		}
		if info.Mode() != restricted.mode {
			t.Fatalf("the restored %q is mode %v, not the %v the archive records", restricted.path, info.Mode(), restricted.mode)
		}
		if info.IsDir() {
			continue
		}
		if blocks := namespace[restricted.path].blocks; blocks != 0 {
			t.Fatalf("the restored %q already held %d allocated blocks, so a cold read proves nothing", restricted.path, blocks)
		}

		got := mustReadFile(t, live.join(restricted.path), "cold read of "+restricted.path)
		if string(got) != string(tree.bytes[restricted.path]) {
			t.Fatalf("the cold read of %q returned %s, not the archived bytes", restricted.path, describeBytes(got))
		}
		if blocks := describeNode(t, filepath.Join(targetRoot, restricted.path)).blocks; blocks == 0 {
			t.Fatalf("%q still holds no allocated block, so the bytes it served were not hydrated into it", restricted.path)
		}
		after, err := os.Lstat(live.join(restricted.path))
		if err != nil {
			t.Fatalf("stat %q after hydration: %v", restricted.path, err)
		}
		if after.Mode() != restricted.mode {
			t.Fatalf("hydrating %q moved its mode to %v; the archive records %v", restricted.path, after.Mode(), restricted.mode)
		}
		if got, want := after.ModTime().UnixNano(), tree.facts[restricted.path].mtimeNS; got != want {
			t.Fatalf("hydrating %q moved its mtime to %d; the archive records %d", restricted.path, got, want)
		}
	}
}

// manifestEntryByName finds the entry index of a top-level name.
func manifestEntryByName(t *testing.T, manifest *archive.Manifest, name string) (uint32, bool) {
	t.Helper()
	for index := range manifest.Entries {
		components, err := manifest.Path(uint32(index))
		if err != nil {
			t.Fatalf("path of entry %d: %v", index, err)
		}
		parts := make([]string, len(components))
		for at, component := range components {
			parts[at] = string(component)
		}
		if strings.Join(parts, "/") == name {
			return uint32(index), true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// The namespace-only comparison.
// ---------------------------------------------------------------------------

// compareNamespace is the instant-namespace assertion: every name, kind, mode,
// nanosecond mtime, logical size, symlink target, user.* attribute and hardlink
// relation matches the archived tree, and every regular file with a logical size
// still holds zero allocated blocks — the content is in the archive, not here.
func compareNamespace(t *testing.T, want, got map[string]nodeFacts, when string) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s: the restored namespace has %d entries, the archive has %d", when, len(got), len(want))
	}
	for path, source := range want {
		target, present := got[path]
		if !present {
			t.Fatalf("%s: %q is missing from the restored namespace", when, path)
		}
		switch {
		case source.kind != target.kind:
			t.Fatalf("%s: %q is a %s in the archive and a %s restored", when, path, source.kind, target.kind)
		case source.mode != target.mode:
			t.Fatalf("%s: %q has mode %v in the archive and %v restored", when, path, source.mode, target.mode)
		case source.mtimeNS != target.mtimeNS:
			t.Fatalf("%s: %q has mtime %d in the archive and %d restored", when, path, source.mtimeNS, target.mtimeNS)
		case source.size != target.size:
			t.Fatalf("%s: %q is %d bytes in the archive and %d restored", when, path, source.size, target.size)
		case source.target != target.target:
			t.Fatalf("%s: %q points at %q in the archive and %q restored", when, path, source.target, target.target)
		case source.xattrs != target.xattrs:
			t.Fatalf("%s: %q carries %q in the archive and %q restored", when, path, source.xattrs, target.xattrs)
		}
		if target.kind == "reg" && target.size > 0 && target.blocks != 0 {
			t.Fatalf("%s: %q was materialized with %d allocated blocks; a restored file holds no content yet",
				when, path, target.blocks)
		}
	}
	if wantGroups, gotGroups := hardlinkGroups(want), hardlinkGroups(got); !equalGroups(wantGroups, gotGroups) {
		t.Fatalf("%s: hardlink relations differ: archive %v, restored %v", when, wantGroups, gotGroups)
	}
}

// ---------------------------------------------------------------------------
// JSON helpers for the pinned launch configurations and state records.
// ---------------------------------------------------------------------------

func writeJSONFile(t *testing.T, directory, name string, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode %s: %v", name, err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(payload, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}
