package restoremode_test

// Cross-package interoperability: the REAL hydrator (vcs/internal/hydrator,
// which owns the serve-mode server, the pinned wire codecs, and the restore
// path that writes the PFSRBND1 bindings file) against the REAL authority-side
// client (vcs/internal/restoremode). Both suites were written against a fake of
// the other side; nothing until now proved the two agree byte for byte.
//
// One test, one archive, three surfaces:
//
//   - The restore-bindings file and the ready marker are produced by the
//     hydrator's own restore path and consumed by restoremode's loader. No byte
//     of either file is hand-rolled here; that is the point.
//   - The AF_UNIX protocol is spoken end to end: INFO, the paged drain order,
//     FETCH, CHUNK, and ERR{corrupt}, with no fake on either side.
//   - The materialized namespace converges to the source bytes, and the holes
//     the archive recorded are never written into.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
	"github.com/steerlabs/portablefs/vcs/internal/hydrator"
	"github.com/steerlabs/portablefs/vcs/internal/restorefixture"
	"github.com/steerlabs/portablefs/vcs/internal/restoremode"
)

const (
	// interopChunkSize is deliberately far below the 8 MiB default so that a
	// 193 KiB file is genuinely multi-chunk and a hole can span whole chunks.
	// It is a power of two inside [archive.MinChunkSizeBytes,
	// hydrator.MaxChunkSizeBytes], which is what both sides bound it to.
	interopChunkSize = uint32(64 << 10)

	interopBucket  = "portablefs-archive"
	interopPrefix  = "archives"
	interopVolume  = "0f0e0d0c-0b0a-4908-8706-050403020100"
	interopCell    = "22222222-3333-4444-8555-666666666666"
	interopAttempt = "11111111-2222-4333-8444-555555555555"
	interopEpoch   = uint64(3)

	// Entry indices of the fixture tree, which is fixed and depth-first.
	entryRoot      = uint32(0)
	entryDataDir   = uint32(1)
	entryBig       = uint32(2)
	entryBigLink   = uint32(3)
	entrySparse    = uint32(4)
	entryNotes     = uint32(5)
	entryReadme    = uint32(6)
	entrySymlink   = uint32(7)
	interopEntries = 8
)

func TestInteropHydratorAndRestoreMode(t *testing.T) {
	t.Run("ConvergesAgainstTheRealHydrator", func(t *testing.T) {
		testInteropConvergence(t)
	})
	t.Run("SurfacesHydratorCorruptionAsErrCorrupt", func(t *testing.T) {
		testInteropCorruption(t)
	})
}

// ---------------------------------------------------------------------------
// The convergence path.
// ---------------------------------------------------------------------------

func testInteropConvergence(t *testing.T) {
	fixture := newInteropFixture(t)
	fixture.startServe(t)

	// The bindings file the hydrator wrote is readable by both implementations,
	// and they agree on every record. This is the file-format half of the
	// interop claim.
	fixture.checkBindingsAgree(t)

	store := newDiskStore(t, fixture)
	// Park the drain before the first recall so the recall below is provably a
	// cold demand fetch rather than a race with a drain worker that already
	// hydrated the chunk. A parked entry reports itself unlinked and
	// not-yet-discardable, which is exactly the state the drain loop is
	// contracted to back off on; it never fetches and never holds a chunk lock
	// across the wait.
	store.park(true)

	mode, err := restoremode.Open(context.Background(), restoremode.Config{
		StateRoot:        fixture.stateRoot,
		VolumeID:         interopVolume,
		AuthorityEpoch:   5,
		Store:            store,
		RecallDeadline:   10 * time.Second,
		RecallLimit:      8,
		PoolSize:         4,
		DrainWorkers:     2,
		DrainHysteresis:  20 * time.Millisecond,
		ProgressInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open restore mode against the real hydrator: %v", err)
	}
	t.Cleanup(func() { _ = mode.Close() })

	if got := mode.ChunkSize(); got != interopChunkSize {
		t.Fatalf("INFO chunk size crossed the wire as %d, want %d", got, interopChunkSize)
	}
	if got := mode.Bindings().Len(); got != interopEntries {
		t.Fatalf("bindings cover %d entries, the manifest has %d", got, interopEntries)
	}

	// A hardlink group is one inode: both names resolve to the entry that
	// materialized it, which is also the only entry the hydrator's drain order
	// names. The two packages have to agree on that or the group is drained
	// twice or not at all.
	bigIdentity, ok := mode.Bindings().Identity(entryBig)
	if !ok {
		t.Fatal("the bindings carry no identity for the multi-chunk file")
	}
	linkIdentity, ok := mode.Bindings().Identity(entryBigLink)
	if !ok {
		t.Fatal("the bindings carry no identity for the hardlink alias")
	}
	if bigIdentity != linkIdentity {
		t.Fatal("the hardlink group's two names were bound to different inode identities")
	}
	if entry, ok := mode.Entry(bigIdentity); !ok || entry != entryBig {
		t.Fatalf("the hardlink identity resolved to entry %d (%v), want the materializing entry %d",
			entry, ok, entryBig)
	}

	// A cold demand recall: one real FETCH, one real ranged GET, real CHUNK
	// extents applied to the materialized inode.
	before := fixture.store.rangeGets()
	if err := mode.EnsureHydrated(context.Background(), bigIdentity, 0, 4096); err != nil {
		t.Fatalf("cold recall through the real pair: %v", err)
	}
	if after := fixture.store.rangeGets(); after <= before {
		t.Fatalf("the recall served %d ranged GETs, so no chunk crossed the wire", after-before)
	}
	recallSpan := uint64(interopChunkSize)
	fixture.compareRange(t, entryBig, 0, recallSpan, "after the cold recall")

	// Let the drain run to convergence against the same server.
	store.park(false)
	waitFor(t, 10*time.Second, "the restore to converge", func() bool {
		if mode.Active() {
			return false
		}
		active, err := restoremode.Active(fixture.stateRoot)
		return err == nil && !active
	})

	// Every file, byte for byte, against the source model.
	for _, file := range fixture.files {
		fixture.compareRange(t, file.entry, 0, uint64(len(file.logical)),
			"after convergence")
	}

	// Holes stayed holes: the only bytes the authority ever wrote are exactly
	// the extents the manifest records as stored, so a chunk that lies wholly
	// inside a hole was never fetched and never written.
	store.checkWritesMatchExtents(t, fixture.manifest)

	// The convergence record and the progress file.
	var converged struct {
		Version        uint32 `json:"version"`
		VolumeID       string `json:"volume_id"`
		AuthorityEpoch uint64 `json:"authority_epoch"`
		Attempt        string `json:"attempt"`
		DrainedBytes   uint64 `json:"drained_bytes"`
		DrainedChunks  uint64 `json:"drained_chunks"`
		WrittenUnix    int64  `json:"written_unix"`
	}
	readJSON(t, filepath.Join(fixture.stateRoot, restoremode.ConvergedFilename), &converged)
	if converged.Version != 1 || converged.VolumeID != interopVolume || converged.Attempt != interopAttempt {
		t.Fatalf("the convergence record does not describe this attempt: %+v", converged)
	}
	if want := fixture.storedChunkCount(); converged.DrainedChunks != want {
		t.Fatalf("the convergence record names %d drained chunks, the hydrator's drain order has %d",
			converged.DrainedChunks, want)
	}

	waitFor(t, 5*time.Second, "the progress file to report full hydration", func() bool {
		progress, err := readProgress(fixture.stateRoot)
		return err == nil && progress.ProgressPermille == 1000
	})
	progress, err := readProgress(fixture.stateRoot)
	if err != nil {
		t.Fatalf("read the progress file: %v", err)
	}
	if progress.Version != 1 || progress.ProgressPermille != 1000 || progress.State != "" {
		t.Fatalf("progress = %+v, want version 1, 1000 permille, healthy", progress)
	}
}

// ---------------------------------------------------------------------------
// The corruption path.
// ---------------------------------------------------------------------------

func testInteropCorruption(t *testing.T) {
	fixture := newInteropFixture(t)

	// Damage the pack inside the exact frame the recalled chunk is served from,
	// before the server exists, so nothing it holds was decoded beforehand. The
	// hydrator must classify this corrupt rather than blocked, and restoremode
	// must map that class onto ErrCorrupt.
	chunk := fixture.manifest.Entries[entryBig].Chunks[0]
	if !chunk.Stored() {
		t.Fatal("the fixture's first chunk stores nothing, so it cannot be damaged")
	}
	frame := fixture.manifest.Frames[chunk.FrameIndex]
	fixture.store.flip(t, fixture.packKeys[frame.PackIndex], frame.PackOffset+frame.CompressedLength/2)

	fixture.startServe(t)

	store := newDiskStore(t, fixture)
	// The drain would hit the same damage; parking it keeps the assertion about
	// the demand-recall path exactly.
	store.park(true)

	mode, err := restoremode.Open(context.Background(), restoremode.Config{
		StateRoot:        fixture.stateRoot,
		VolumeID:         interopVolume,
		AuthorityEpoch:   5,
		Store:            store,
		RecallDeadline:   10 * time.Second,
		RecallLimit:      8,
		PoolSize:         4,
		DrainWorkers:     2,
		DrainHysteresis:  20 * time.Millisecond,
		ProgressInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open restore mode: %v", err)
	}
	t.Cleanup(func() { _ = mode.Close() })

	identity, ok := mode.Bindings().Identity(entryBig)
	if !ok {
		t.Fatal("the bindings carry no identity for the damaged file")
	}
	err = mode.EnsureHydrated(context.Background(), identity, 0, 4096)
	if !errors.Is(err, restoremode.ErrCorrupt) {
		t.Fatalf("a damaged pack surfaced as %v, want restoremode.ErrCorrupt", err)
	}
	if err := mode.ContentError(); !errors.Is(err, restoremode.ErrCorrupt) {
		t.Fatalf("the corrupt classification did not stick: %v", err)
	}
	if store.writtenBytes(entryBig) != 0 {
		t.Fatal("a corrupt chunk was written into the restored inode")
	}
}

// ---------------------------------------------------------------------------
// The fixture: one archive, one fake store, one materialized namespace.
// ---------------------------------------------------------------------------

type interopFile struct {
	entry   uint32
	logical []byte
	extents []archive.Extent
}

type interopFixture struct {
	store    *fakeS3
	client   *archivestore.Client
	manifest *archive.Manifest
	packKeys []string

	volumeRoot string
	stateRoot  string

	files []interopFile
	paths map[uint32]string
}

func newInteropFixture(t *testing.T) *interopFixture {
	t.Helper()
	files := interopSourceFiles()
	manifest, packs := buildInteropArchive(t, files)
	checkFixtureShape(t, manifest)

	store := &fakeS3{objects: map[string][]byte{}}
	server := httptest.NewServer(store)
	t.Cleanup(server.Close)
	client, err := archivestore.New(archivestore.Config{
		Endpoint: server.URL, Region: "us-east-1", Bucket: interopBucket, KeyPrefix: interopPrefix,
		AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret", PathStyle: true,
		ChecksumCapability: archivestore.ChecksumCRC64NVMEFullObject, MaxAttempts: 1,
	})
	if err != nil {
		t.Fatalf("archive-store client: %v", err)
	}

	encoded, err := archive.Encode(manifest)
	if err != nil {
		t.Fatalf("encode the manifest: %v", err)
	}
	manifestKey, err := client.KeyFor(interopVolume, interopEpoch, interopAttempt, hydrator.ManifestObjectName)
	if err != nil {
		t.Fatal(err)
	}
	store.put(manifestKey, encoded)
	packKeys := make([]string, len(manifest.Header.Packs))
	for index := range manifest.Header.Packs {
		key, err := client.KeyFor(interopVolume, interopEpoch, interopAttempt, hydrator.PackObjectName(index))
		if err != nil {
			t.Fatal(err)
		}
		packKeys[index] = key
		store.put(key, packs[index])
	}

	fixture := &interopFixture{
		store:      store,
		client:     client,
		manifest:   manifest,
		packKeys:   packKeys,
		volumeRoot: restorefixture.Root(t),
		// The state directory holds the AF_UNIX socket, which is capped at
		// about a hundred bytes; a test temporary directory is often longer
		// than that on its own.
		stateRoot: shortDir(t, "pfs-interop-state-"),
		files:     files,
		paths:     map[uint32]string{},
	}

	digest := sha256.Sum256(encoded)
	launch := hydrator.LaunchConfig{
		Version:           hydrator.LaunchConfigVersion,
		VolumeID:          interopVolume,
		CellID:            interopCell,
		SealedEpoch:       interopEpoch,
		Attempt:           interopAttempt,
		Mode:              hydrator.ModeRestoreNamespace,
		ManifestSHA256:    hex.EncodeToString(digest[:]),
		ManifestSizeBytes: uint64(len(encoded)),
		ManifestCRC64NVME: archivestore.CRC64Hex(archivestore.ChecksumCRC64NVME(encoded)),
		ChunkSizeBytes:    interopChunkSize,
	}

	// The bindings table and the ready marker are produced here, by the
	// hydrator's own restore path, against the manifest it downloaded from the
	// fake store. Hand-rolling either file would defeat the purpose of the test.
	if err := hydrator.Run(context.Background(), hydrator.Options{
		LaunchConfigPath: writeLaunchConfig(t, launch),
		VolumeRoot:       fixture.volumeRoot,
		StateDir:         fixture.stateRoot,
		Client:           client,
		Logf:             t.Logf,
	}); err != nil {
		t.Fatalf("restore the namespace: %v", err)
	}

	for index := range manifest.Entries {
		components, err := manifest.Path(uint32(index))
		if err != nil {
			t.Fatalf("path of entry %d: %v", index, err)
		}
		parts := make([]string, len(components))
		for at, component := range components {
			parts[at] = string(component)
		}
		fixture.paths[uint32(index)] = filepath.Join(fixture.volumeRoot, filepath.Join(parts...))
	}
	return fixture
}

// startServe runs the real serve-mode hydrator on the state directory's pinned
// socket, which is exactly where restoremode's client dials.
func (f *interopFixture) startServe(t *testing.T) {
	t.Helper()
	launch := hydrator.LaunchConfig{
		Version:           hydrator.LaunchConfigVersion,
		VolumeID:          interopVolume,
		CellID:            interopCell,
		SealedEpoch:       interopEpoch,
		Attempt:           interopAttempt,
		Mode:              hydrator.ModeServe,
		ManifestSHA256:    f.manifestDigestHex(t),
		ManifestSizeBytes: f.manifestSize(t),
		ManifestCRC64NVME: f.manifestChecksumHex(t),
		ChunkSizeBytes:    interopChunkSize,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var exited atomic.Bool
	go func() {
		err := hydrator.Run(ctx, hydrator.Options{
			LaunchConfigPath: writeLaunchConfig(t, launch),
			StateDir:         f.stateRoot,
			Client:           f.client,
			Logf:             t.Logf,
		})
		exited.Store(true)
		done <- err
	}()
	t.Cleanup(func() {
		cancel()
		if exited.Load() {
			return
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve returned %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("serve did not stop when its context was cancelled")
		}
	})
	socket := filepath.Join(f.stateRoot, hydrator.SocketName)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the hydrator never created its socket")
		}
		select {
		case err := <-done:
			t.Fatalf("serve exited before it listened: %v", err)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (f *interopFixture) manifestBytes(t *testing.T) []byte {
	t.Helper()
	key, err := f.client.KeyFor(interopVolume, interopEpoch, interopAttempt, hydrator.ManifestObjectName)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := f.store.get(key)
	if !ok {
		t.Fatal("the manifest is not in the fake store")
	}
	return payload
}

func (f *interopFixture) manifestDigestHex(t *testing.T) string {
	digest := sha256.Sum256(f.manifestBytes(t))
	return hex.EncodeToString(digest[:])
}

func (f *interopFixture) manifestSize(t *testing.T) uint64 {
	return uint64(len(f.manifestBytes(t)))
}

func (f *interopFixture) manifestChecksumHex(t *testing.T) string {
	return archivestore.CRC64Hex(archivestore.ChecksumCRC64NVME(f.manifestBytes(t)))
}

// checkBindingsAgree decodes the hydrator-written table with both packages'
// readers and proves they see the same records.
func (f *interopFixture) checkBindingsAgree(t *testing.T) {
	t.Helper()
	path := filepath.Join(f.stateRoot, hydrator.BindingsName)
	if hydrator.BindingsName != restoremode.BindingsFilename {
		t.Fatalf("the two packages name the bindings file differently: %q and %q",
			hydrator.BindingsName, restoremode.BindingsFilename)
	}
	if hydrator.ReadyName != restoremode.ReadyFilename || hydrator.SocketName != restoremode.HydratorSocket {
		t.Fatal("the two packages disagree on the pinned state-directory names")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the bindings: %v", err)
	}
	authoritative, err := hydrator.DecodeBindings(payload)
	if err != nil {
		t.Fatalf("the hydrator cannot decode the table it wrote: %v", err)
	}
	loaded, err := restoremode.LoadBindings(path, 1<<20)
	if err != nil {
		t.Fatalf("restoremode cannot load the hydrator's bindings table: %v", err)
	}
	if loaded.Len() != len(authoritative) {
		t.Fatalf("restoremode read %d bindings, the hydrator wrote %d", loaded.Len(), len(authoritative))
	}
	for _, binding := range authoritative {
		identity, ok := loaded.Identity(binding.EntryIndex)
		if !ok || identity != binding.Identity {
			t.Fatalf("entry %d: restoremode read identity %x, the hydrator wrote %x",
				binding.EntryIndex, identity, binding.Identity)
		}
	}
	if digest := loaded.Digest(); digest != sha256.Sum256(payload[:len(payload)-sha256.Size]) {
		t.Fatal("restoremode's bindings digest is not the seal the hydrator computed")
	}
}

func (f *interopFixture) storedChunkCount() uint64 {
	total := uint64(0)
	groups := map[uint32]bool{}
	for index := range f.manifest.Entries {
		entry := &f.manifest.Entries[index]
		if entry.Type != archive.TypeRegular {
			continue
		}
		if entry.HardlinkGroup != 0 {
			if groups[entry.HardlinkGroup] {
				continue
			}
			groups[entry.HardlinkGroup] = true
		}
		for _, chunk := range entry.Chunks {
			if chunk.Stored() {
				total++
			}
		}
	}
	return total
}

func (f *interopFixture) logicalOf(entry uint32) []byte {
	for _, file := range f.files {
		if file.entry == entry {
			return file.logical
		}
	}
	return nil
}

func (f *interopFixture) compareRange(t *testing.T, entry uint32, offset, length uint64, when string) {
	t.Helper()
	want := f.logicalOf(entry)
	if want == nil {
		t.Fatalf("entry %d is not a modelled regular file", entry)
	}
	handle, err := os.Open(f.paths[entry])
	if err != nil {
		t.Fatalf("open the restored entry %d: %v", entry, err)
	}
	defer func() { _ = handle.Close() }()
	got := make([]byte, length)
	if _, err := handle.ReadAt(got, int64(offset)); err != nil {
		t.Fatalf("read the restored entry %d: %v", entry, err)
	}
	if !bytes.Equal(got, want[offset:offset+length]) {
		t.Fatalf("entry %d bytes [%d,%d) differ from the source %s", entry, offset, offset+length, when)
	}
}

// ---------------------------------------------------------------------------
// The source tree and the archive.
// ---------------------------------------------------------------------------

func interopSourceFiles() []interopFile {
	chunk := uint64(interopChunkSize)

	// A multi-chunk file: four chunks, the last one partial, fully allocated.
	bigSize := 3*chunk + 1234
	big := interopFile{entry: entryBig, logical: pseudoRandom(bigSize, 0x51ed270b),
		extents: []archive.Extent{{Offset: 0, Length: bigSize}}}

	// A sparse file whose middle two chunks lie wholly inside one hole, so the
	// archive stores nothing for them and the restored file must keep them as
	// the holes truncate created.
	sparseSize := 4 * chunk
	sparse := interopFile{entry: entrySparse, logical: make([]byte, sparseSize),
		extents: []archive.Extent{{Offset: 0, Length: 4096}, {Offset: 3 * chunk, Length: 8192}}}
	copy(sparse.logical[0:4096], pseudoRandom(4096, 0x2545f491))
	copy(sparse.logical[3*chunk:3*chunk+8192], pseudoRandom(8192, 0x9e3779b9))

	// Two small files under one parent with one extension: the builder groups
	// them into a single shared frame, so one fetched frame answers both.
	notes := interopFile{entry: entryNotes, logical: pseudoRandom(137, 0x1234567)}
	notes.extents = []archive.Extent{{Offset: 0, Length: 137}}
	readme := interopFile{entry: entryReadme, logical: pseudoRandom(211, 0x7654321)}
	readme.extents = []archive.Extent{{Offset: 0, Length: 211}}

	// The hardlink alias shares the multi-chunk file's inode and its bytes.
	link := interopFile{entry: entryBigLink, logical: big.logical, extents: big.extents}

	return []interopFile{big, link, sparse, notes, readme}
}

func buildInteropArchive(t *testing.T, files []interopFile) (*archive.Manifest, [][]byte) {
	t.Helper()
	byEntry := map[uint32]interopFile{}
	for _, file := range files {
		byEntry[file.entry] = file
	}
	open := func(entry uint32) func() (archive.SourceFile, error) {
		file := byEntry[entry]
		return func() (archive.SourceFile, error) {
			return &archive.MemoryFile{Logical: file.logical, Data: file.extents}, nil
		}
	}
	base := int64(1_700_000_000) * int64(time.Second)
	entries := []archive.SourceEntry{
		{ParentIndex: entryRoot, Name: nil, Type: archive.TypeDirectory, Mode: 0o755, MTimeNanos: base + 11},
		{ParentIndex: entryRoot, Name: []byte("data"), Type: archive.TypeDirectory, Mode: 0o750, MTimeNanos: base + 22},
		{ParentIndex: entryDataDir, Name: []byte("big.bin"), Type: archive.TypeRegular,
			Size: uint64(len(byEntry[entryBig].logical)), Mode: 0o640, MTimeNanos: base + 33,
			Nlink: 2, InodeKey: 11, Open: open(entryBig)},
		{ParentIndex: entryDataDir, Name: []byte("big-link.bin"), Type: archive.TypeRegular,
			Size: uint64(len(byEntry[entryBigLink].logical)), Mode: 0o640, MTimeNanos: base + 33,
			Nlink: 2, InodeKey: 11, Open: open(entryBigLink)},
		{ParentIndex: entryDataDir, Name: []byte("sparse.bin"), Type: archive.TypeRegular,
			Size: uint64(len(byEntry[entrySparse].logical)), Mode: 0o600, MTimeNanos: base + 44,
			Nlink: 1, InodeKey: 12, Open: open(entrySparse)},
		{ParentIndex: entryRoot, Name: []byte("notes.txt"), Type: archive.TypeRegular,
			Size: uint64(len(byEntry[entryNotes].logical)), Mode: 0o644, MTimeNanos: base + 55,
			Nlink: 1, InodeKey: 13, Open: open(entryNotes)},
		{ParentIndex: entryRoot, Name: []byte("readme.txt"), Type: archive.TypeRegular,
			Size: uint64(len(byEntry[entryReadme].logical)), Mode: 0o644, MTimeNanos: base + 66,
			Nlink: 1, InodeKey: 14, Open: open(entryReadme)},
		{ParentIndex: entryRoot, Name: []byte("notes-link"), Type: archive.TypeSymlink,
			Size: uint64(len("notes.txt")), Mode: 0o777, MTimeNanos: base + 77,
			LinkName: []byte("notes.txt"), Nlink: 1},
	}
	if len(entries) != interopEntries {
		t.Fatalf("the fixture tree has %d entries, the indices name %d", len(entries), interopEntries)
	}

	config := archive.DefaultBuilderConfig()
	config.ChunkSizeBytes = interopChunkSize
	config.VolumeID = rawInteropUUID(t, interopVolume)
	config.SealedEpoch = interopEpoch
	config.Attempt = rawInteropUUID(t, interopAttempt)

	sink := &memorySink{}
	manifest, err := archive.Build(config, archive.NewSliceSource(entries), sink)
	if err != nil {
		t.Fatalf("build the archive: %v", err)
	}
	return manifest, sink.packs
}

// checkFixtureShape proves the archive actually exercises what the test claims:
// a multi-chunk file, a chunk that lies wholly inside a hole, a partially
// sparse chunk, a shared small-file frame, and a hardlink group.
func checkFixtureShape(t *testing.T, manifest *archive.Manifest) {
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
		t.Fatal("the fixture has no multi-chunk file")
	case !wholeHole:
		t.Fatal("the fixture has no chunk lying wholly inside a hole")
	case !partial:
		t.Fatal("the fixture has no partially sparse chunk")
	case !shared:
		t.Fatal("the fixture has no small files sharing a frame")
	case !group:
		t.Fatal("the fixture has no hardlink group")
	}
}

// pseudoRandom is SplitMix64 rather than math/rand: a fixture must reproduce
// the identical bytes on any toolchain.
func pseudoRandom(size uint64, seed uint64) []byte {
	out := make([]byte, size)
	state := seed
	for index := range out {
		state += 0x9e3779b97f4a7c15
		z := state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		out[index] = byte(z ^ (z >> 31))
	}
	return out
}

type memorySink struct{ packs [][]byte }

type packBuffer struct {
	owner *memorySink
	index uint32
	buf   bytes.Buffer
}

func (p *packBuffer) Write(payload []byte) (int, error) { return p.buf.Write(payload) }

func (p *packBuffer) Close() error {
	p.owner.packs[p.index] = append([]byte(nil), p.buf.Bytes()...)
	return nil
}

func (s *memorySink) OpenPack(index uint32) (io.WriteCloser, error) {
	if int(index) != len(s.packs) {
		return nil, fmt.Errorf("packs opened out of order: got %d, have %d", index, len(s.packs))
	}
	s.packs = append(s.packs, nil)
	return &packBuffer{owner: s, index: index}, nil
}

// ---------------------------------------------------------------------------
// The fake object store. Unauthenticated by design: signature verification is
// archivestore's own concern and its suite proves it independently. Ranged GET
// is real here, because that is how the hydrator reads a frame.
// ---------------------------------------------------------------------------

type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	ranges  int
}

func (s *fakeS3) put(key string, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = payload
}

func (s *fakeS3) get(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, ok := s.objects[key]
	return payload, ok
}

func (s *fakeS3) rangeGets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ranges
}

func (s *fakeS3) flip(t *testing.T, key string, at uint64) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, ok := s.objects[key]
	if !ok || at >= uint64(len(payload)) {
		t.Fatalf("cannot damage byte %d of %q", at, key)
	}
	damaged := append([]byte(nil), payload...)
	damaged[at] ^= 0xff
	s.objects[key] = damaged
}

func (s *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/"+interopBucket+"/")
	payload, ok := s.get(key)
	switch r.Method {
	case http.MethodGet:
		if !ok {
			http.Error(w, "<Error><Code>NoSuchKey</Code><Message>absent</Message></Error>", http.StatusNotFound)
			return
		}
		if header := r.Header.Get("Range"); header != "" {
			first, last, err := parseByteRange(header, len(payload))
			if err != nil {
				http.Error(w, "<Error><Code>InvalidRange</Code></Error>", http.StatusRequestedRangeNotSatisfiable)
				return
			}
			s.mu.Lock()
			s.ranges++
			s.mu.Unlock()
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, len(payload)))
			w.Header().Set("Content-Length", strconv.Itoa(last-first+1))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(payload[first : last+1])
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case http.MethodHead:
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("x-amz-checksum-crc64nvme", archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(payload)))
		w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func parseByteRange(header string, size int) (int, int, error) {
	span, ok := strings.CutPrefix(strings.TrimSpace(header), "bytes=")
	if !ok {
		return 0, 0, fmt.Errorf("range %q is not a bytes range", header)
	}
	firstText, lastText, ok := strings.Cut(span, "-")
	if !ok {
		return 0, 0, fmt.Errorf("range %q has no span", header)
	}
	first, firstErr := strconv.Atoi(firstText)
	last, lastErr := strconv.Atoi(lastText)
	if firstErr != nil || lastErr != nil || first < 0 || last < first || last >= size {
		return 0, 0, fmt.Errorf("range %q is outside a %d byte object", header, size)
	}
	return first, last, nil
}

// ---------------------------------------------------------------------------
// The authority-side Store, over the namespace the hydrator materialized.
// ---------------------------------------------------------------------------

type writeRange struct {
	offset int64
	length int
}

type diskStore struct {
	paths  map[uint32]string
	mtimes map[uint32]int64

	mu     sync.Mutex
	files  map[uint32]*os.File
	writes map[uint32][]writeRange
	parked bool
}

func newDiskStore(t *testing.T, fixture *interopFixture) *diskStore {
	t.Helper()
	store := &diskStore{
		paths:  map[uint32]string{},
		mtimes: map[uint32]int64{},
		files:  map[uint32]*os.File{},
		writes: map[uint32][]writeRange{},
	}
	for index := range fixture.manifest.Entries {
		entry := &fixture.manifest.Entries[index]
		if entry.Type != archive.TypeRegular {
			continue
		}
		store.paths[uint32(index)] = fixture.paths[uint32(index)]
		store.mtimes[uint32(index)] = entry.MTimeNanos
	}
	t.Cleanup(func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		for _, file := range store.files {
			_ = file.Close()
		}
	})
	return store
}

// park makes every entry report itself unlinked and not yet discardable, which
// is the one state the drain loop backs off on without fetching or holding a
// chunk lock. It is the test's pacing lever, never a correctness claim.
func (s *diskStore) park(parked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parked = parked
}

func (s *diskStore) handle(entry uint32) (*os.File, error) {
	if file, ok := s.files[entry]; ok {
		return file, nil
	}
	path, ok := s.paths[entry]
	if !ok {
		return nil, fmt.Errorf("entry %d is not a restored regular file", entry)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	s.files[entry] = file
	return file, nil
}

func (s *diskStore) LogicalSize(entry uint32) (int64, error) {
	path, ok := s.paths[entry]
	if !ok {
		return 0, fmt.Errorf("entry %d is not a restored regular file", entry)
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (s *diskStore) PWrite(entry uint32, offset int64, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := s.handle(entry)
	if err != nil {
		return err
	}
	if _, err := file.WriteAt(data, offset); err != nil {
		return err
	}
	s.writes[entry] = append(s.writes[entry], writeRange{offset: offset, length: len(data)})
	return nil
}

func (s *diskStore) Fdatasync(entry uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := s.handle(entry)
	if err != nil {
		return err
	}
	return file.Sync()
}

func (s *diskStore) RestoreMtime(entry uint32) error {
	s.mu.Lock()
	path, ok := s.paths[entry]
	nanos := s.mtimes[entry]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("entry %d is not a restored regular file", entry)
	}
	when := time.Unix(0, nanos)
	return os.Chtimes(path, when, when)
}

func (s *diskStore) Linked(entry uint32) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.paths[entry]; !ok {
		return false, fmt.Errorf("entry %d is not a restored regular file", entry)
	}
	return !s.parked, nil
}

func (s *diskStore) DiscardUnlinked(uint32) (bool, error) { return false, nil }

func (s *diskStore) writtenBytes(entry uint32) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, write := range s.writes[entry] {
		total += write.length
	}
	return total
}

// checkWritesMatchExtents proves the authority wrote exactly the byte ranges
// the manifest records as stored — no more, which is what "holes stay holes"
// means once the restorer has created every file fully sparse.
func (s *diskStore) checkWritesMatchExtents(t *testing.T, manifest *archive.Manifest) {
	t.Helper()
	chunkSize := uint64(manifest.Header.ChunkSizeBytes)
	for entry := range s.paths {
		expected := map[writeRange]bool{}
		for position, chunk := range manifest.Entries[entry].Chunks {
			for _, extent := range chunk.Extents {
				expected[writeRange{
					offset: int64(uint64(position)*chunkSize + extent.Offset),
					length: int(extent.Length),
				}] = false
			}
		}
		s.mu.Lock()
		observed := append([]writeRange(nil), s.writes[entry]...)
		s.mu.Unlock()
		for _, write := range observed {
			if _, ok := expected[write]; !ok {
				t.Fatalf("entry %d was written at [%d,%d), which the manifest does not record as stored",
					entry, write.offset, write.offset+int64(write.length))
			}
			expected[write] = true
		}
		if manifest.Entries[entry].HardlinkGroup != 0 && len(observed) == 0 {
			// A hardlink alias is drained under the entry that materialized the
			// inode, so the alias itself is legitimately never written.
			continue
		}
		var missing []writeRange
		for write, seen := range expected {
			if !seen {
				missing = append(missing, write)
			}
		}
		if len(missing) != 0 {
			sort.Slice(missing, func(i, j int) bool { return missing[i].offset < missing[j].offset })
			t.Fatalf("entry %d never received %d stored extents, first at offset %d",
				entry, len(missing), missing[0].offset)
		}
	}
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

type interopProgress struct {
	Version          uint32 `json:"version"`
	ProgressPermille uint32 `json:"progress_permille"`
	State            string `json:"state"`
	RecalledBytes    uint64 `json:"recalled_bytes"`
	DrainedBytes     uint64 `json:"drained_bytes"`
	UpdatedUnix      int64  `json:"updated_unix"`
}

func readProgress(stateRoot string) (interopProgress, error) {
	payload, err := os.ReadFile(filepath.Join(stateRoot, restoremode.ProgressFilename))
	if err != nil {
		return interopProgress{}, err
	}
	var progress interopProgress
	if err := json.Unmarshal(payload, &progress); err != nil {
		return interopProgress{}, err
	}
	return progress, nil
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(payload, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func waitFor(t *testing.T, within time.Duration, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if ready() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func writeLaunchConfig(t *testing.T, config hydrator.LaunchConfig) string {
	t.Helper()
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("encode the hydrator configuration: %v", err)
	}
	path := filepath.Join(t.TempDir(), hydrator.LaunchConfigName)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write the hydrator configuration: %v", err)
	}
	return path
}

func shortDir(t *testing.T, prefix string) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", prefix)
	if err != nil {
		t.Fatalf("create a short directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("restrict the short directory: %v", err)
	}
	return directory
}

func rawInteropUUID(t *testing.T, value string) [16]byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(decoded) != 16 {
		t.Fatalf("uuid %q", value)
	}
	var raw [16]byte
	copy(raw[:], decoded)
	return raw
}
