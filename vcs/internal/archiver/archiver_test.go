package archiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"golang.org/x/sys/unix"
)

const (
	testVolumeID = "11111111-2222-4333-8444-555555555555"
	testCellID   = "99999999-8888-4777-8666-555555555555"
	testAttempt  = "abcdef01-2345-4678-8abc-def012345678"
	testEpoch    = uint64(7)
)

func testLaunchConfig() LaunchConfig {
	return LaunchConfig{
		Version:           LaunchConfigVersion,
		VolumeID:          testVolumeID,
		CellID:            testCellID,
		AuthorityEpoch:    testEpoch,
		PlacementSequence: 2,
		Attempt:           testAttempt,
		KeyVersion:        "default",
		ChunkSizeBytes:    testChunkSize,
	}
}

func writeLaunchConfig(t *testing.T, directory string, config LaunchConfig) string {
	t.Helper()
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("encode launch configuration: %v", err)
	}
	path := filepath.Join(directory, LaunchConfigName)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write launch configuration: %v", err)
	}
	return path
}

// runArchiver performs one archive against the fake store and returns the
// options it used, so a test can re-run the same phase.
func runArchiver(t *testing.T, tree treeFacts) (Options, *fakeStore, Sealed) {
	t.Helper()
	client, store := newTestStore(t)
	configDir := t.TempDir()
	resultDir := t.TempDir()
	options := Options{
		LaunchConfigPath: writeLaunchConfig(t, configDir, testLaunchConfig()),
		VolumeRoot:       tree.root,
		ResultDir:        resultDir,
		Client:           client,
		Now:              func() time.Time { return time.Unix(1_700_000_100, 0) },
		Logf:             t.Logf,
	}
	if err := Run(context.Background(), options); err != nil {
		t.Fatalf("archive: %v", err)
	}
	sealed, err := ReadSealed(sealedPath(resultDir))
	if err != nil {
		t.Fatalf("read seal: %v", err)
	}
	return options, store, sealed
}

func TestArchiveSealsVerifiedContent(t *testing.T) {
	tree := buildSourceTree(t)
	_, store, sealed := runArchiver(t, tree)

	wantManifestKey := fmt.Sprintf("%s/%s/%d-%s/manifest", testPrefix, testVolumeID, testEpoch, testAttempt)
	if sealed.Manifest.Key != wantManifestKey {
		t.Fatalf("manifest key = %q, want %q", sealed.Manifest.Key, wantManifestKey)
	}
	if len(sealed.Packs) == 0 {
		t.Fatal("the seal names no pack objects")
	}
	for index, pack := range sealed.Packs {
		want := fmt.Sprintf("%s/%s/%d-%s/pack-%06d", testPrefix, testVolumeID, testEpoch, testAttempt, index)
		if pack.Key != want {
			t.Fatalf("pack %d key = %q, want %q", index, pack.Key, want)
		}
		payload, ok := store.object(pack.Key)
		if !ok {
			t.Fatalf("pack %d is not in the store", index)
		}
		if uint64(len(payload)) != pack.SizeBytes || sha256Hex(payload) != pack.SHA256 {
			t.Fatalf("pack %d in the store does not match its sealed identity", index)
		}
	}

	payload, ok := store.object(sealed.Manifest.Key)
	if !ok {
		t.Fatal("the manifest is not in the store")
	}
	if sha256Hex(payload) != sealed.Manifest.SHA256 || uint64(len(payload)) != sealed.Manifest.SizeBytes {
		t.Fatal("the stored manifest does not match its sealed identity")
	}
	manifest, err := archive.Decode(payload)
	if err != nil {
		t.Fatalf("decode the sealed manifest: %v", err)
	}
	if archive.RootDigestHex(manifest) != sealed.RootDigest {
		t.Fatal("the sealed root digest does not describe the sealed manifest")
	}
	if manifest.Header.ChunkSizeBytes != testChunkSize || manifest.Header.SealedEpoch != testEpoch {
		t.Fatal("the manifest header does not describe this attempt")
	}
	if sealed.LogicalInodes != manifest.Header.LogicalInodes || sealed.LogicalBytes != manifest.Header.LogicalBytes {
		t.Fatal("the seal's logical totals do not match the manifest's")
	}
	if sealed.SealedInodes != uint64(len(manifest.Entries)) {
		t.Fatalf("sealed inodes = %d, entries = %d", sealed.SealedInodes, len(manifest.Entries))
	}

	// The tree's shapes survive into the manifest: a hardlink group of three,
	// a sparse file with a chunk that stores nothing, and a file spanning more
	// than one chunk.
	byName := map[string]*archive.Entry{}
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		byName[string(entry.Name)] = entry
	}
	if group := byName["linked-a"]; group == nil || group.HardlinkGroup == 0 || group.Nlink != 3 {
		t.Fatal("the hardlink group did not survive the walk")
	}
	if gamma := byName["gamma.bin"]; gamma == nil || len(gamma.Chunks) != 4 {
		t.Fatalf("a file of %d chunks was archived as %v chunks", 4, len(byName["gamma.bin"].Chunks))
	}
	if weird := byName[tree.weirdName]; weird == nil {
		t.Fatalf("the name %q did not survive the walk", tree.weirdName)
	}
	sparse := byName["sparse.bin"]
	holes := byName["holes.bin"]
	zeros := byName["zeros.bin"]
	if sparse == nil || holes == nil || zeros == nil {
		t.Fatal("the sparse cases are missing from the manifest")
	}
	if len(sparse.Chunks) != 4 || sparse.Size != 4*testChunkSize {
		t.Fatalf("the sparse file has %d chunks of %d bytes, want 4 of %d", len(sparse.Chunks), sparse.Size, 4*testChunkSize)
	}
	if holes.ContentDigest != zeros.ContentDigest {
		t.Fatal("a wholly sparse file and its allocated-zeros twin must share a content digest")
	}
	// Whether the host's scanner sees holes is a property of the filesystem,
	// not of the archiver: reporting a sparse file as fully allocated is always
	// correct and only ever more expensive. The must-not-deduplicate assertion
	// therefore applies exactly when the manifest actually shows one file
	// storing nothing and the other storing bytes.
	if unstoredChunks(holes) > 0 && unstoredChunks(zeros) == 0 {
		if holes.Chunks[0].SliceDigest == zeros.Chunks[0].SliceDigest {
			t.Fatal("a wholly sparse file and its allocated-zeros twin must not deduplicate")
		}
		if unstoredChunks(sparse) == 0 {
			t.Fatal("the hole-spanning chunk of the sparse file was stored")
		}
	}

	// Read-back fetched every pack range; the seal exists because it passed.
	if store.callCount("HeadObject") == 0 {
		t.Fatal("read-back never proved the pack objects")
	}
}

func unstoredChunks(entry *archive.Entry) int {
	count := 0
	for _, chunk := range entry.Chunks {
		if !chunk.Stored() {
			count++
		}
	}
	return count
}

func TestArchiveIsIdempotentForTheSameAttempt(t *testing.T) {
	tree := buildSourceTree(t)
	options, store, first := runArchiver(t, tree)
	before := store.callCount("CreateMultipartUpload") + store.callCount("PutObject")

	if err := Run(context.Background(), options); err != nil {
		t.Fatalf("second archive: %v", err)
	}
	after := store.callCount("CreateMultipartUpload") + store.callCount("PutObject")
	if after != before {
		t.Fatalf("a re-run with an existing seal uploaded again: %d write operations became %d", before, after)
	}
	second, err := ReadSealed(sealedPath(options.ResultDir))
	if err != nil {
		t.Fatalf("read seal: %v", err)
	}
	if second.RootDigest != first.RootDigest {
		t.Fatal("the re-run rewrote the seal")
	}
}

func TestArchiveRefusesAStaleResultRecord(t *testing.T) {
	tree := buildSourceTree(t)
	options, _, sealed := runArchiver(t, tree)
	sealed.Attempt = "00000000-0000-4000-8000-000000000000"
	if err := WriteSealed(sealedPath(options.ResultDir), sealed); err != nil {
		t.Fatalf("write a stale seal: %v", err)
	}
	err := Run(context.Background(), options)
	if err == nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("a seal from another attempt was accepted: %v", err)
	}
}

func TestArchiveRerunAfterACrashBeforeTheSealSucceeds(t *testing.T) {
	tree := buildSourceTree(t)
	options, store, first := runArchiver(t, tree)
	// Model a crash between the upload and the result record: the objects are
	// in the store, the seal is not on disk.
	if err := os.Remove(sealedPath(options.ResultDir)); err != nil {
		t.Fatalf("remove the seal: %v", err)
	}
	if err := Run(context.Background(), options); err != nil {
		t.Fatalf("re-run after a crash: %v", err)
	}
	second, err := ReadSealed(sealedPath(options.ResultDir))
	if err != nil {
		t.Fatalf("read seal: %v", err)
	}
	if second.RootDigest != first.RootDigest || second.Manifest.SHA256 != first.Manifest.SHA256 {
		t.Fatal("the re-run produced a different archive for the same tree")
	}
	if store.callCount("GetObject") == 0 {
		t.Fatal("the conditional-create conflict was resolved without reading the stored object")
	}
}

func TestArchiveRefusesAForeignManifestAtItsKey(t *testing.T) {
	tree := buildSourceTree(t)
	client, store := newTestStore(t)
	key := fmt.Sprintf("%s/%s/%d-%s/manifest", testPrefix, testVolumeID, testEpoch, testAttempt)
	store.put(key, []byte("not this attempt's manifest"))

	err := Run(context.Background(), Options{
		LaunchConfigPath: writeLaunchConfig(t, t.TempDir(), testLaunchConfig()),
		VolumeRoot:       tree.root,
		ResultDir:        t.TempDir(),
		Client:           client,
		Logf:             t.Logf,
	})
	if err == nil || !strings.Contains(err.Error(), "already holds a different object") {
		t.Fatalf("a foreign manifest at this attempt's key was accepted: %v", err)
	}
}

func TestArchiveFailsWhenReadBackIsCorrupt(t *testing.T) {
	tree := buildSourceTree(t)
	client, store := newTestStore(t)
	resultDir := t.TempDir()
	options := Options{
		LaunchConfigPath: writeLaunchConfig(t, t.TempDir(), testLaunchConfig()),
		VolumeRoot:       tree.root,
		ResultDir:        resultDir,
		Client:           client,
		Logf:             t.Logf,
	}
	// Corrupt every pack the moment it is read back: the store accepted the
	// write and then lost integrity, which is precisely what the read-back
	// pass exists to catch.
	store.corruptKey(fmt.Sprintf("%s/%s/%d-%s/pack-%06d", testPrefix, testVolumeID, testEpoch, testAttempt, 0))

	err := Run(context.Background(), options)
	if err == nil {
		t.Fatal("a corrupt pack was sealed")
	}
	if !strings.Contains(err.Error(), "read-back") {
		t.Fatalf("the failure did not name the read-back: %v", err)
	}
	if _, statErr := os.Stat(sealedPath(resultDir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("a failed archive wrote a result record")
	}
}

func TestArchiveRefusesAnUnsupportedInodeKind(t *testing.T) {
	tree := buildSourceTree(t)
	if err := unix.Mkfifo(filepath.Join(tree.root, "fifo"), 0o600); err != nil {
		t.Skipf("this host cannot create a FIFO: %v", err)
	}
	client, _ := newTestStore(t)
	err := Run(context.Background(), Options{
		LaunchConfigPath: writeLaunchConfig(t, t.TempDir(), testLaunchConfig()),
		VolumeRoot:       tree.root,
		ResultDir:        t.TempDir(),
		Client:           client,
		Logf:             t.Logf,
	})
	var unsupported *UnsupportedInodeError
	if !errors.As(err, &unsupported) {
		t.Fatalf("a FIFO in the tree did not fail the archive with a typed error: %v", err)
	}
	if unsupported.Path != "fifo" {
		t.Fatalf("the typed error names %q, not the offending path", unsupported.Path)
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatal("the typed error does not match the package's rejection sentinel")
	}
}

func TestLoadLaunchConfigIsStrict(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, LaunchConfigName)
	valid, err := json.Marshal(testLaunchConfig())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cases := map[string][]byte{
		"an unknown field":     []byte(strings.TrimSuffix(string(valid), "}") + `,"surprise":1}`),
		"a second document":    append(append([]byte(nil), valid...), valid...),
		"a truncated document": valid[:len(valid)/2],
		"a chunk size of 12 bytes": []byte(strings.Replace(string(valid),
			fmt.Sprintf(`"chunk_size_bytes":%d`, testChunkSize), `"chunk_size_bytes":12`, 1)),
		"an unknown version": []byte(strings.Replace(string(valid), `"version":1`, `"version":2`, 1)),
		"a zero epoch":       []byte(strings.Replace(string(valid), `"authority_epoch":7`, `"authority_epoch":0`, 1)),
	}
	for name, payload := range cases {
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if _, err := LoadLaunchConfig(path); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatalf("write the valid configuration: %v", err)
	}
	config, err := LoadLaunchConfig(path)
	if err != nil {
		t.Fatalf("the valid configuration was refused: %v", err)
	}
	if config != testLaunchConfig() {
		t.Fatal("the parsed configuration does not round-trip")
	}
}

// TestSealedRecordMatchesTheControlPlaneObservation pins the shared subset of
// archive-sealed.json against the type the helper forwards and the Manager
// verifies. The record deliberately carries four fields the observation does
// not; everything else must decode into it unchanged, so the helper's
// observation is a re-marshal rather than a translation.
func TestSealedRecordMatchesTheControlPlaneObservation(t *testing.T) {
	tree := buildSourceTree(t)
	_, _, sealed := runArchiver(t, tree)
	payload, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("encode the seal: %v", err)
	}
	var observation controlplane.ArchiveSealedObservation
	if err := json.Unmarshal(payload, &observation); err != nil {
		t.Fatalf("the seal does not decode as an ArchiveSealedObservation: %v", err)
	}
	switch {
	case observation.Attempt != sealed.Attempt,
		observation.RootDigest != sealed.RootDigest,
		observation.FormatVersion != sealed.FormatVersion,
		observation.ChunkSizeBytes != sealed.ChunkSizeBytes,
		observation.KeyVersion != sealed.KeyVersion,
		observation.LogicalBytes != sealed.LogicalBytes,
		observation.LogicalInodes != sealed.LogicalInodes,
		observation.SealedAllocatedBytes != sealed.SealedAllocatedBytes,
		observation.SealedInodes != sealed.SealedInodes,
		observation.Manifest.Key != sealed.Manifest.Key,
		observation.Manifest.SHA256 != sealed.Manifest.SHA256,
		observation.Manifest.CRC64NVME != sealed.Manifest.CRC64NVME,
		observation.Manifest.SizeBytes != sealed.Manifest.SizeBytes,
		len(observation.Packs) != len(sealed.Packs):
		t.Fatal("the shared subset of the seal does not survive into the observation")
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
		t.Fatalf("the Manager would refuse this seal: %v", err)
	}
}

// TestArchiveUploadsPacksAsWholeFrameParts drives the multipart path a real
// volume always takes and the small trees above never reach: a pack larger than
// one part.
//
// The assertion is the format's own rule — every multipart part contains whole
// frames (pack-format.md, "S3 mechanics") — proved by showing every part
// boundary is a frame boundary in the manifest. It also proves the uploader's
// memory story: parts are flushed at the configured size, so a large pack
// becomes many parts rather than one buffered object.
func TestArchiveUploadsPacksAsWholeFrameParts(t *testing.T) {
	root := t.TempDir()
	// Incompressible content, so the compressed pack is as large as the source
	// and the part size is actually reached.
	if err := os.WriteFile(filepath.Join(root, "large.bin"), randomish(20<<20), 0o644); err != nil {
		t.Fatalf("write the large file: %v", err)
	}
	client, store := newTestStore(t)
	config := testLaunchConfig()
	config.ChunkSizeBytes = 8 << 20
	resultDir := t.TempDir()
	options := Options{
		LaunchConfigPath: writeLaunchConfig(t, t.TempDir(), config),
		VolumeRoot:       root,
		ResultDir:        resultDir,
		PartSizeBytes:    archive.MinPartSizeBytes,
		Client:           client,
		Logf:             t.Logf,
	}
	if err := Run(context.Background(), options); err != nil {
		t.Fatalf("archive: %v", err)
	}
	sealed, err := ReadSealed(sealedPath(resultDir))
	if err != nil {
		t.Fatalf("read seal: %v", err)
	}
	if len(sealed.Packs) != 1 {
		t.Fatalf("the archive sharded into %d packs", len(sealed.Packs))
	}
	parts := store.parts(sealed.Packs[0].Key)
	if len(parts) < 2 {
		t.Fatalf("a %d byte pack uploaded in %d part(s) at a %d byte part size",
			sealed.Packs[0].SizeBytes, len(parts), archive.MinPartSizeBytes)
	}
	payload, ok := store.object(sealed.Manifest.Key)
	if !ok {
		t.Fatal("the manifest is not in the store")
	}
	manifest, err := archive.Decode(payload)
	if err != nil {
		t.Fatalf("decode the manifest: %v", err)
	}
	boundaries := map[uint64]bool{}
	for _, frame := range manifest.Frames {
		boundaries[frame.PackOffset] = true
		boundaries[frame.PackOffset+frame.CompressedLength] = true
	}
	at := uint64(0)
	for index, size := range parts {
		if index+1 < len(parts) && size < archive.MinPartSizeBytes {
			t.Fatalf("non-final part %d is %d bytes, below the %d byte minimum", index+1, size, archive.MinPartSizeBytes)
		}
		at += size
		if !boundaries[at] {
			t.Fatalf("part %d ends at %d, which is not a frame boundary", index+1, at)
		}
	}
	if at != sealed.Packs[0].SizeBytes {
		t.Fatalf("the parts sum to %d bytes for a %d byte pack", at, sealed.Packs[0].SizeBytes)
	}
}

// TestArchiveRefusesAnUnreadableFile pins the honest failure for a tree the
// service identity cannot fully read. The archiver holds no capability that
// overrides discretionary access — it reads one volume as exactly the identity
// that owns it — so a mode that denies the owner denies the archive, and the
// failure names the path rather than sealing a manifest that omits it.
func TestArchiveRefusesAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, where no mode denies a read")
	}
	tree := buildSourceTree(t)
	locked := filepath.Join(tree.root, "alpha.txt")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	client, _ := newTestStore(t)
	err := Run(context.Background(), Options{
		LaunchConfigPath: writeLaunchConfig(t, t.TempDir(), testLaunchConfig()),
		VolumeRoot:       tree.root,
		ResultDir:        t.TempDir(),
		Client:           client,
		Logf:             t.Logf,
	})
	var unreadable *UnreadableInodeError
	if !errors.As(err, &unreadable) {
		t.Fatalf("an unreadable file did not fail the archive with a typed error: %v", err)
	}
	if unreadable.Path != "alpha.txt" || unreadable.Mode != 0 {
		t.Fatalf("the typed error names %q mode %#o", unreadable.Path, unreadable.Mode)
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatal("the typed error does not match the package's rejection sentinel")
	}
}
