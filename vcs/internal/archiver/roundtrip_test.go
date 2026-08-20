package archiver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/hydrator"
)

// The round trip of the whole tier below the authority: archive a real tree,
// restore its namespace into an empty one, compare everything the contract says
// must survive, then serve every chunk over the pinned socket protocol and
// prove the bytes are the source's, exactly.
//
// It lives in the archiver's suite because that is where the store fake and the
// tree builder are; it drives the hydrator package as an ordinary consumer.

func TestArchiveRestoreServeRoundTrip(t *testing.T) {
	tree := buildSourceTree(t)
	options, _, sealed := runArchiver(t, tree)

	restored := t.TempDir()
	stateDir := t.TempDir()
	restoreOptions := hydrator.Options{
		LaunchConfigPath: writeHydratorConfig(t, t.TempDir(), hydratorConfig(sealed, hydrator.ModeRestoreNamespace)),
		VolumeRoot:       restored,
		StateDir:         stateDir,
		Client:           options.Client,
		Now:              func() time.Time { return time.Unix(1_700_000_200, 0) },
		Logf:             t.Logf,
	}
	if err := hydrator.Run(context.Background(), restoreOptions); err != nil {
		t.Fatalf("restore the namespace: %v", err)
	}

	compareTrees(t, tree, restored)
	manifest := loadManifestFromStore(t, options, sealed)
	checkBindings(t, stateDir, manifest, restored)
	checkReady(t, stateDir, manifest)

	// Idempotency: the helper may restart the unit. The marker describes this
	// attempt, so the second run succeeds without touching the tree — which it
	// could not restore again anyway, since it is no longer empty.
	if err := hydrator.Run(context.Background(), restoreOptions); err != nil {
		t.Fatalf("a second restore with the marker present failed: %v", err)
	}

	// Serve mode: fetch every chunk of every file and rebuild the content.
	socket := startServer(t, options, sealed)
	client := dialHydrator(t, socket)
	defer client.close()

	info := client.info(t)
	if info.EntryCount != uint32(len(manifest.Entries)) || info.ChunkSizeBytes != testChunkSize {
		t.Fatalf("INFO describes %d entries at %d bytes per chunk, want %d at %d",
			info.EntryCount, info.ChunkSizeBytes, len(manifest.Entries), testChunkSize)
	}
	if info.SealedEpoch != testEpoch {
		t.Fatalf("INFO names epoch %d", info.SealedEpoch)
	}
	drain := client.drainOrder(t, info)
	if uint64(len(drain)) != info.DrainCount {
		t.Fatalf("the drain order paged %d of %d pairs", len(drain), info.DrainCount)
	}
	if info.PriorityDrainCount > info.DrainCount {
		t.Fatalf("the priority region claims %d of %d pairs", info.PriorityDrainCount, info.DrainCount)
	}
	checkDrainCoversContent(t, manifest, drain)

	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		if entry.Type != archive.TypeRegular {
			continue
		}
		content := client.readFile(t, manifest, uint32(index))
		path := entryPath(t, manifest, uint32(index))
		want, err := os.ReadFile(filepath.Join(tree.root, path))
		if err != nil {
			t.Fatalf("read the source file %q: %v", path, err)
		}
		if !bytes.Equal(content, want) {
			t.Fatalf("the served content of %q is %d bytes and does not match the %d byte source",
				path, len(content), len(want))
		}
	}

	// A protocol fault is answered and does not take the connection's framing
	// with it, and an oversized frame is refused outright.
	kind, payload := client.request(t, hydrator.TypeFetch, []byte{1, 2, 3})
	if kind != hydrator.TypeErr {
		t.Fatalf("a malformed FETCH was answered with %s", kind)
	}
	if class, _, err := hydrator.DecodeError(payload); err != nil || class != hydrator.ErrorInvalid {
		t.Fatalf("a malformed FETCH was not classified invalid: %v %v", class, err)
	}
	kind, payload = client.request(t, hydrator.MessageType(200), nil)
	if kind != hydrator.TypeErr {
		t.Fatalf("an unknown message type was answered with %s", kind)
	}
	if class, _, err := hydrator.DecodeError(payload); err != nil || class != hydrator.ErrorInvalid {
		t.Fatalf("an unknown message type was not classified invalid: %v %v", class, err)
	}
	kind, _ = client.request(t, hydrator.TypeHealth, nil)
	if kind != hydrator.TypeHealthOK {
		t.Fatalf("HEALTH answered %s against a reachable store", kind)
	}
}

func TestServeReportsCorruptionRatherThanServingIt(t *testing.T) {
	tree := buildSourceTree(t)
	options, store, sealed := runArchiver(t, tree)
	manifest := loadManifestFromStore(t, options, sealed)

	// A pack that lost integrity after it was sealed, damaged inside the exact
	// frame the chunk below is served from. The server is started afterwards so
	// nothing it holds was decoded before the damage.
	entry, chunk := firstStoredChunk(t, manifest)
	frame := manifest.Frames[manifest.Entries[entry].Chunks[chunk].FrameIndex]
	if !store.flip(sealed.Packs[frame.PackIndex].Key, frame.PackOffset+frame.CompressedLength/2) {
		t.Fatal("the pack could not be damaged")
	}
	socket := startServer(t, options, sealed)
	client := dialHydrator(t, socket)
	defer client.close()

	kind, payload := client.request(t, hydrator.TypeFetch, hydrator.EncodeFetch(entry, chunk))
	if kind != hydrator.TypeErr {
		t.Fatalf("a corrupt chunk was answered with %s", kind)
	}
	class, message, err := hydrator.DecodeError(payload)
	if err != nil {
		t.Fatalf("decode the error: %v", err)
	}
	if class != hydrator.ErrorCorrupt {
		t.Fatalf("a corrupt chunk was classified %s: %s", class, message)
	}
}

func TestServeReportsAnUnreachableStoreAsBlocked(t *testing.T) {
	tree := buildSourceTree(t)
	options, store, sealed := runArchiver(t, tree)
	manifest := loadManifestFromStore(t, options, sealed)

	socket := startServer(t, options, sealed)
	client := dialHydrator(t, socket)
	defer client.close()

	// The object vanishes: the store is reachable but cannot answer, which is
	// the blocked class, not the corrupt one. Restore-blocked is volume-wide
	// and auto-clearing; corruption is a data-integrity event, and confusing
	// the two would turn an outage into a false integrity alarm.
	for _, pack := range sealed.Packs {
		store.forget(pack.Key)
	}
	entry, chunk := firstStoredChunk(t, manifest)
	kind, payload := client.request(t, hydrator.TypeFetch, hydrator.EncodeFetch(entry, chunk))
	if kind != hydrator.TypeErr {
		t.Fatalf("a missing pack was answered with %s", kind)
	}
	class, message, err := hydrator.DecodeError(payload)
	if err != nil {
		t.Fatalf("decode the error: %v", err)
	}
	if class != hydrator.ErrorBlocked {
		t.Fatalf("a missing pack was classified %s: %s", class, message)
	}
}

func TestRestoreRefusesANonEmptyTree(t *testing.T) {
	tree := buildSourceTree(t)
	options, _, sealed := runArchiver(t, tree)
	restored := t.TempDir()
	if err := os.WriteFile(filepath.Join(restored, "left-over"), []byte("someone else's data"), 0o600); err != nil {
		t.Fatalf("seed the tree: %v", err)
	}
	err := hydrator.Run(context.Background(), hydrator.Options{
		LaunchConfigPath: writeHydratorConfig(t, t.TempDir(), hydratorConfig(sealed, hydrator.ModeRestoreNamespace)),
		VolumeRoot:       restored,
		StateDir:         t.TempDir(),
		Client:           options.Client,
		Logf:             t.Logf,
	})
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("a non-empty tree was restored into: %v", err)
	}
}

func TestRestoreRefusesAManifestThatDoesNotMatchItsConfiguration(t *testing.T) {
	tree := buildSourceTree(t)
	options, _, sealed := runArchiver(t, tree)
	config := hydratorConfig(sealed, hydrator.ModeRestoreNamespace)
	config.ManifestSHA256 = strings.Repeat("0", 64)
	err := hydrator.Run(context.Background(), hydrator.Options{
		LaunchConfigPath: writeHydratorConfig(t, t.TempDir(), config),
		VolumeRoot:       t.TempDir(),
		StateDir:         t.TempDir(),
		Client:           options.Client,
		Logf:             t.Logf,
	})
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("a manifest whose digest was not the pinned one was accepted: %v", err)
	}
}

// hydratorConfig builds the pinned launch configuration from a seal, which is
// exactly what the helper does with the record the archiver wrote.
func hydratorConfig(sealed Sealed, mode string) hydrator.LaunchConfig {
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

func writeHydratorConfig(t *testing.T, directory string, config hydrator.LaunchConfig) string {
	t.Helper()
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("encode the hydrator configuration: %v", err)
	}
	path := filepath.Join(directory, hydrator.LaunchConfigName)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write the hydrator configuration: %v", err)
	}
	return path
}

func loadManifestFromStore(t *testing.T, options Options, sealed Sealed) *archive.Manifest {
	t.Helper()
	manifest, err := hydrator.LoadManifest(context.Background(), options.Client, hydratorConfig(sealed, hydrator.ModeServe))
	if err != nil {
		t.Fatalf("load the sealed manifest: %v", err)
	}
	return manifest
}

// startServer runs serve mode until the test ends and returns its socket.
//
// The socket lives in a deliberately short directory: an AF_UNIX path is capped
// at about a hundred bytes, and a test temporary directory is often longer than
// that on its own.
func startServer(t *testing.T, options Options, sealed Sealed) string {
	t.Helper()
	stateDir := t.TempDir()
	socket := filepath.Join(shortSocketDir(t), hydrator.SocketName)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var exited atomic.Bool
	go func() {
		err := hydrator.Run(ctx, hydrator.Options{
			LaunchConfigPath: writeHydratorConfig(t, t.TempDir(), hydratorConfig(sealed, hydrator.ModeServe)),
			StateDir:         stateDir,
			SocketPath:       socket,
			Client:           options.Client,
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
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			return socket
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

func shortSocketDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "pfs-hydrator-")
	if err != nil {
		t.Fatalf("create a socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("restrict the socket directory: %v", err)
	}
	return directory
}

// hydratorClient speaks the pinned protocol the way the authority will: one
// request in flight, replies in order, every frame length-prefixed.
type hydratorClient struct {
	connection net.Conn
	chunkSize  uint64
}

// dialHydrator connects, retrying briefly: the socket file appears when the
// listener binds, which is a moment before it accepts, so a connect that lands
// in that window is refused and means "not yet", not "never".
func dialHydrator(t *testing.T, socket string) *hydratorClient {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		connection, err := net.Dial("unix", socket)
		if err == nil {
			return &hydratorClient{connection: connection, chunkSize: testChunkSize}
		}
		if time.Now().After(deadline) {
			t.Fatalf("connect to the hydrator: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (c *hydratorClient) close() { _ = c.connection.Close() }

func (c *hydratorClient) request(t *testing.T, kind hydrator.MessageType, payload []byte) (hydrator.MessageType, []byte) {
	t.Helper()
	if err := hydrator.WriteFrame(c.connection, kind, payload); err != nil {
		t.Fatalf("write a %s frame: %v", kind, err)
	}
	replyKind, reply, err := hydrator.ReadFrame(c.connection)
	if err != nil {
		t.Fatalf("read the reply to %s: %v", kind, err)
	}
	return replyKind, reply
}

func (c *hydratorClient) info(t *testing.T) hydrator.Info {
	t.Helper()
	kind, payload := c.request(t, hydrator.TypeInfo, nil)
	if kind != hydrator.TypeInfoOK {
		t.Fatalf("INFO answered %s", kind)
	}
	info, err := hydrator.DecodeInfo(payload)
	if err != nil {
		t.Fatalf("decode INFO_OK: %v", err)
	}
	return info
}

func (c *hydratorClient) drainOrder(t *testing.T, info hydrator.Info) []hydrator.DrainPair {
	t.Helper()
	var pairs []hydrator.DrainPair
	for cursor := uint64(0); ; {
		kind, payload := c.request(t, hydrator.TypeInfoNext, hydrator.EncodeCursor(cursor))
		if kind != hydrator.TypeDrainPage {
			t.Fatalf("INFO_NEXT answered %s", kind)
		}
		page, err := hydrator.DecodeDrainPage(payload)
		if err != nil {
			t.Fatalf("decode a drain page: %v", err)
		}
		if page.Cursor != cursor {
			t.Fatalf("a drain page starts at %d, requested %d", page.Cursor, cursor)
		}
		pairs = append(pairs, page.Pairs...)
		cursor += uint64(len(page.Pairs))
		if !page.More {
			break
		}
		if len(page.Pairs) == 0 {
			t.Fatal("a drain page promised more and carried nothing")
		}
	}
	_ = info
	return pairs
}

// readFile rebuilds one file's logical content out of chunk fetches, exactly as
// the authority's drain does: place each extent's bytes at its offset inside the
// chunk, and leave everything else as the hole it already is.
func (c *hydratorClient) readFile(t *testing.T, manifest *archive.Manifest, entryIndex uint32) []byte {
	t.Helper()
	entry := &manifest.Entries[entryIndex]
	content := make([]byte, 0, entry.Size)
	for chunkIndex := range entry.Chunks {
		kind, payload := c.request(t, hydrator.TypeFetch, hydrator.EncodeFetch(entryIndex, uint32(chunkIndex)))
		if kind != hydrator.TypeChunk {
			class, message, _ := hydrator.DecodeError(payload)
			t.Fatalf("fetching entry %d chunk %d answered %s (%s: %s)", entryIndex, chunkIndex, kind, class, message)
		}
		chunk, err := hydrator.DecodeChunk(payload, c.chunkSize)
		if err != nil {
			t.Fatalf("decode a chunk reply: %v", err)
		}
		span := c.chunkSize
		if remaining := entry.Size - uint64(chunkIndex)*c.chunkSize; remaining < span {
			span = remaining
		}
		logical := make([]byte, span)
		at := uint64(0)
		for _, extent := range chunk.Extents {
			copy(logical[extent.Offset:extent.Offset+extent.Length], chunk.Data[at:at+extent.Length])
			at += extent.Length
		}
		content = append(content, logical...)
	}
	return content
}

func entryPath(t *testing.T, manifest *archive.Manifest, index uint32) string {
	t.Helper()
	components, err := manifest.Path(index)
	if err != nil {
		t.Fatalf("path of entry %d: %v", index, err)
	}
	parts := make([]string, len(components))
	for at, component := range components {
		parts[at] = string(component)
	}
	return strings.Join(parts, "/")
}

func firstStoredChunk(t *testing.T, manifest *archive.Manifest) (uint32, uint32) {
	t.Helper()
	for index := range manifest.Entries {
		for chunkIndex, chunk := range manifest.Entries[index].Chunks {
			if chunk.Stored() {
				return uint32(index), uint32(chunkIndex)
			}
		}
	}
	t.Fatal("the archive stores no chunk at all")
	return 0, 0
}

// checkDrainCoversContent proves the drain order names every stored chunk of
// every distinct inode exactly once, and nothing else.
func checkDrainCoversContent(t *testing.T, manifest *archive.Manifest, drain []hydrator.DrainPair) {
	t.Helper()
	wanted := map[hydrator.DrainPair]bool{}
	groups := map[uint32]bool{}
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		if entry.Type != archive.TypeRegular {
			continue
		}
		if entry.HardlinkGroup != 0 {
			if groups[entry.HardlinkGroup] {
				continue
			}
			groups[entry.HardlinkGroup] = true
		}
		for chunkIndex, chunk := range entry.Chunks {
			if chunk.Stored() {
				wanted[hydrator.DrainPair{EntryIndex: uint32(index), ChunkIndex: uint32(chunkIndex)}] = true
			}
		}
	}
	if len(drain) != len(wanted) {
		t.Fatalf("the drain order has %d pairs for %d stored chunks", len(drain), len(wanted))
	}
	for _, pair := range drain {
		if !wanted[pair] {
			t.Fatalf("the drain order names entry %d chunk %d, which is not a stored chunk of a distinct inode",
				pair.EntryIndex, pair.ChunkIndex)
		}
		delete(wanted, pair)
	}
	if len(wanted) != 0 {
		t.Fatalf("%d stored chunks are missing from the drain order", len(wanted))
	}
}

func checkBindings(t *testing.T, stateDir string, manifest *archive.Manifest, restored string) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(stateDir, hydrator.BindingsName))
	if err != nil {
		t.Fatalf("read the bindings: %v", err)
	}
	bindings, err := hydrator.DecodeBindings(payload)
	if err != nil {
		t.Fatalf("decode the bindings: %v", err)
	}
	if len(bindings) != len(manifest.Entries) {
		t.Fatalf("the bindings cover %d of %d entries", len(bindings), len(manifest.Entries))
	}
	byIndex := map[uint32][16]byte{}
	for index, binding := range bindings {
		if binding.EntryIndex != uint32(index) {
			t.Fatalf("binding %d names entry %d", index, binding.EntryIndex)
		}
		byIndex[binding.EntryIndex] = binding.Identity
	}
	// A hardlink group is one inode, so its members share one identity, and
	// two unrelated files never do.
	groups := map[uint32][]uint32{}
	for index := range manifest.Entries {
		if group := manifest.Entries[index].HardlinkGroup; group != 0 {
			groups[group] = append(groups[group], uint32(index))
		}
	}
	if len(groups) == 0 {
		t.Fatal("the tree lost its hardlink group before the bindings were written")
	}
	for group, members := range groups {
		first := byIndex[members[0]]
		for _, member := range members[1:] {
			if byIndex[member] != first {
				t.Fatalf("hardlink group %d has members with different inode identities", group)
			}
		}
	}
	distinct := map[[16]byte]uint32{}
	for index := range manifest.Entries {
		identity := byIndex[uint32(index)]
		if previous, seen := distinct[identity]; seen {
			if manifest.Entries[index].HardlinkGroup == 0 ||
				manifest.Entries[index].HardlinkGroup != manifest.Entries[previous].HardlinkGroup {
				t.Fatalf("entries %d and %d share an inode identity without sharing a hardlink group", previous, index)
			}
			continue
		}
		distinct[identity] = uint32(index)
	}
	// The identities describe the tree that was actually created.
	if _, err := os.Stat(restored); err != nil {
		t.Fatalf("the restored tree is not there: %v", err)
	}
}

func checkReady(t *testing.T, stateDir string, manifest *archive.Manifest) {
	t.Helper()
	ready, err := hydrator.ReadReady(filepath.Join(stateDir, hydrator.ReadyName))
	if err != nil {
		t.Fatalf("read the ready marker: %v", err)
	}
	if ready.Entries != uint64(len(manifest.Entries)) {
		t.Fatalf("the marker reports %d of %d entries", ready.Entries, len(manifest.Entries))
	}
	if ready.VolumeID != testVolumeID || ready.Attempt != testAttempt || ready.SealedEpoch != testEpoch {
		t.Fatal("the marker does not describe this attempt")
	}
}

// compareTrees is the full-tree comparison the format contract calls for:
// names, kinds, modes including set-ID and sticky, nanosecond mtimes, sizes,
// symlink targets, extended attributes, and hardlink relations. Content is
// deliberately not compared here — a restored file is fully sparse until the
// authority hydrates it, which the sparseness assertion below proves.
func compareTrees(t *testing.T, tree treeFacts, restored string) {
	t.Helper()
	source := walkTreeFacts(t, tree.root)
	target := walkTreeFacts(t, restored)
	if len(source) != len(target) {
		t.Fatalf("the restored tree has %d entries, the source has %d", len(target), len(source))
	}
	paths := make([]string, 0, len(source))
	for path := range source {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		want, got := source[path], target[path]
		if !got.present {
			t.Fatalf("%q is missing from the restored tree", path)
		}
		switch {
		case want.kind != got.kind:
			t.Fatalf("%q is a %s in the source and a %s restored", path, want.kind, got.kind)
		case want.mode != got.mode:
			t.Fatalf("%q has mode %v in the source and %v restored", path, want.mode, got.mode)
		case want.mtime != got.mtime:
			t.Fatalf("%q has mtime %d in the source and %d restored", path, want.mtime, got.mtime)
		case want.target != got.target:
			t.Fatalf("%q points at %q in the source and %q restored", path, want.target, got.target)
		case want.size != got.size:
			t.Fatalf("%q is %d bytes in the source and %d restored", path, want.size, got.size)
		case want.xattrs != got.xattrs:
			t.Fatalf("%q carries %q in the source and %q restored", path, want.xattrs, got.xattrs)
		}
		if got.kind == "reg" && got.size > 0 && !got.sparse {
			t.Fatalf("%q was restored with %d allocated blocks; a restored file holds no content yet",
				path, got.blocks)
		}
	}
	if want, got := hardlinkGroups(source), hardlinkGroups(target); !equalGroups(want, got) {
		t.Fatalf("hardlink relations differ: source %v, restored %v", want, got)
	}
}

// hardlinkGroups collapses a tree's inode numbers into the sets of paths that
// share one. Inode numbers themselves are meaningless across a restore; what
// must survive is which names are the same file.
func hardlinkGroups(facts map[string]node) [][]string {
	byInode := map[uint64][]string{}
	for path, entry := range facts {
		if entry.kind != "reg" {
			continue
		}
		byInode[entry.inode] = append(byInode[entry.inode], path)
	}
	var groups [][]string
	for _, paths := range byInode {
		if len(paths) < 2 {
			continue
		}
		sort.Strings(paths)
		groups = append(groups, paths)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i][0] < groups[j][0] })
	return groups
}

func equalGroups(left, right [][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if fmt.Sprint(left[index]) != fmt.Sprint(right[index]) {
			return false
		}
	}
	return true
}
