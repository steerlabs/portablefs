// writeamp is a measurement spike, not a filesystem prototype. It compares
// durable bytes written by the existing PFT2 editor with bbolt transactions
// for the same deterministic logical mutations.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	bolt "go.etcd.io/bbolt"
)

const (
	sparseFileBytes = uint64(1 << 30)
	createBytes     = 128
	boltVersion     = "v1.5.0"
)

var (
	workloads = []string{"random-4k", "sequential-append", "small-creates", "rename", "chmod", "mkdir", "mixed"}
	fsBucket  = []byte("fs")
)

type config struct {
	sizes  []int
	ops    int
	reps   int
	out    string
	keep   bool
	work   string
	seed   uint64
	pretty bool
}

type result struct {
	Engine         string
	EngineVersion  string
	TreeFiles      int
	InodeDepth     int
	DirectoryDepth int
	Workload       string
	Rep            int
	Operations     int
	LogicalBytes   uint64
	FormatBytes    int64
	PathWriteBytes int64
	KernelBytes    uint64
	Duration       time.Duration
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fatal(err)
	}
	if err := run(cfg); err != nil {
		fatal(err)
	}
}

func parseFlags() (config, error) {
	var sizes string
	var cfg config
	flag.StringVar(&sizes, "sizes", "128,4096,65536,524288", "comma-separated baseline file counts")
	flag.IntVar(&cfg.ops, "ops", 32, "operations per non-mixed workload")
	flag.IntVar(&cfg.reps, "reps", 3, "repetitions per point")
	flag.StringVar(&cfg.out, "out", "results.csv", "raw CSV output")
	flag.StringVar(&cfg.work, "work", "", "working directory (default: temporary directory)")
	flag.BoolVar(&cfg.keep, "keep", false, "keep database and log files")
	flag.Uint64Var(&cfg.seed, "seed", 0x50465432, "deterministic workload seed")
	flag.BoolVar(&cfg.pretty, "print", true, "print each measurement")
	flag.Parse()
	if cfg.ops <= 0 || cfg.reps <= 0 {
		return config{}, fmt.Errorf("ops and reps must be positive")
	}
	for _, raw := range strings.Split(sizes, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || n < 2 {
			return config{}, fmt.Errorf("invalid size %q (each size must be at least 2)", raw)
		}
		cfg.sizes = append(cfg.sizes, n)
	}
	sort.Ints(cfg.sizes)
	return cfg, nil
}

func run(cfg config) error {
	workDir := cfg.work
	if workDir == "" {
		var err error
		workDir, err = os.MkdirTemp("", "portablefs-writeamp-")
		if err != nil {
			return err
		}
		if !cfg.keep {
			defer os.RemoveAll(workDir)
		}
	} else if err := os.MkdirAll(workDir, 0o755); err != nil {
		return err
	}

	if _, err := diskBytesWritten(); err != nil {
		return fmt.Errorf("kernel disk accounting: %w", err)
	}

	var results []result
	for _, size := range cfg.sizes {
		fmt.Fprintf(os.Stderr, "building baselines for %d files\n", size)
		base, root, inodeDepth, directoryDepth, err := buildPFT2Base(size)
		if err != nil {
			return fmt.Errorf("build PFT2 baseline size %d: %w", size, err)
		}
		boltBase := filepath.Join(workDir, fmt.Sprintf("bbolt-base-%d.db", size))
		if err := buildBoltBase(boltBase, size); err != nil {
			return fmt.Errorf("build bbolt baseline size %d: %w", size, err)
		}

		for _, workload := range workloads {
			for rep := 1; rep <= cfg.reps; rep++ {
				seed := cfg.seed ^ uint64(size)<<17 ^ uint64(rep)<<41 ^ workloadSeed(workload)
				pftResult, err := measurePFT2(workDir, base, root, size, inodeDepth, directoryDepth, workload, cfg.ops, rep, seed)
				if err != nil {
					return err
				}
				results = append(results, pftResult)
				if cfg.pretty {
					printResult(pftResult)
				}

				boltResult, err := measureBolt(workDir, boltBase, size, inodeDepth, directoryDepth, workload, cfg.ops, rep, seed)
				if err != nil {
					return err
				}
				results = append(results, boltResult)
				if cfg.pretty {
					printResult(boltResult)
				}
			}
		}
		if !cfg.keep {
			if err := os.Remove(boltBase); err != nil {
				return err
			}
		}
		runtime.GC()
	}
	return writeResults(cfg.out, results)
}

func workloadSeed(workload string) uint64 {
	var out uint64
	for _, b := range []byte(workload) {
		out = out*131 + uint64(b)
	}
	return out
}

func measuredOperations(workload string, configured int) int {
	if workload == "mixed" {
		return 100
	}
	return configured
}

func printResult(r result) {
	amp := "n/a"
	if r.LogicalBytes > 0 {
		amp = fmt.Sprintf("%.2fx", float64(r.KernelBytes)/float64(r.LogicalBytes))
	}
	fmt.Fprintf(os.Stderr, "%-5s files=%-7d depth=%d/%d %-17s rep=%d disk=%-10d amp=%s\n",
		r.Engine, r.TreeFiles, r.InodeDepth, r.DirectoryDepth, r.Workload, r.Rep, r.KernelBytes, amp)
}

func writeResults(path string, results []result) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	header := []string{
		"engine", "engine_version", "tree_files", "pft2_inode_index_depth", "pft2_directory_depth", "workload", "rep",
		"operations", "logical_bytes", "format_bytes", "path_write_bytes", "kernel_disk_bytes", "duration_ms",
		"kernel_amplification", "three_way_kernel_amplification", "kernel_bytes_per_op", "go_version", "os", "arch",
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, r := range results {
		amp, quorumAmp := "", ""
		if r.LogicalBytes > 0 {
			amp = strconv.FormatFloat(float64(r.KernelBytes)/float64(r.LogicalBytes), 'f', 6, 64)
			quorumAmp = strconv.FormatFloat(3*float64(r.KernelBytes)/float64(r.LogicalBytes), 'f', 6, 64)
		}
		record := []string{
			r.Engine, r.EngineVersion, strconv.Itoa(r.TreeFiles), strconv.Itoa(r.InodeDepth), strconv.Itoa(r.DirectoryDepth),
			r.Workload, strconv.Itoa(r.Rep), strconv.Itoa(r.Operations), strconv.FormatUint(r.LogicalBytes, 10),
			strconv.FormatInt(r.FormatBytes, 10), strconv.FormatInt(r.PathWriteBytes, 10), strconv.FormatUint(r.KernelBytes, 10),
			strconv.FormatInt(r.Duration.Milliseconds(), 10), amp, quorumAmp,
			strconv.FormatFloat(float64(r.KernelBytes)/float64(r.Operations), 'f', 3, 64), runtime.Version(), runtime.GOOS, runtime.GOARCH,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

// objectStore keeps the immutable baseline in memory. An overlay additionally
// records exact new-object bytes in a synced append log. The log is a
// measurement sink, not a proposed persistence format.
type objectStore struct {
	parent  *objectStore
	objects map[pft2.Ref][]byte
	log     *os.File
	pending bytes.Buffer
	written int64
	format  int64
}

func newObjectStore(parent *objectStore, log *os.File) *objectStore {
	return &objectStore{parent: parent, objects: make(map[pft2.Ref][]byte), log: log}
}

func (s *objectStore) Fetch(_ context.Context, ref pft2.Ref) ([]byte, error) {
	if data, ok := s.objects[ref]; ok {
		return data, nil
	}
	if s.parent != nil {
		return s.parent.Fetch(context.Background(), ref)
	}
	return nil, fmt.Errorf("object %s is absent", ref.Hex())
}

func (s *objectStore) PutNode(ref pft2.Ref, data []byte) error {
	return s.put('N', ref, data)
}

func (s *objectStore) PutPack(ref pft2.Ref, data []byte) error {
	return s.put('P', ref, data)
}

func (s *objectStore) put(kind byte, ref pft2.Ref, data []byte) error {
	if err := pft2.VerifyObjectBytes(ref, data); err != nil {
		return err
	}
	if _, ok := s.objects[ref]; ok {
		return nil
	}
	if s.parent != nil {
		if _, err := s.parent.Fetch(context.Background(), ref); err == nil {
			return nil
		}
	}
	s.objects[ref] = bytes.Clone(data)
	s.format += int64(len(data))
	if s.log == nil {
		return nil
	}
	s.pending.WriteString("OBJ")
	s.pending.WriteByte(kind)
	s.pending.Write(ref.Digest[:])
	var size [8]byte
	binary.LittleEndian.PutUint64(size[:], ref.Size)
	s.pending.Write(size[:])
	s.pending.Write(data)
	return nil
}

func (s *objectStore) commit(root pft2.Ref) error {
	if s.log == nil {
		return fmt.Errorf("commit on memory-only store")
	}
	s.pending.WriteString("ROOT")
	s.pending.Write(root.Digest[:])
	var size [8]byte
	binary.LittleEndian.PutUint64(size[:], root.Size)
	s.pending.Write(size[:])
	written, err := s.log.Write(s.pending.Bytes())
	if err != nil {
		return err
	}
	if written != s.pending.Len() {
		return io.ErrShortWrite
	}
	s.written += int64(written)
	s.pending.Reset()
	return s.log.Sync()
}

func buildPFT2Base(fileCount int) (*objectStore, pft2.Ref, int, int, error) {
	store := newObjectStore(nil, nil)
	dirEntries := make([]pft2.DirEntry, fileCount)
	for i := range dirEntries {
		dirEntries[i] = pft2.DirEntry{Name: baseName(i), Ino: uint64(i + 2), Kind: pft2.FileKindRegular}
	}
	dirRoot, dirCount, err := pft2.BuildDirectoryTree(dirEntries, store)
	if err != nil {
		return nil, pft2.Ref{}, 0, 0, err
	}

	indexEntries := make([]pft2.InodeIndexEntry, 0, fileCount+1)
	rootInode := pft2.Inode{
		Ino: pft2.RootIno, Kind: pft2.FileKindDirectory, Mode: 0o755, Nlink: 1, DirectoryRoot: dirRoot,
	}
	rootInodeRef, err := putPFT2Node(store, &pft2.Node{Kind: pft2.KindInode, Inode: &rootInode})
	if err != nil {
		return nil, pft2.Ref{}, 0, 0, err
	}
	indexEntries = append(indexEntries, pft2.InodeIndexEntry{Ino: pft2.RootIno, Inode: rootInodeRef})
	for i := 0; i < fileCount; i++ {
		size := sparseFileBytes
		if i == 0 {
			size = 0 // inode 2 is the sequential-append target.
		}
		inode := pft2.Inode{Ino: uint64(i + 2), Kind: pft2.FileKindRegular, Mode: 0o644, Nlink: 1, Size: size}
		ref, err := putPFT2Node(store, &pft2.Node{Kind: pft2.KindInode, Inode: &inode})
		if err != nil {
			return nil, pft2.Ref{}, 0, 0, err
		}
		indexEntries = append(indexEntries, pft2.InodeIndexEntry{Ino: inode.Ino, Inode: ref})
	}
	indexRoot, inodeCount, err := pft2.BuildInodeIndexTree(indexEntries, store)
	if err != nil {
		return nil, pft2.Ref{}, 0, 0, err
	}
	facts := pft2.Root{
		RootInode: rootInodeRef, InodeIndex: *indexRoot, MaxInoSeen: uint64(fileCount + 1),
		InodeCount: inodeCount, DirentCount: dirCount, LogicalBytes: uint64(fileCount-1) * sparseFileBytes,
	}
	root, err := putPFT2Node(store, &pft2.Node{Kind: pft2.KindRoot, Root: &facts})
	if err != nil {
		return nil, pft2.Ref{}, 0, 0, err
	}
	inodeDepth, err := pftTreeDepth(store, *indexRoot, pft2.KindInodeIndexLeaf, pft2.KindInodeIndexIndex)
	if err != nil {
		return nil, pft2.Ref{}, 0, 0, err
	}
	dirDepth, err := pftTreeDepth(store, *dirRoot, pft2.KindDirectoryLeaf, pft2.KindDirectoryIndex)
	if err != nil {
		return nil, pft2.Ref{}, 0, 0, err
	}
	return store, root, inodeDepth, dirDepth, nil
}

func putPFT2Node(store *objectStore, node *pft2.Node) (pft2.Ref, error) {
	encoded, err := pft2.EncodeNode(node)
	if err != nil {
		return pft2.Ref{}, err
	}
	ref := pft2.RefOf(encoded)
	return ref, store.PutNode(ref, encoded)
}

func pftTreeDepth(store *objectStore, start pft2.Ref, leaf, index pft2.Kind) (int, error) {
	ref := start
	for depth := 1; depth <= pft2.MaxTreeDepth; depth++ {
		data, err := store.Fetch(context.Background(), ref)
		if err != nil {
			return 0, err
		}
		node, err := pft2.DecodeNode(data)
		if err != nil {
			return 0, err
		}
		if node.Kind == leaf {
			return depth, nil
		}
		if node.Kind != index {
			return 0, fmt.Errorf("unexpected %s in depth walk", node.Kind)
		}
		switch index {
		case pft2.KindInodeIndexIndex:
			ref = node.InodeIndexIndex.Children[0].Child
		case pft2.KindDirectoryIndex:
			ref = node.DirectoryIndex.Children[0].Child
		default:
			return 0, fmt.Errorf("unsupported index kind %s", index)
		}
	}
	return 0, fmt.Errorf("tree exceeds depth %d", pft2.MaxTreeDepth)
}

func measurePFT2(
	workDir string,
	base *objectStore,
	root pft2.Ref,
	fileCount, inodeDepth, directoryDepth int,
	workload string,
	ops, rep int,
	seed uint64,
) (result, error) {
	path := filepath.Join(workDir, fmt.Sprintf("pft2-%d-%s-%d.log", fileCount, workload, rep))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return result{}, err
	}
	store := newObjectStore(base, file)
	state := newMutationState(fileCount, seed)
	operations := measuredOperations(workload, ops)
	before, err := diskBytesWritten()
	if err != nil {
		return result{}, err
	}
	started := time.Now()
	var logical uint64
	for op := 0; op < operations; op++ {
		reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: store}, root)
		if err != nil {
			return result{}, err
		}
		editor, err := pft2.NewEditor(context.Background(), reader, nil, pft2.EditorLimits{})
		if err != nil {
			return result{}, err
		}
		kind := operationKind(workload, op)
		written, err := applyPFT2(editor, state, kind, op)
		if err != nil {
			return result{}, fmt.Errorf("PFT2 %s size %d op %d: %w", workload, fileCount, op, err)
		}
		commit, err := editor.Commit(context.Background(), store, store)
		if err != nil {
			return result{}, fmt.Errorf("PFT2 %s size %d commit %d: %w", workload, fileCount, op, err)
		}
		root = commit.Root
		if err := store.commit(root); err != nil {
			return result{}, err
		}
		logical += written
	}
	if err := file.Close(); err != nil {
		return result{}, err
	}
	duration := time.Since(started)
	after, err := diskBytesWritten()
	if err != nil {
		return result{}, err
	}
	if !strings.HasSuffix(path, ".log") {
		return result{}, fmt.Errorf("refusing to remove unexpected PFT2 path %q", path)
	}
	if err := os.Remove(path); err != nil {
		return result{}, err
	}
	return result{
		Engine: "pft2", EngineVersion: "repository HEAD", TreeFiles: fileCount, InodeDepth: inodeDepth,
		DirectoryDepth: directoryDepth, Workload: workload, Rep: rep, Operations: operations, LogicalBytes: logical,
		FormatBytes: store.format, PathWriteBytes: store.written, KernelBytes: after - before, Duration: duration,
	}, nil
}

type mutationState struct {
	fileCount int
	rng       *rand.Rand
	appendAt  uint64
	nextIno   uint64
	created   int
	mkdirs    int
	renameIno uint64
	rename    string
	renameAlt string
}

func newMutationState(fileCount int, seed uint64) *mutationState {
	return &mutationState{
		fileCount: fileCount,
		rng:       rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		nextIno:   uint64(fileCount + 2),
		renameIno: 3,
		rename:    baseName(1),
		renameAlt: "renamed-anchor",
	}
}

func operationKind(workload string, op int) string {
	if workload != "mixed" {
		return workload
	}
	switch op % 100 {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
		20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
		30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
		40, 41, 42, 43, 44, 45, 46, 47, 48, 49:
		return "random-4k"
	case 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
		60, 61, 62, 63, 64, 65, 66, 67, 68, 69:
		return "sequential-append"
	case 70, 71, 72, 73, 74, 75, 76, 77, 78, 79:
		return "small-creates"
	case 80, 81, 82, 83, 84, 85, 86, 87, 88, 89:
		return "rename"
	case 90, 91, 92, 93, 94:
		return "chmod"
	default:
		return "mkdir"
	}
}

func applyPFT2(editor *pft2.Editor, state *mutationState, kind string, op int) (uint64, error) {
	ctx := context.Background()
	switch kind {
	case "random-4k":
		ino := uint64(3 + state.rng.IntN(state.fileCount-1))
		offset := uint64(state.rng.IntN(int(sparseFileBytes/pft2.CellBytes))) * pft2.CellBytes
		if err := editor.WriteCell(ctx, ino, offset, dataCell(op, ino^offset)); err != nil {
			return 0, err
		}
		if err := touchPFT2Inode(editor, ino, op, nil); err != nil {
			return 0, err
		}
		return pft2.CellBytes, nil
	case "sequential-append":
		if err := editor.WriteCell(ctx, 2, state.appendAt, dataCell(op, state.appendAt)); err != nil {
			return 0, err
		}
		state.appendAt += pft2.CellBytes
		if err := editor.SetFileSize(ctx, 2, state.appendAt); err != nil {
			return 0, err
		}
		if err := touchPFT2Inode(editor, 2, op, nil); err != nil {
			return 0, err
		}
		return pft2.CellBytes, nil
	case "small-creates":
		ino := state.allocateIno()
		name := fmt.Sprintf("new-%09d", state.created)
		state.created++
		meta := pft2.Inode{Ino: ino, Kind: pft2.FileKindRegular, Mode: 0o644, Nlink: 1, MtimeMs: int64(op + 1), CtimeMs: int64(op + 1)}
		if err := editor.PutInode(ctx, meta); err != nil {
			return 0, err
		}
		if err := editor.WriteCell(ctx, ino, 0, createCell(op, ino)); err != nil {
			return 0, err
		}
		if err := editor.SetFileSize(ctx, ino, createBytes); err != nil {
			return 0, err
		}
		if err := editor.PutDirEntry(ctx, pft2.RootIno, pft2.DirEntry{Name: name, Ino: ino, Kind: pft2.FileKindRegular}); err != nil {
			return 0, err
		}
		if err := touchPFT2Inode(editor, pft2.RootIno, op, nil); err != nil {
			return 0, err
		}
		return createBytes, nil
	case "rename":
		if err := editor.DeleteDirEntry(ctx, pft2.RootIno, state.rename); err != nil {
			return 0, err
		}
		if err := editor.PutDirEntry(ctx, pft2.RootIno, pft2.DirEntry{Name: state.renameAlt, Ino: state.renameIno, Kind: pft2.FileKindRegular}); err != nil {
			return 0, err
		}
		state.rename, state.renameAlt = state.renameAlt, state.rename
		if err := touchPFT2Inode(editor, state.renameIno, op, nil); err != nil {
			return 0, err
		}
		if err := touchPFT2Inode(editor, pft2.RootIno, op, nil); err != nil {
			return 0, err
		}
		return 0, nil
	case "chmod":
		ino := uint64(3 + state.rng.IntN(state.fileCount-1))
		mode := uint32(0o600)
		if op%2 == 1 {
			mode = 0o644
		}
		return 0, touchPFT2Inode(editor, ino, op, &mode)
	case "mkdir":
		ino := state.allocateIno()
		name := fmt.Sprintf("dir-%09d", state.mkdirs)
		state.mkdirs++
		meta := pft2.Inode{Ino: ino, Kind: pft2.FileKindDirectory, Mode: 0o755, Nlink: 1, MtimeMs: int64(op + 1), CtimeMs: int64(op + 1)}
		if err := editor.PutInode(ctx, meta); err != nil {
			return 0, err
		}
		if err := editor.PutDirEntry(ctx, pft2.RootIno, pft2.DirEntry{Name: name, Ino: ino, Kind: pft2.FileKindDirectory}); err != nil {
			return 0, err
		}
		return 0, touchPFT2Inode(editor, pft2.RootIno, op, nil)
	default:
		return 0, fmt.Errorf("unknown operation %q", kind)
	}
}

func touchPFT2Inode(editor *pft2.Editor, ino uint64, op int, mode *uint32) error {
	meta, found, err := editor.GetInode(context.Background(), ino)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("inode %d is absent", ino)
	}
	meta.DirectoryRoot = nil
	meta.ExtentRoot = nil
	meta.CtimeMs = int64(op + 1)
	meta.MtimeMs = int64(op + 1)
	if mode != nil {
		meta.Mode = *mode
	}
	return editor.PutInode(context.Background(), meta)
}

func (s *mutationState) allocateIno() uint64 {
	ino := s.nextIno
	s.nextIno++
	return ino
}

func baseName(index int) string {
	return fmt.Sprintf("f%09d", index)
}

func dataCell(op int, salt uint64) []byte {
	cell := make([]byte, pft2.CellBytes)
	state := uint64(op+1)*0x9e3779b97f4a7c15 ^ salt
	for i := 0; i < len(cell); i += 8 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		binary.LittleEndian.PutUint64(cell[i:], state|1)
	}
	return cell
}

func createCell(op int, salt uint64) []byte {
	cell := dataCell(op, salt)
	clear(cell[createBytes:])
	return cell
}

// bbolt keys use one ordered bucket: inode, dirent, and sparse cell rows.
func inodeKey(ino uint64) []byte {
	key := make([]byte, 9)
	key[0] = 'i'
	binary.BigEndian.PutUint64(key[1:], ino)
	return key
}

func dirKey(parent uint64, name string) []byte {
	key := make([]byte, 9+len(name))
	key[0] = 'd'
	binary.BigEndian.PutUint64(key[1:], parent)
	copy(key[9:], name)
	return key
}

func cellKey(ino, offset uint64) []byte {
	key := make([]byte, 17)
	key[0] = 'c'
	binary.BigEndian.PutUint64(key[1:], ino)
	binary.BigEndian.PutUint64(key[9:], offset)
	return key
}

type inodeValue struct {
	Kind  byte
	Mode  uint32
	Size  uint64
	Mtime int64
	Ctime int64
}

func encodeInodeValue(value inodeValue) []byte {
	out := make([]byte, 32)
	out[0] = value.Kind
	binary.LittleEndian.PutUint32(out[4:], value.Mode)
	binary.LittleEndian.PutUint64(out[8:], value.Size)
	binary.LittleEndian.PutUint64(out[16:], uint64(value.Mtime))
	binary.LittleEndian.PutUint64(out[24:], uint64(value.Ctime))
	return out
}

func decodeInodeValue(data []byte) (inodeValue, error) {
	if len(data) != 32 {
		return inodeValue{}, fmt.Errorf("inode value is %d bytes", len(data))
	}
	return inodeValue{
		Kind: data[0], Mode: binary.LittleEndian.Uint32(data[4:]), Size: binary.LittleEndian.Uint64(data[8:]),
		Mtime: int64(binary.LittleEndian.Uint64(data[16:])), Ctime: int64(binary.LittleEndian.Uint64(data[24:])),
	}, nil
}

func encodeDirValue(ino uint64, kind byte) []byte {
	out := make([]byte, 9)
	binary.LittleEndian.PutUint64(out, ino)
	out[8] = kind
	return out
}

func buildBoltBase(path string, fileCount int) error {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucket(fsBucket)
		if err != nil {
			return err
		}
		if err := bucket.Put(inodeKey(1), encodeInodeValue(inodeValue{Kind: 2, Mode: 0o755})); err != nil {
			return err
		}
		for i := 0; i < fileCount; i++ {
			ino := uint64(i + 2)
			size := sparseFileBytes
			if i == 0 {
				size = 0
			}
			if err := bucket.Put(inodeKey(ino), encodeInodeValue(inodeValue{Kind: 1, Mode: 0o644, Size: size})); err != nil {
				return err
			}
			if err := bucket.Put(dirKey(1, baseName(i)), encodeDirValue(ino, 1)); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		err = db.Sync()
	}
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	return err
}

func copyBaseline(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func measureBolt(
	workDir, baseline string,
	fileCount, inodeDepth, directoryDepth int,
	workload string,
	ops, rep int,
	seed uint64,
) (result, error) {
	path := filepath.Join(workDir, fmt.Sprintf("bbolt-%d-%s-%d.db", fileCount, workload, rep))
	if err := copyBaseline(baseline, path); err != nil {
		return result{}, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return result{}, err
	}
	state := newMutationState(fileCount, seed)
	operations := measuredOperations(workload, ops)
	before, err := diskBytesWritten()
	if err != nil {
		return result{}, err
	}
	started := time.Now()
	var logical uint64
	for op := 0; op < operations; op++ {
		kind := operationKind(workload, op)
		written, err := applyBolt(db, state, kind, op)
		if err != nil {
			return result{}, fmt.Errorf("bbolt %s size %d op %d: %w", workload, fileCount, op, err)
		}
		logical += written
	}
	if err := db.Sync(); err != nil {
		return result{}, err
	}
	if err := db.Close(); err != nil {
		return result{}, err
	}
	duration := time.Since(started)
	after, err := diskBytesWritten()
	if err != nil {
		return result{}, err
	}
	if !strings.HasSuffix(path, ".db") || path == baseline {
		return result{}, fmt.Errorf("refusing to remove unexpected bbolt path %q", path)
	}
	if err := os.Remove(path); err != nil {
		return result{}, err
	}
	return result{
		Engine: "bbolt", EngineVersion: boltVersion, TreeFiles: fileCount, InodeDepth: inodeDepth,
		DirectoryDepth: directoryDepth, Workload: workload, Rep: rep, Operations: operations, LogicalBytes: logical,
		FormatBytes: -1, PathWriteBytes: -1, KernelBytes: after - before, Duration: duration,
	}, nil
}

func applyBolt(db *bolt.DB, state *mutationState, kind string, op int) (uint64, error) {
	var logical uint64
	err := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(fsBucket)
		if bucket == nil {
			return errors.New("fs bucket is absent")
		}
		switch kind {
		case "random-4k":
			ino := uint64(3 + state.rng.IntN(state.fileCount-1))
			offset := uint64(state.rng.IntN(int(sparseFileBytes/pft2.CellBytes))) * pft2.CellBytes
			if err := bucket.Put(cellKey(ino, offset), dataCell(op, ino^offset)); err != nil {
				return err
			}
			logical = pft2.CellBytes
			return touchBoltInode(bucket, ino, op, nil)
		case "sequential-append":
			if err := bucket.Put(cellKey(2, state.appendAt), dataCell(op, state.appendAt)); err != nil {
				return err
			}
			state.appendAt += pft2.CellBytes
			logical = pft2.CellBytes
			return touchBoltInode(bucket, 2, op, func(value *inodeValue) { value.Size = state.appendAt })
		case "small-creates":
			ino := state.allocateIno()
			name := fmt.Sprintf("new-%09d", state.created)
			state.created++
			if err := bucket.Put(inodeKey(ino), encodeInodeValue(inodeValue{Kind: 1, Mode: 0o644, Size: createBytes, Mtime: int64(op + 1), Ctime: int64(op + 1)})); err != nil {
				return err
			}
			if err := bucket.Put(dirKey(1, name), encodeDirValue(ino, 1)); err != nil {
				return err
			}
			if err := bucket.Put(cellKey(ino, 0), createCell(op, ino)); err != nil {
				return err
			}
			logical = createBytes
			return touchBoltInode(bucket, 1, op, nil)
		case "rename":
			value := bytes.Clone(bucket.Get(dirKey(1, state.rename)))
			if value == nil {
				return fmt.Errorf("rename source %q is absent", state.rename)
			}
			if err := bucket.Delete(dirKey(1, state.rename)); err != nil {
				return err
			}
			if err := bucket.Put(dirKey(1, state.renameAlt), value); err != nil {
				return err
			}
			state.rename, state.renameAlt = state.renameAlt, state.rename
			if err := touchBoltInode(bucket, state.renameIno, op, nil); err != nil {
				return err
			}
			return touchBoltInode(bucket, 1, op, nil)
		case "chmod":
			ino := uint64(3 + state.rng.IntN(state.fileCount-1))
			mode := uint32(0o600)
			if op%2 == 1 {
				mode = 0o644
			}
			return touchBoltInode(bucket, ino, op, func(value *inodeValue) { value.Mode = mode })
		case "mkdir":
			ino := state.allocateIno()
			name := fmt.Sprintf("dir-%09d", state.mkdirs)
			state.mkdirs++
			if err := bucket.Put(inodeKey(ino), encodeInodeValue(inodeValue{Kind: 2, Mode: 0o755, Mtime: int64(op + 1), Ctime: int64(op + 1)})); err != nil {
				return err
			}
			if err := bucket.Put(dirKey(1, name), encodeDirValue(ino, 2)); err != nil {
				return err
			}
			return touchBoltInode(bucket, 1, op, nil)
		default:
			return fmt.Errorf("unknown operation %q", kind)
		}
	})
	return logical, err
}

func touchBoltInode(bucket *bolt.Bucket, ino uint64, op int, mutate func(*inodeValue)) error {
	value, err := decodeInodeValue(bucket.Get(inodeKey(ino)))
	if err != nil {
		return err
	}
	value.Mtime = int64(op + 1)
	value.Ctime = int64(op + 1)
	if mutate != nil {
		mutate(&value)
	}
	return bucket.Put(inodeKey(ino), encodeInodeValue(value))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
