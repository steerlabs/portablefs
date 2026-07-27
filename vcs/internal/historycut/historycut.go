// Package historycut is the deterministic HistoryCut reducer: it turns ONE
// captured cut tuple (frozen by pfh.history_cuts) into content-addressed
// PFT2 objects — the user filesystem ROOT plus the separate internal
// RecoveryRoot (control map, parked-orphan index, inode-namespace allocator
// watermarks) — by replaying the exact journal prefix, or by streaming a
// fully resolved legacy manifest, through the ONE shared filesystem
// transition engine (internal/fstransition) over a pft2.Editor.
//
// The package is a pure in-process reduction library: every input arrives
// through the JournalSource / LegacySource / BlobSource interfaces and every
// output object lands in a Store. In production BOTH sides are the direct Go
// history-worker (internal/histworker): sources are claim-fenced pfh
// SECURITY DEFINER functions over pgx, the Store uploads every produced
// object straight to the exact-key replicated object stores (read-after-
// write verified, receipted) as it is produced, and base/legacy content is
// fetched directly from the stores by RECORDED exact keys. There is no
// spool directory, no child process, and no process-local durable truth:
// crash-resume converges because the reduction is deterministic (object
// boundaries depend only on the frozen cut tuple and fixed constants),
// uploads are idempotent at per-incarnation keys, and cursors/receipts live
// in PostgreSQL.
//
// Verification is not optional: journal pages verify record_hash and the
// exact chain digest from the frozen base digest to the frozen cut digest;
// PFJ3 entries and PFC2 controls decode strictly; legacy conversions verify
// blob/chunk digests, sizes, offsets, decompression bounds, and finally the
// exact canonical tree hash of the resolved entry stream against the pinned
// anchor commit. Any mismatch is a definite typed failure — never a partial
// publication.
package historycut

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/fstransition"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/treehash"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// ─── errors ──────────────────────────────────────────────────────────────────

var (
	// ErrCorrupt is a definite integrity failure of the captured source: the
	// cut must fail, never retry into readiness.
	ErrCorrupt = errors.New("historycut: source corruption")
	// ErrNeedBlobs reports that reduction paused because blob content is not
	// staged yet. The supervisor fetches Needs() and re-runs; cursors make
	// the rerun resume deterministically.
	ErrNeedBlobs = errors.New("historycut: blob content required")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCorrupt}, args...)...)
}

// ─── chain verification (mirrors pfj.chain_step exactly) ────────────────────

// ChainStep folds one payload into the running chain digest:
// sha256(prev[32] || be64(len(payload)) || payload).
func ChainStep(prev [32]byte, payload []byte) [32]byte {
	h := sha256.New()
	h.Write(prev[:])
	var lenBE [8]byte
	for i := 0; i < 8; i++ {
		lenBE[7-i] = byte(uint64(len(payload)) >> (8 * i))
	}
	h.Write(lenBE[:])
	h.Write(payload)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// RecordHash is the per-record sidecar hash: ChainStep(zero, payload).
func RecordHash(payload []byte) [32]byte {
	var zero [32]byte
	return ChainStep(zero, payload)
}

func hexDigest(d [32]byte) string { return hex.EncodeToString(d[:]) }

func parseHex32(s, what string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, corruptf("%s %q is not 32 hex bytes", what, s)
	}
	copy(out[:], raw)
	return out, nil
}

// ─── cut facts ───────────────────────────────────────────────────────────────

// CutFacts is the frozen linearization tuple of one cut, decoded from the
// pfh.cut_status projection. All 64-bit values arrive as decimal strings.
type CutFacts struct {
	CutID           string           `json:"cutId"`
	Kind            string           `json:"kind"`
	SourceKind      string           `json:"sourceKind"`
	GenerationID    string           `json:"generationId"`
	RecordCodec     string           `json:"recordCodec"`
	ControlCodec    string           `json:"controlCodec"`
	SourceBaseSeq   string           `json:"sourceBaseSeq"`
	SourceBaseDig   string           `json:"sourceBaseDigest"`
	CutSeqExclusive string           `json:"cutSeqExclusive"`
	CutDigest       string           `json:"cutDigest"`
	InodeNamespace  string           `json:"inodeNamespace"`
	NamespaceNext   string           `json:"namespaceNextLocal"`
	BaseCommit      *BaseCommitFacts `json:"baseCommit"`
}

// BaseCommitFacts is the worker's view of the frozen base commit: the USER
// arm (root) plus, for a pft2 base, its recovery ANCHOR summary and the
// database-proven base MODE that decides whether that anchor may be
// imported at all.
type BaseCommitFacts struct {
	CommitID   string `json:"commitId"`
	CommitKind string `json:"commitKind"`
	// BaseMode is the database-proven provenance of this base for THIS
	// cut's branch: "adopted" (a pft2 commit produced by a cut of the SAME
	// branch — its anchor binds exactly), "fork" (a pft2 commit produced by
	// a DIFFERENT branch's cut — only the immutable user root is imported;
	// the anchor, controls, orphans, and allocator are NEVER read), or
	// "conversion" (a manifest_v1 legacy base imported through the
	// conversion pipeline). Required whenever a base commit is present;
	// anything missing, unknown, or contradictory fails the cut closed.
	BaseMode         string `json:"baseMode"`
	TreeHash         string `json:"treeHash"`
	RootDigest       string `json:"rootDigest"`
	RootSize         string `json:"rootSize"`
	MaxInoSeen       string `json:"maxInoSeen"`
	AnchorID         string `json:"anchorId"`
	RecoveryRoot     string `json:"recoveryRootDigest"`
	RecoveryRootSize string `json:"recoveryRootSize"`
	// InodeNamespace is the DB row's view of the anchor's allocation
	// namespace (the PRODUCING branch's namespace). For an adopted base it
	// must equal both the hashed anchor's namespace and this cut's
	// namespace; for a fork it must DIFFER from this cut's namespace.
	InodeNamespace string `json:"inodeNamespace"`
	NextLocal      string `json:"nextLocal"`
	AnchorMaxIno   string `json:"anchorMaxInoSeen"`
}

func (f *CutFacts) baseSeq() (uint64, error) { return parseU64(f.SourceBaseSeq, "sourceBaseSeq") }
func (f *CutFacts) cutSeq() (uint64, error)  { return parseU64(f.CutSeqExclusive, "cutSeqExclusive") }
func (f *CutFacts) namespace() (uint32, error) {
	v, err := parseU64(f.InodeNamespace, "inodeNamespace")
	if err != nil {
		return 0, err
	}
	if v < 1 || v > uint64(pft2.MaxInodeNamespace) {
		return 0, corruptf("inode namespace %d outside 1..%d", v, pft2.MaxInodeNamespace)
	}
	return uint32(v), nil
}

func parseU64(s, what string) (uint64, error) {
	if s == "" {
		return 0, corruptf("%s is missing", what)
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, corruptf("%s %q is not a decimal uint64", what, s)
	}
	return v, nil
}

// ─── sources ─────────────────────────────────────────────────────────────────

// PageRecord is one durable journal record with its recorded hashes.
type PageRecord struct {
	Seq         uint64
	Payload     []byte
	RecordHash  string
	ChainDigest string
}

// JournalSource reads the immutable captured journal prefix (claim-fenced).
type JournalSource interface {
	ReadPage(ctx context.Context, fromSeq uint64, maxRecords int, maxBytes int64) ([]PageRecord, error)
}

// LegacyEntry is one resolved, ino-assigned legacy manifest entry.
type LegacyEntry struct {
	Ord         int64
	Path        string
	Kind        string
	Mode        uint32
	UID         uint32
	GID         uint32
	Size        uint64
	MtimeMs     int64
	CtimeMs     int64
	AtimeMs     int64
	Executable  bool
	AssignedIno uint64
	Nlink       int
	LinkTarget  string
	BlobDigest  string
	BlobSize    int64
	Compression string
	Packed      bool
	ChunksJSON  []byte
	Synthetic   bool // synthesized ancestor: excluded from the tree hash
}

// LegacySource streams the finalized entries and persists resume cursors.
type LegacySource interface {
	EntriesPage(ctx context.Context, afterOrd int64, limit int) ([]LegacyEntry, error)
	ImportCursor(ctx context.Context) (json.RawMessage, error)
	PutImportCursor(ctx context.Context, cursor json.RawMessage) error
	// VerifyTreeHash proves the recomputed canonical hash against the pinned
	// anchor commit in the database (a mismatch raises there).
	VerifyTreeHash(ctx context.Context, treeHash string) error
}

// BlobSource returns verified-length blob bytes from the local spool. A
// missing digest returns ErrNeedBlobs AFTER registering the need, so one
// pass collects a bounded batch for the supervisor.
type BlobSource interface {
	Blob(ctx context.Context, digest string, size int64) ([]byte, error)
}

// ObjectFact is one content-addressed object's registration facts.
type ObjectFact struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// ─── spool ───────────────────────────────────────────────────────────────────

// Store is the object surface one materialization reduces into: a
// content-addressed sink + fetcher with typed need registration. *Spool is
// the in-memory implementation for tests/fixtures. Production supplies the
// history worker's bounded, upload-as-produced cutStore; no local durable
// spool participates in recovery or publication.
type Store interface {
	pft2.Fetcher
	PutNode(ref pft2.Ref, encoded []byte) error
	PutPack(ref pft2.Ref, data []byte) error
	Seed(ref pft2.Ref, data []byte) error
	// NeedDigest registers one missing content address for the supervisor.
	NeedDigest(digest string, size int64)
	// Needs lists the registered missing content addresses.
	Needs() map[string]int64
}

// Spool is the deterministic content-addressed object set one materialization
// produces (and the fetch surface for base-tree objects already staged). It
// implements pft2.NodeSink, pft2.PackSink, and pft2.Fetcher.
type Spool struct {
	objects map[pft2.Ref][]byte
	order   []pft2.Ref
	needs   map[string]int64 // digest -> size (missing base/blob objects)
}

// NewSpool creates an empty spool.
func NewSpool() *Spool {
	return &Spool{objects: map[pft2.Ref][]byte{}, needs: map[string]int64{}}
}

// Seed stages one already-fetched object (base tree node, pack, or blob).
func (s *Spool) Seed(ref pft2.Ref, data []byte) error {
	if pft2.RefOf(data) != ref {
		return corruptf("seeded object does not match its reference")
	}
	if _, ok := s.objects[ref]; !ok {
		s.objects[ref] = append([]byte(nil), data...)
		s.order = append(s.order, ref)
	}
	return nil
}

// PutNode implements pft2.NodeSink.
func (s *Spool) PutNode(ref pft2.Ref, encoded []byte) error { return s.Seed(ref, encoded) }

// PutPack implements pft2.PackSink.
func (s *Spool) PutPack(ref pft2.Ref, data []byte) error { return s.Seed(ref, data) }

// Fetch implements pft2.Fetcher; a miss registers a need and fails typed.
func (s *Spool) Fetch(_ context.Context, ref pft2.Ref) ([]byte, error) {
	if data, ok := s.objects[ref]; ok {
		return data, nil
	}
	s.NeedDigest("sha256:"+ref.Hex(), int64(ref.Size))
	return nil, fmt.Errorf("%w: object sha256:%s (%d bytes)", ErrNeedBlobs, ref.Hex(), ref.Size)
}

// NeedDigest registers one missing content address.
func (s *Spool) NeedDigest(digest string, size int64) { s.needs[digest] = size }

// Needs lists the missing digests registered by failed fetches.
func (s *Spool) Needs() map[string]int64 {
	out := make(map[string]int64, len(s.needs))
	for k, v := range s.needs {
		out[k] = v
	}
	return out
}

// Objects enumerates every spooled object in insertion order.
func (s *Spool) Objects() []pft2.Ref { return append([]pft2.Ref(nil), s.order...) }

// Bytes returns one object's bytes.
func (s *Spool) Bytes(ref pft2.Ref) ([]byte, bool) {
	data, ok := s.objects[ref]
	return data, ok
}

// ─── result ──────────────────────────────────────────────────────────────────

// Result is the complete materialization outcome the worker publishes. The
// two closures are DISTINCT: UserClosure is the exact reachable set of the
// user filesystem root; RecoveryClosure is the reachable set of the
// RecoveryRoot MINUS the user closure (the strictly internal objects —
// recovery root, control map, orphan index). The recovery root references
// the user root, so together they cover the anchor's full reachability while
// user APIs only ever serve the user set.
type Result struct {
	Root         pft2.Ref
	RecoveryRoot pft2.Ref
	ControlRoot  *pft2.Ref
	OrphanIndex  *pft2.Ref
	// NextLocal / MaxInoSeen are the monotone allocator watermarks after the
	// cut (namespace-local counter; global ino high-water).
	NextLocal  uint64
	MaxInoSeen uint64
	// RootMaxInoSeen is the USER root object's own recorded high-water — the
	// fact an attach proof must bind byte-exactly against the hashed ROOT.
	// It can sit BELOW MaxInoSeen whenever the fold burned identities that
	// did not survive into the tree (deletes, reaped orphans); recording the
	// allocator watermark in its place breaks every later cut-base attach.
	RootMaxInoSeen uint64
	// User closure accounting (new + reused base objects reachable from the
	// user root), and the exact digest set (sha256:<hex>).
	UserObjectCount uint64
	UserObjectBytes uint64
	UserClosure     []string
	// Recovery-only closure accounting and digest set.
	RecoveryObjectCount uint64
	RecoveryObjectBytes uint64
	RecoveryClosure     []string
}

// fixed reduction constants (changing any of these changes committed object
// boundaries and therefore the materializer version string).
const (
	pageMaxRecords   = 256
	pageMaxBytes     = 16 << 20
	importChunkOps   = 4096
	importChunkBytes = 128 << 20
	legacyEntryPage  = 2048
	maxChunksPerFile = 8192
	maxGzipBlobBytes = int64(1) << 32 // 4 GiB decompressed bound per blob
	// managedChunkOps / managedChunkBytes gate the managed journal fold's
	// checkpoint commits: after a whole record folds (never inside one
	// OpBatch's leaves), the fold commits the tree transaction and reopens
	// it on the committed root once it has applied managedChunkOps leaf
	// mutations or the editor RETAINS managedChunkBytes staged cell bytes
	// (read exactly via pft2.Editor.StagedCellBytes, coalescing included).
	// This bounds every transaction far below the editor's staged-cell cap
	// and the traversal budgets regardless of backlog size — a fold whose
	// backlog stays under both thresholds still commits exactly once.
	managedChunkOps   = 4096
	managedChunkBytes = 128 << 20
	// MaterializerVersion identifies this exact deterministic reduction.
	// -2: anchors always carry a ControlRoot (with NextCheckoutEpoch and the
	// new db_time_floor_ms), exact envelope outcomes fold into the anchored
	// control map, and the anchor NextLocal dominates every logged local —
	// all of which change produced object bytes for the same cut tuple.
	// -3: live extended attributes fold through the shared engine and anchor
	// as XATTR_LEAF objects on the RecoveryRoot (recovery closure only) —
	// a cut whose fold holds xattrs produces objects a -2 reduction never
	// emitted (xattr-free cuts stay byte-identical).
	// -4: managed journal folds checkpoint-commit at managedChunkOps /
	// managedChunkBytes instead of folding the whole backlog through one
	// transaction. A backlog crossing either threshold now materializes
	// (previously it tripped the 256 MiB staged-cell transaction limit and
	// failed terminally) and produces chunk-boundary-dependent object
	// bytes; folds under both thresholds stay byte-identical to -3.
	// -5: filesystem-homed xattrs also ride appended Root field 8, making
	// them part of the user closure and preserving them across snapshots
	// and forks. RecoveryRoot retains the complete set, including parked
	// orphan xattrs. Xattr-free cuts stay byte-identical to -4.
	//
	// NOT a bump: the empty-filesystem outcome (a fold with no base root that
	// stages nothing now materializes the canonical empty root instead of
	// failing terminally). This constant fences CHANGED bytes for a frozen cut
	// tuple; that change only maps tuples the reduction previously REFUSED —
	// every fold that ever produced a root took the identical path and
	// produces identical bytes. Changing the canonical empty filesystem's own
	// bytes later WOULD require a bump.
	MaterializerVersion = "pfm-2026.07-5"
)

// ─── managed journal materialization ─────────────────────────────────────────

// Materializer reduces one claimed cut.
type Materializer struct {
	Facts   CutFacts
	Journal JournalSource
	Legacy  LegacySource
	Blobs   BlobSource
	Spool   Store
	// Limits bounds every tree transaction this reduction opens (zero values
	// select the pft2 defaults). Production leaves it zero; tests lower
	// MaxStagedCellBytes to force many checkpoint commits on small folds.
	Limits pft2.EditorLimits
}

// Run materializes the cut. On ErrNeedBlobs the supervisor stages Spool
// needs and calls Run again (cursors + the content-addressed spool make the
// rerun deterministic).
func (m *Materializer) Run(ctx context.Context) (*Result, error) {
	switch {
	case m.Facts.SourceKind == "legacy_manifest":
		return m.runLegacy(ctx, 0)
	case m.Facts.SourceKind == "managed_journal":
		return m.runManaged(ctx)
	default:
		return nil, corruptf("unknown source kind %q", m.Facts.SourceKind)
	}
}

// zeroChainDigest is the frozen chain origin of a fresh generation.
const zeroChainDigest = "0000000000000000000000000000000000000000000000000000000000000000"

func (m *Materializer) runManaged(ctx context.Context) (*Result, error) {
	baseSeq, err := m.Facts.baseSeq()
	if err != nil {
		return nil, err
	}
	cutSeq, err := m.Facts.cutSeq()
	if err != nil {
		return nil, err
	}
	namespace, err := m.Facts.namespace()
	if err != nil {
		return nil, err
	}
	if m.Facts.RecordCodec != "pfj3" && m.Facts.RecordCodec != "pfr1" {
		return nil, corruptf("unknown record codec %q", m.Facts.RecordCodec)
	}

	// Base state, decided by the DATABASE-PROVEN base mode and re-verified
	// against the hashed objects:
	//   * adopted    — a pft2 commit produced by a SAME-branch cut: its
	//     recovery anchor (controls, orphans, allocator) binds exactly;
	//   * fork       — a pft2 commit produced by a DIFFERENT branch's cut:
	//     ONLY the immutable user root is imported; the source anchor's
	//     controls, orphan namespace, and allocator are never read;
	//   * conversion — a manifest_v1 base imported through the legacy
	//     pipeline;
	//   * absent     — an empty base.
	// Missing, unknown, or contradictory mode facts fail the cut closed.
	var (
		baseRoot     *pft2.Ref
		baseRecovery *recoveryFacts
	)
	if m.Facts.BaseCommit != nil {
		bc := m.Facts.BaseCommit
		switch bc.CommitKind {
		case "pft2":
			ref, err := refFromParts(bc.RootDigest, bc.RootSize)
			if err != nil {
				return nil, err
			}
			baseRoot = &ref
			switch bc.BaseMode {
			case "adopted":
				if bc.RecoveryRoot == "" {
					return nil, corruptf("adopted pft2 base carries no recovery anchor")
				}
				baseRecovery, err = m.loadRecovery(ctx, bc.RecoveryRoot, bc.RecoveryRootSize)
				if err != nil {
					return nil, err
				}
				if err := m.bindAdoptedRecovery(bc, baseRecovery, ref, baseSeq, namespace); err != nil {
					return nil, err
				}
			case "fork":
				// A fork is a fresh generation origin by construction; a
				// nonzero base seq or a non-origin chain contradicts it.
				if baseSeq != 0 || m.Facts.SourceBaseDig != zeroChainDigest {
					return nil, corruptf("fork base claims seq %d digest %q; a fork folds from the zero origin",
						baseSeq, m.Facts.SourceBaseDig)
				}
				// The source anchor (if the claim projects one) belongs to
				// the source branch: its namespace must DIFFER from this
				// cut's, or the mode itself is a lie. It is never fetched.
				if bc.InodeNamespace != "" {
					anchorNs, err := parseU64(bc.InodeNamespace, "base anchor inodeNamespace")
					if err != nil {
						return nil, err
					}
					if anchorNs == uint64(namespace) {
						return nil, corruptf("fork base anchor namespace %d equals the cut namespace; a same-branch base cannot be a fork", anchorNs)
					}
				}
			default:
				return nil, corruptf("pft2 base commit carries base mode %q (want adopted or fork)", bc.BaseMode)
			}
		case "manifest_v1":
			if bc.BaseMode != "conversion" {
				return nil, corruptf("manifest_v1 base commit carries base mode %q (want conversion)", bc.BaseMode)
			}
			if baseSeq != 0 {
				return nil, corruptf("manifest_v1 base commit with nonzero base seq %d", baseSeq)
			}
			imported, err := m.runLegacy(ctx, cutSeq)
			if err != nil {
				return nil, err
			}
			baseRoot = &imported.Root
			// The imported tree IS the base; journal replay continues below
			// with the allocator seeded from the import watermarks.
			return m.foldJournal(ctx, baseRoot, nil, imported.NextLocal, imported.MaxInoSeen, baseSeq, cutSeq)
		default:
			return nil, corruptf("base commit kind %q is not materializable", bc.CommitKind)
		}
	}

	// Allocator seeding is a pure function of the base anchor and the folded
	// journal — NEVER the live namespace row, which keeps advancing after
	// the cut froze and would make retried materializations diverge. A fork
	// (or empty base) starts at local 1; the fold advances past every logged
	// identity in assemble.
	nextLocal := uint64(1)
	maxInoSeen := uint64(0)
	var orphanIndex *pft2.Ref
	if baseRecovery != nil {
		nextLocal = baseRecovery.NextLocal
		orphanIndex = baseRecovery.OrphanIndex
		maxInoSeen = baseRecovery.MaxInoSeen
	}
	if m.Facts.BaseCommit != nil && m.Facts.BaseCommit.MaxInoSeen != "" {
		// The DB-proven base ROOT high-water participates in the engine's
		// monotone seed (fork included: the reused root's ids must never be
		// re-issued to legacy allocations).
		rootMax, err := parseU64(m.Facts.BaseCommit.MaxInoSeen, "base maxInoSeen")
		if err != nil {
			return nil, err
		}
		if rootMax > maxInoSeen {
			maxInoSeen = rootMax
		}
	}
	return m.foldJournalWithControl(ctx, baseRoot, orphanIndex, baseRecovery, nextLocal, maxInoSeen, baseSeq, cutSeq)
}

// bindAdoptedRecovery fail-closes every provable mismatch between the
// database's adopted-base claim and the HASHED anchor object: filesystem
// root, as-of sequence, allocation namespace (hashed, claimed, and the
// cut's own), and the allocator cursor. A lying claim must never reach
// journal folding.
func (m *Materializer) bindAdoptedRecovery(
	bc *BaseCommitFacts, facts *recoveryFacts, baseRoot pft2.Ref, baseSeq uint64, namespace uint32,
) error {
	if facts.FilesystemRoot != baseRoot {
		return corruptf("adopted anchor binds filesystem root sha256:%s, base commit carries sha256:%s",
			facts.FilesystemRoot.Hex(), baseRoot.Hex())
	}
	if facts.AsOfSeq != baseSeq {
		return corruptf("adopted anchor is as-of seq %d, cut folds from base seq %d", facts.AsOfSeq, baseSeq)
	}
	if facts.Namespace != namespace {
		return corruptf("adopted anchor allocates namespace %d, the cut's branch allocates %d",
			facts.Namespace, namespace)
	}
	if bc.InodeNamespace != "" {
		claimed, err := parseU64(bc.InodeNamespace, "base anchor inodeNamespace")
		if err != nil {
			return err
		}
		if claimed != uint64(facts.Namespace) {
			return corruptf("claimed anchor namespace %d does not equal the hashed anchor's %d",
				claimed, facts.Namespace)
		}
	}
	if bc.NextLocal != "" {
		claimed, err := parseU64(bc.NextLocal, "base anchor nextLocal")
		if err != nil {
			return err
		}
		if claimed != facts.NextLocal {
			return corruptf("claimed anchor nextLocal %d does not equal the hashed anchor's %d",
				claimed, facts.NextLocal)
		}
	}
	return nil
}

// recoveryFacts is the decoded internal anchor of a base pft2 commit, with
// the hashed bindings adoption verification requires.
type recoveryFacts struct {
	FilesystemRoot pft2.Ref
	AsOfSeq        uint64
	Namespace      uint32
	ControlRoot    *pft2.Ref
	OrphanIndex    *pft2.Ref
	NextLocal      uint64
	MaxInoSeen     uint64
	State          *pfc2.State
	Orphans        []uint64
	// Xattrs is the anchored LIVE extended-attribute state the fold seeds
	// the transition engine with (strictly ascending (ino, name)).
	Xattrs []pft2.XattrEntry
}

func (m *Materializer) loadRecovery(ctx context.Context, digestHex, sizeStr string) (*recoveryFacts, error) {
	ref, err := refFromParts(digestHex, sizeStr)
	if err != nil {
		return nil, err
	}
	raw, err := m.Spool.Fetch(ctx, ref)
	if err != nil {
		return nil, err
	}
	node, err := pft2.DecodeNodeKind(raw, pft2.KindRecoveryRoot)
	if err != nil {
		return nil, corruptf("base recovery root: %v", err)
	}
	rr := node.RecoveryRoot
	facts := &recoveryFacts{
		FilesystemRoot: rr.FilesystemRoot,
		AsOfSeq:        rr.AsOfSeq,
		Namespace:      rr.InoNamespace,
		ControlRoot:    rr.ControlRoot,
		OrphanIndex:    rr.OrphanIndex,
		NextLocal:      rr.NextLocal,
	}
	// Rebuild the exact control state the base anchored.
	if rr.ControlRoot != nil {
		state, err := m.rebuildControl(ctx, *rr.ControlRoot)
		if err != nil {
			return nil, err
		}
		facts.State = state
	}
	if rr.OrphanIndex != nil {
		orphans, maxIno, err := m.collectOrphans(ctx, *rr.OrphanIndex)
		if err != nil {
			return nil, err
		}
		facts.Orphans = orphans
		facts.MaxInoSeen = maxIno
	}
	xattrs, err := m.collectXattrs(ctx, rr.XattrLeaves)
	if err != nil {
		return nil, err
	}
	facts.Xattrs = xattrs
	return facts, nil
}

// collectXattrs loads the base anchor's ordered xattr leaves, re-verifying
// the cross-leaf (ino, name) ordering (in-leaf ordering is codec-validated).
func (m *Materializer) collectXattrs(ctx context.Context, leaves []pft2.Ref) ([]pft2.XattrEntry, error) {
	var out []pft2.XattrEntry
	for i, ref := range leaves {
		raw, err := m.Spool.Fetch(ctx, ref)
		if err != nil {
			return nil, err
		}
		node, err := pft2.DecodeNodeKind(raw, pft2.KindXattrLeaf)
		if err != nil {
			return nil, corruptf("base xattr leaf %d: %v", i, err)
		}
		for _, e := range node.XattrLeaf.Entries {
			if n := len(out); n > 0 {
				prev := out[n-1]
				if prev.Ino > e.Ino || (prev.Ino == e.Ino && prev.Name >= e.Name) {
					return nil, corruptf("base xattr leaves are not strictly ordered across leaf %d", i)
				}
			}
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *Materializer) rebuildControl(ctx context.Context, root pft2.Ref) (*pfc2.State, error) {
	raw, err := m.Spool.Fetch(ctx, root)
	if err != nil {
		return nil, err
	}
	node, err := pft2.DecodeNodeKind(raw, pft2.KindControlRoot)
	if err != nil {
		return nil, corruptf("base control root: %v", err)
	}
	cr := node.ControlRoot
	if cr.DbTimeFloorMs > uint64(1<<62) {
		return nil, corruptf("base control root database-time floor %d overflows", cr.DbTimeFloorMs)
	}
	// NextCheckoutEpoch and DbTimeFloorMs ride the CONTROL_ROOT itself so
	// they survive cuts whose reduced map is empty: a replacement authority
	// must never reuse a checkout epoch or accept a minted database time
	// older than the retired prefix.
	projection := &pfc2.Projection{
		Schema:            pfc2.ProjectionSchema,
		NextCheckoutEpoch: pfc2.Epoch(strconv.FormatUint(cr.NextCheckoutEpoch, 10)),
		DbTimeFloorMs:     int64(cr.DbTimeFloorMs),
	}
	if cr.MapRoot != nil {
		entries, err := m.collectControlEntries(ctx, *cr.MapRoot)
		if err != nil {
			return nil, err
		}
		projection.Entries = entries
		for i := range entries {
			addProjectionCount(&projection.Counts, entries[i].Kind)
		}
	}
	state, err := pfc2.Rebuild(projection)
	if err != nil {
		return nil, corruptf("base control state rebuild: %v", err)
	}
	return state, nil
}

func (m *Materializer) collectControlEntries(ctx context.Context, root pft2.Ref) ([]pfc2.Entry, error) {
	var out []pfc2.Entry
	var walk func(ref pft2.Ref) error
	walk = func(ref pft2.Ref) error {
		raw, err := m.Spool.Fetch(ctx, ref)
		if err != nil {
			return err
		}
		node, err := pft2.DecodeNode(raw)
		if err != nil {
			return corruptf("control tree node: %v", err)
		}
		switch node.Kind {
		case pft2.KindControlLeaf:
			for _, e := range node.ControlLeaf.Entries {
				entry, err := pfc2.DecodeEntry(e.Value)
				if err != nil {
					return corruptf("control entry decode: %v", err)
				}
				out = append(out, entry)
			}
			return nil
		case pft2.KindControlIndex:
			for _, child := range node.ControlIndex.Children {
				if err := walk(child.Child); err != nil {
					return err
				}
			}
			return nil
		default:
			return corruptf("control tree contains %s", node.Kind)
		}
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	return out, nil
}

func (m *Materializer) collectOrphans(ctx context.Context, root pft2.Ref) ([]uint64, uint64, error) {
	var inos []uint64
	maxIno := uint64(0)
	var walk func(ref pft2.Ref) error
	walk = func(ref pft2.Ref) error {
		raw, err := m.Spool.Fetch(ctx, ref)
		if err != nil {
			return err
		}
		node, err := pft2.DecodeNode(raw)
		if err != nil {
			return corruptf("orphan index node: %v", err)
		}
		switch node.Kind {
		case pft2.KindInodeIndexLeaf:
			for _, e := range node.InodeIndexLeaf.Entries {
				inos = append(inos, e.Ino)
				if e.Ino > maxIno {
					maxIno = e.Ino
				}
			}
			return nil
		case pft2.KindInodeIndexIndex:
			for _, child := range node.InodeIndexIndex.Children {
				if err := walk(child.Child); err != nil {
					return err
				}
			}
			return nil
		default:
			return corruptf("orphan index contains %s", node.Kind)
		}
	}
	if err := walk(root); err != nil {
		return nil, 0, err
	}
	return inos, maxIno, nil
}

func (m *Materializer) foldJournal(
	ctx context.Context, baseRoot *pft2.Ref, orphanIndex *pft2.Ref,
	nextLocal, maxInoSeen, baseSeq, cutSeq uint64,
) (*Result, error) {
	return m.foldJournalWithControl(ctx, baseRoot, orphanIndex, nil, nextLocal, maxInoSeen, baseSeq, cutSeq)
}

func (m *Materializer) foldJournalWithControl(
	ctx context.Context, baseRoot *pft2.Ref, orphanIndex *pft2.Ref,
	baseRecovery *recoveryFacts, nextLocal, maxInoSeen, baseSeq, cutSeq uint64,
) (*Result, error) {
	namespace, err := m.Facts.namespace()
	if err != nil {
		return nil, err
	}
	editor, engine, err := m.openEditor(ctx, baseRoot, orphanIndex, namespace, &nextLocal, maxInoSeen)
	if err != nil {
		return nil, err
	}
	var baseUserXattrs []pft2.XattrEntry
	if baseRoot != nil {
		raw, err := m.Spool.Fetch(ctx, *baseRoot)
		if err != nil {
			return nil, err
		}
		node, err := pft2.DecodeNodeKind(raw, pft2.KindRoot)
		if err != nil {
			return nil, corruptf("base filesystem root: %v", err)
		}
		baseUserXattrs, err = m.collectXattrs(ctx, node.Root.XattrLeaves)
		if err != nil {
			return nil, err
		}
		for _, e := range baseUserXattrs {
			engine.SeedXattr(e.Ino, e.Name, e.Value)
		}
	}
	if baseRecovery != nil {
		for _, ino := range baseRecovery.Orphans {
			engine.SeedOrphan(ino)
		}
		// New-format roots duplicate every filesystem-homed row into the
		// complete recovery set. Require byte agreement before adding the
		// recovery-only orphan rows. Old roots have no field 8 and continue
		// to restore solely from RecoveryRoot.
		recoveryRows := make(map[string][]byte, len(baseRecovery.Xattrs))
		for _, e := range baseRecovery.Xattrs {
			recoveryRows[strconv.FormatUint(e.Ino, 10)+"\x00"+e.Name] = e.Value
		}
		for _, e := range baseUserXattrs {
			value, ok := recoveryRows[strconv.FormatUint(e.Ino, 10)+"\x00"+e.Name]
			if !ok || !bytes.Equal(value, e.Value) {
				return nil, corruptf("base root xattr %d/%q disagrees with recovery anchor", e.Ino, e.Name)
			}
		}
		for _, e := range baseRecovery.Xattrs {
			engine.SeedXattr(e.Ino, e.Name, e.Value)
		}
	}

	control := pfc2.NewState()
	if baseRecovery != nil && baseRecovery.State != nil {
		control = baseRecovery.State
	}

	// Checkpoint: bound ONE transaction's staging regardless of backlog
	// size. The staged edits commit (emitting their objects), the editor
	// reopens on the just-committed root with the committed orphan index
	// (continuity for parked inodes), and the SAME engine — whose orphan,
	// xattr, and allocator state is transaction-independent and must
	// survive — rebinds to the fresh transaction. Checkpoints fire only at
	// whole-record boundaries, so an atomic OpBatch always commits together.
	stagedThreshold := m.managedStagedByteThreshold()
	chunkOps := 0
	checkpoint := func() error {
		res, err := editor.Commit(ctx, m.Spool, m.Spool)
		if err != nil {
			return err
		}
		editor, err = m.reopenEditor(ctx, &res.Root, res.OrphanIndex)
		if err != nil {
			return err
		}
		engine.SetTx(editor)
		chunkOps = 0
		return nil
	}

	// Fold the exact captured range, verifying hashes and the chain.
	chain, err := parseHex32(m.Facts.SourceBaseDig, "base digest")
	if err != nil {
		return nil, err
	}
	next := baseSeq
	for next < cutSeq {
		page, err := m.Journal.ReadPage(ctx, next, pageMaxRecords, pageMaxBytes)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return nil, corruptf("journal page at seq %d is empty below the cut %d", next, cutSeq)
		}
		for _, rec := range page {
			if rec.Seq != next {
				return nil, corruptf("journal returned seq %d, want %d (gap or reorder)", rec.Seq, next)
			}
			if hexDigest(RecordHash(rec.Payload)) != rec.RecordHash {
				return nil, corruptf("record %d sidecar hash mismatch", rec.Seq)
			}
			chain = ChainStep(chain, rec.Payload)
			if hexDigest(chain) != rec.ChainDigest {
				return nil, corruptf("record %d chain digest mismatch", rec.Seq)
			}
			entry, err := m.decodeEntry(rec)
			if err != nil {
				return nil, err
			}
			if entry.Tree != nil {
				if err := m.applyTreeRow(ctx, engine, control, rec.Seq, *entry.Tree); err != nil {
					return nil, err
				}
				chunkOps++
				if entry.Tree.Op.IsBatch() {
					chunkOps += len(entry.Tree.Mutations) - 1
				}
			}
			for i := range entry.Controls {
				if _, err := control.Apply(&entry.Controls[i]); err != nil {
					return nil, corruptf("control apply at seq %d: %v", rec.Seq, err)
				}
			}
			next = rec.Seq + 1
			// The record is fully folded (tree leaves AND their exact
			// outcomes); records remain below the cut, so a checkpoint here
			// never leaves a trailing empty transaction.
			if next < cutSeq && (chunkOps >= managedChunkOps || editor.StagedCellBytes() >= stagedThreshold) {
				if err := checkpoint(); err != nil {
					return nil, err
				}
			}
		}
	}
	if hexDigest(chain) != m.Facts.CutDigest {
		return nil, corruptf("folded chain %s does not equal the frozen cut digest %s",
			hexDigest(chain), m.Facts.CutDigest)
	}

	userXattrLeaves, err := buildXattrLeaves(engine.UserXattrs(), m.Spool)
	if err != nil {
		return nil, err
	}
	if err := editor.SetRootXattrLeaves(userXattrLeaves); err != nil {
		return nil, err
	}
	res, err := commitOrEmptyFilesystem(ctx, editor, m.Spool)
	if err != nil {
		return nil, err
	}
	return m.assemble(ctx, res, engine, control, namespace, nextLocal, cutSeq)
}

// commitOrEmptyFilesystem closes one FINAL transaction of a reduction,
// materializing the canonical empty user filesystem when the transaction
// proves the reduction is legitimately empty: no base filesystem root and
// nothing staged. A journal range of pure control records over a rootless
// base reduces to exactly that filesystem, and it is not the
// accidental-empty commit the editor's own guard exists to catch. Interim
// transactions (checkpoint commits, import flushes) never take this path:
// they always follow staged work.
//
// Only the last transaction can be the empty one. A checkpoint requires
// folded tree work (a control-only record advances neither chunkOps nor
// staged cell bytes), and any checkpoint reopens the fold against the
// committed interim root — a base root — so no chunk boundary can create
// this outcome mid-fold or hide it at the end.
func commitOrEmptyFilesystem(
	ctx context.Context, editor *pft2.Editor, store Store,
) (*pft2.CommitResult, error) {
	if editor.EmptyOverEmptyBase() {
		return pft2.BuildEmptyFilesystem(store)
	}
	return editor.Commit(ctx, store, store)
}

// managedStagedByteThreshold is the staged-cell-byte checkpoint trigger:
// the fixed managedChunkBytes under the default editor limits, or half of a
// caller-lowered MaxStagedCellBytes. The boundary check runs after every
// record, so staging can overshoot the threshold by at most ONE record's
// retained cells — bounded by the 8 MiB durable entry cap, far below the
// remaining headroom to the transaction limit under the default 256 MiB cap.
func (m *Materializer) managedStagedByteThreshold() int64 {
	threshold := int64(managedChunkBytes)
	if m.Limits.MaxStagedCellBytes > 0 && m.Limits.MaxStagedCellBytes/2 < threshold {
		threshold = m.Limits.MaxStagedCellBytes / 2
	}
	if threshold < pft2.CellBytes {
		threshold = pft2.CellBytes
	}
	return threshold
}

// applyTreeRow folds one durable tree intent through the shared transition
// engine with EXACTLY the live authority's per-leaf semantics:
//
//   - every deterministic outcome of an ENVELOPE-CARRYING leaf is
//     serialized into the PFC2 control state byte-identically to the
//     outcome the live apply stored and cold replay re-stores, so a
//     duplicate retry against an authority that adopted this cut returns
//     the original status instead of re-executing;
//   - an envelope-less leaf may fail only with the explicitly proven benign
//     replay outcomes (the same set cold replay tolerates); anything else
//     would need environment facts to justify and fails the cut closed.
func (m *Materializer) applyTreeRow(
	ctx context.Context, engine *fstransition.Engine, control *pfc2.State,
	seq uint64, tree wal.Record,
) error {
	leaves := []wal.Record{tree}
	if tree.Op.IsBatch() {
		leaves = tree.Mutations
	}
	outcomes, err := engine.Apply(ctx, tree)
	if err != nil {
		return fmt.Errorf("apply seq %d: %w", seq, err)
	}
	if len(outcomes) != len(leaves) {
		return corruptf("apply seq %d produced %d outcomes for %d leaves", seq, len(outcomes), len(leaves))
	}
	for i := range leaves {
		leaf := &leaves[i]
		out := &outcomes[i]
		if !leaf.Env.Valid() {
			if out.Err != nil && !fstransition.BenignEnvlessOutcome(leaf.Op, leaf.TsMs, out.Err) {
				return corruptf("env-less mutation at seq %d failed deterministically (%v); replay without environment facts cannot prove it benign", seq, out.Err)
			}
			continue
		}
		key, err := exactKeyOf(leaf.Env)
		if err != nil {
			return corruptf("exact envelope at seq %d: %v", seq, err)
		}
		ino, err := engine.ResolveIno(ctx, leaf.Path, leaf.Ino)
		if err != nil {
			return fmt.Errorf("exact outcome resolve at seq %d: %w", seq, err)
		}
		exact := pfc2.Outcome{Status: errnos.Of(out.Err), OrphanIno: out.OrphanIno, Ino: ino}
		if leaf.Op == wal.OpWrite {
			exact.Count = int32(len(leaf.Data))
			// The live authority stores the offset it RESOLVED for the leaf
			// (the ordered-position EOF for O_APPEND); an unresolved target
			// (ENOENT) falls back to the record's own offset there too.
			exact.Offset = leaf.Offset
			if !errors.Is(out.Err, os.ErrNotExist) {
				exact.Offset = out.ResolvedOffset
			}
		}
		if err := control.RecordExternalOutcome(key, exact); err != nil {
			return corruptf("exact outcome at seq %d: %v", seq, err)
		}
	}
	return nil
}

// exactKeyOf mirrors the live authority's managedExactKey exactly.
func exactKeyOf(env *wal.Envelope) (pfc2.ExactKey, error) {
	if env == nil || !env.Valid() {
		return pfc2.ExactKey{}, fmt.Errorf("exact record carries no envelope")
	}
	if len(env.ReqHash) != pfc2.RequestHashBytes {
		return pfc2.ExactKey{}, fmt.Errorf("exact envelope hash is %d bytes", len(env.ReqHash))
	}
	key := pfc2.ExactKey{
		Session: pfc2.SessionRef{SessionID: env.SessionID, Generation: env.Generation},
		Slot:    env.Slot,
		SlotSeq: env.SlotSeq,
	}
	copy(key.RequestHash[:], env.ReqHash)
	return key, nil
}

func (m *Materializer) decodeEntry(rec PageRecord) (pfj3.JournalEntry, error) {
	switch m.Facts.RecordCodec {
	case "pfj3":
		entry, err := pfj3.Decode(rec.Payload)
		if err != nil {
			return pfj3.JournalEntry{}, corruptf("pfj3 decode at seq %d: %v", rec.Seq, err)
		}
		if entry.LSN != rec.Seq {
			return pfj3.JournalEntry{}, corruptf("pfj3 LSN %d disagrees with row seq %d", entry.LSN, rec.Seq)
		}
		return entry, nil
	case "pfr1":
		record, err := wal.DecodePFR1(rec.Payload)
		if err != nil {
			return pfj3.JournalEntry{}, corruptf("pfr1 decode at seq %d: %v", rec.Seq, err)
		}
		record.Seq = rec.Seq
		if record.Op.IsControl() {
			// Legacy PFC1 control payloads carry no PFT2-visible state.
			return pfj3.JournalEntry{LSN: rec.Seq}, nil
		}
		return pfj3.FromLegacyRecord(record), nil
	default:
		return pfj3.JournalEntry{}, corruptf("record codec %q", m.Facts.RecordCodec)
	}
}

func (m *Materializer) openEditor(
	ctx context.Context, baseRoot *pft2.Ref, orphanIndex *pft2.Ref,
	namespace uint32, nextLocal *uint64, maxInoSeen uint64,
) (*pft2.Editor, *fstransition.Engine, error) {
	editor, err := m.reopenEditor(ctx, baseRoot, orphanIndex)
	if err != nil {
		return nil, nil, err
	}
	engine, err := fstransition.New(fstransition.Config{
		Tx: editor,
		Alloc: func() (uint64, error) {
			ino, err := pft2.ComposeIno(namespace, *nextLocal)
			if err != nil {
				return 0, err
			}
			*nextLocal++
			return ino, nil
		},
		FallbackTsMs:   0,
		BaseMaxInoSeen: maxInoSeen,
	})
	if err != nil {
		return nil, nil, err
	}
	return editor, engine, nil
}

// reopenEditor opens a fresh tree transaction over an already-committed root
// (nil = empty base) and orphan index WITHOUT building a new transition
// engine. Checkpointing folds call it with the previous commit's Root and
// OrphanIndex and rebind the surviving engine via Engine.SetTx: the engine's
// cross-record state (orphans, xattrs, allocator watermarks, control
// reduction) lives outside the transaction and must not be rebuilt.
func (m *Materializer) reopenEditor(ctx context.Context, root *pft2.Ref, orphanIndex *pft2.Ref) (*pft2.Editor, error) {
	var reader *pft2.TreeReader
	if root != nil {
		r, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: m.Spool}, *root)
		if err != nil {
			return nil, err
		}
		reader = r
	}
	return pft2.NewEditor(ctx, reader, orphanIndex, m.Limits)
}

// assemble builds the ControlRoot (from the reduced PFC2 state) and the
// RecoveryRoot, then computes the exact user and recovery-only closures.
//
// A newly materialized anchor ALWAYS carries a ControlRoot — an empty
// reduced map included — because NextCheckoutEpoch and DbTimeFloorMs ride
// the root object itself: dropping the node when the map happens to be
// empty would reset checkout epochs and the durable database-time floor on
// the next adoption, letting retired epochs and stale minted times be
// accepted again. A cut with no control history at all (pure legacy import)
// anchors the canonical fresh state (epoch 1, floor 0) explicitly.
func (m *Materializer) assemble(
	ctx context.Context, res *pft2.CommitResult, engine *fstransition.Engine,
	control *pfc2.State, namespace uint32, nextLocal uint64, asOfSeq uint64,
) (*Result, error) {
	if control == nil {
		control = pfc2.NewState()
	}
	projection := control.Project()
	var mapRoot *pft2.Ref
	var counts []pft2.ControlKindCount
	if len(projection.Entries) > 0 {
		entries := make([]pft2.ControlEntry, 0, len(projection.Entries))
		for i := range projection.Entries {
			value, err := pfc2.EncodeEntry(&projection.Entries[i])
			if err != nil {
				return nil, corruptf("control entry encode: %v", err)
			}
			entries = append(entries, pft2.ControlEntry{
				Key:   projection.Entries[i].Key(),
				Kind:  uint64(projection.Entries[i].Kind),
				Value: value,
			})
		}
		builtRoot, _, builtCounts, err := pft2.BuildControlTree(entries, m.Spool)
		if err != nil {
			return nil, err
		}
		mapRoot, counts = builtRoot, builtCounts
	}
	nextEpoch, err := parseU64(string(projection.NextCheckoutEpoch), "next checkout epoch")
	if err != nil {
		return nil, err
	}
	if projection.DbTimeFloorMs < 0 {
		return nil, corruptf("reduced database-time floor %d is negative", projection.DbTimeFloorMs)
	}
	node := &pft2.Node{Kind: pft2.KindControlRoot, ControlRoot: &pft2.ControlRoot{
		Schema:            pft2.ControlSchemaVersion,
		MapRoot:           mapRoot,
		NextCheckoutEpoch: nextEpoch,
		Counts:            counts,
		DbTimeFloorMs:     uint64(projection.DbTimeFloorMs),
	}}
	encoded, err := pft2.EncodeNode(node)
	if err != nil {
		return nil, err
	}
	controlRef := pft2.RefOf(encoded)
	if err := m.Spool.PutNode(controlRef, encoded); err != nil {
		return nil, err
	}
	controlRoot := &controlRef

	// The anchor's allocator cursor must dominate EVERY local this fold
	// observed in the cut's namespace — successes, deterministic failures,
	// and unused reservation members alike — or an authority adopting this
	// anchor could re-issue an identity the retired authority already
	// burned. Deterministic: derived from the base anchor and the folded
	// records only, never from live namespace rows.
	if maxLocal := engine.MaxLocalSeen(namespace); maxLocal >= nextLocal {
		if maxLocal > pft2.MaxInodeLocalCounter {
			return nil, corruptf("observed local counter %d exceeds the namespace cap", maxLocal)
		}
		nextLocal = maxLocal + 1
	}

	maxInoSeen := engine.MaxInoSeen()
	if res.RootFacts.MaxInoSeen > maxInoSeen {
		maxInoSeen = res.RootFacts.MaxInoSeen
	}
	// The user root carries filesystem-homed xattrs so snapshots/forks
	// preserve metadata. RecoveryRoot carries the complete set, including
	// parked open-after-unlink orphans that must survive authority adoption
	// but must never leak into a user snapshot.
	recoveryXattrLeaves, err := buildXattrLeaves(engine.Xattrs(), m.Spool)
	if err != nil {
		return nil, err
	}
	recovery := &pft2.Node{Kind: pft2.KindRecoveryRoot, RecoveryRoot: &pft2.RecoveryRoot{
		AsOfSeq:        asOfSeq,
		FilesystemRoot: res.Root,
		ControlRoot:    controlRoot,
		OrphanIndex:    res.OrphanIndex,
		InoNamespace:   namespace,
		NextLocal:      nextLocal,
		XattrLeaves:    recoveryXattrLeaves,
	}}
	recoveryEncoded, err := pft2.EncodeNode(recovery)
	if err != nil {
		return nil, err
	}
	recoveryRef := pft2.RefOf(recoveryEncoded)
	if err := m.Spool.PutNode(recoveryRef, recoveryEncoded); err != nil {
		return nil, err
	}

	userSet := map[pft2.Ref]uint64{}
	if err := m.closureInto(ctx, res.Root, userSet, nil); err != nil {
		return nil, err
	}
	// The user filesystem tree must never reach an internal recovery object.
	for ref := range userSet {
		if ref == recoveryRef {
			return nil, corruptf("user closure reaches the recovery root")
		}
		if controlRoot != nil && ref == *controlRoot {
			return nil, corruptf("user closure reaches the control root")
		}
	}
	recoverySet := map[pft2.Ref]uint64{}
	if err := m.closureInto(ctx, recoveryRef, recoverySet, userSet); err != nil {
		return nil, err
	}
	userClosure, userBytes := sortedClosure(userSet)
	recoveryClosure, recoveryBytes := sortedClosure(recoverySet)
	return &Result{
		Root:                res.Root,
		RecoveryRoot:        recoveryRef,
		ControlRoot:         controlRoot,
		OrphanIndex:         res.OrphanIndex,
		NextLocal:           nextLocal,
		MaxInoSeen:          maxInoSeen,
		RootMaxInoSeen:      res.RootFacts.MaxInoSeen,
		UserObjectCount:     uint64(len(userClosure)),
		UserObjectBytes:     userBytes,
		UserClosure:         userClosure,
		RecoveryObjectCount: uint64(len(recoveryClosure)),
		RecoveryObjectBytes: recoveryBytes,
		RecoveryClosure:     recoveryClosure,
	}, nil
}

// buildXattrLeaves chunks the fold's live (ino, name, value) rows — already
// sorted by Engine.Xattrs — into canonical XATTR_LEAF nodes. Deterministic
// boundaries: a leaf closes at MaxLeafEntries entries or when its encoded
// payload estimate reaches TargetNodeBytes, whichever first, so identical
// inputs always produce identical objects (crash-resume reproducibility).
func buildXattrLeaves(rows []fstransition.XattrRow, sink Store) ([]pft2.Ref, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	var refs []pft2.Ref
	var entries []pft2.XattrEntry
	var pending int
	flush := func() error {
		if len(entries) == 0 {
			return nil
		}
		node := &pft2.Node{Kind: pft2.KindXattrLeaf, XattrLeaf: &pft2.XattrLeaf{Entries: entries}}
		encoded, err := pft2.EncodeNode(node)
		if err != nil {
			return err
		}
		ref := pft2.RefOf(encoded)
		if err := sink.PutNode(ref, encoded); err != nil {
			return err
		}
		refs = append(refs, ref)
		entries, pending = nil, 0
		return nil
	}
	for _, row := range rows {
		// Conservative per-entry framing estimate (tag/length bytes + ino
		// varint), mirroring the builder discipline elsewhere.
		size := len(row.Name) + len(row.Value) + 32
		if len(entries) > 0 && (len(entries) >= pft2.MaxLeafEntries || pending+size > pft2.TargetNodeBytes) {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		entries = append(entries, pft2.XattrEntry{Ino: row.Ino, Name: row.Name, Value: append([]byte(nil), row.Value...)})
		pending += size
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return refs, nil
}

// closureInto walks the exact object graph from root (every edge re-verified
// by decode) into out, skipping members of exclude (already accounted to the
// other closure).
func (m *Materializer) closureInto(
	ctx context.Context, root pft2.Ref, out map[pft2.Ref]uint64, exclude map[pft2.Ref]uint64,
) error {
	var visit func(ref pft2.Ref) error
	visit = func(ref pft2.Ref) error {
		if _, ok := out[ref]; ok {
			return nil
		}
		if exclude != nil {
			if _, ok := exclude[ref]; ok {
				return nil
			}
		}
		raw, err := m.Spool.Fetch(ctx, ref)
		if err != nil {
			return err
		}
		out[ref] = uint64(len(raw))
		node, err := pft2.DecodeNode(raw)
		if err != nil {
			// Packed data objects are opaque leaves.
			return nil
		}
		for _, child := range nodeChildren(node) {
			if err := visit(child); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(root)
}

func sortedClosure(set map[pft2.Ref]uint64) ([]string, uint64) {
	out := make([]string, 0, len(set))
	var total uint64
	for ref, size := range set {
		out = append(out, "sha256:"+ref.Hex())
		total += size
	}
	sort.Strings(out)
	return out, total
}

// nodeChildren enumerates every outgoing object reference of a node.
func nodeChildren(n *pft2.Node) []pft2.Ref {
	var out []pft2.Ref
	switch n.Kind {
	case pft2.KindRoot:
		out = append(out, n.Root.InodeIndex)
		out = append(out, n.Root.XattrLeaves...)
	case pft2.KindRecoveryRoot:
		out = append(out, n.RecoveryRoot.FilesystemRoot)
		if n.RecoveryRoot.ControlRoot != nil {
			out = append(out, *n.RecoveryRoot.ControlRoot)
		}
		if n.RecoveryRoot.OrphanIndex != nil {
			out = append(out, *n.RecoveryRoot.OrphanIndex)
		}
		out = append(out, n.RecoveryRoot.XattrLeaves...)
	case pft2.KindControlRoot:
		if n.ControlRoot.MapRoot != nil {
			out = append(out, *n.ControlRoot.MapRoot)
		}
	case pft2.KindControlIndex:
		for _, c := range n.ControlIndex.Children {
			out = append(out, c.Child)
		}
	case pft2.KindInode:
		if n.Inode.DirectoryRoot != nil {
			out = append(out, *n.Inode.DirectoryRoot)
		}
		if n.Inode.ExtentRoot != nil {
			out = append(out, *n.Inode.ExtentRoot)
		}
	case pft2.KindDirectoryIndex:
		for _, c := range n.DirectoryIndex.Children {
			out = append(out, c.Child)
		}
	case pft2.KindExtentLeaf:
		for _, e := range n.ExtentLeaf.Entries {
			out = append(out, e.Page)
		}
	case pft2.KindExtentIndex:
		for _, c := range n.ExtentIndex.Children {
			out = append(out, c.Child)
		}
	case pft2.KindInodeIndexLeaf:
		for _, e := range n.InodeIndexLeaf.Entries {
			out = append(out, e.Inode)
		}
	case pft2.KindInodeIndexIndex:
		for _, c := range n.InodeIndexIndex.Children {
			out = append(out, c.Child)
		}
	case pft2.KindDataPage:
		for _, cell := range n.DataPage.Cells {
			if cell != nil {
				out = append(out, cell.Object)
			}
		}
	}
	return out
}

func refFromParts(digestHex, sizeStr string) (pft2.Ref, error) {
	raw, err := parseHex32(digestHex, "object digest")
	if err != nil {
		return pft2.Ref{}, err
	}
	size, err := parseU64(sizeStr, "object size")
	if err != nil {
		return pft2.Ref{}, err
	}
	return pft2.Ref{Digest: raw, Size: size}, nil
}

// ─── legacy manifest import ──────────────────────────────────────────────────

// importCursor is the durable resume point of one conversion import.
type importCursor struct {
	AfterOrd   int64  `json:"afterOrd"`
	RootHex    string `json:"rootHex,omitempty"`
	RootSize   uint64 `json:"rootSize,omitempty"`
	NextLocal  uint64 `json:"nextLocal"`
	MaxInoSeen uint64 `json:"maxInoSeen"`
}

type chunkRef struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Offset int64  `json:"offset"`
}

// runLegacy streams the finalized resolved entries into a PFT2 tree with
// bounded chunked commits, verifies every content fact, recomputes the exact
// canonical tree hash, and (for a pfr1 conversion) leaves the imported tree
// as the base for journal folding.
func (m *Materializer) runLegacy(ctx context.Context, asOfSeq uint64) (*Result, error) {
	namespace, err := m.Facts.namespace()
	if err != nil {
		return nil, err
	}

	cursor := importCursor{AfterOrd: -1, NextLocal: 1}
	if m.Facts.NamespaceNext != "" {
		if v, err := parseU64(m.Facts.NamespaceNext, "namespaceNextLocal"); err == nil && v > 0 {
			cursor.NextLocal = v
		}
	}
	if raw, err := m.Legacy.ImportCursor(ctx); err != nil {
		return nil, err
	} else if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &cursor); err != nil {
			return nil, corruptf("import cursor decode: %v", err)
		}
	}

	var baseRoot *pft2.Ref
	if cursor.RootHex != "" {
		ref, err := refFromParts(cursor.RootHex, strconv.FormatUint(cursor.RootSize, 10))
		if err != nil {
			return nil, err
		}
		baseRoot = &ref
	}

	// Streaming tree hash: entries arrive in ascending byte order (the
	// COLLATE "C" ordinal order), so per-shard hashes fold incrementally —
	// bounded memory regardless of entry count.
	hashStream := treehash.NewStreaming()
	inoFirstPath := map[uint64]string{}

	editor, engine, err := m.openEditor(ctx, baseRoot, nil, namespace, &cursor.NextLocal, cursor.MaxInoSeen)
	if err != nil {
		return nil, err
	}
	chunkOps := 0
	chunkBytes := int64(0)

	flush := func() error {
		res, err := editor.Commit(ctx, m.Spool, m.Spool)
		if err != nil {
			return err
		}
		cursor.RootHex = res.Root.Hex()
		cursor.RootSize = res.Root.Size
		cursor.MaxInoSeen = engine.MaxInoSeen()
		raw, err := json.Marshal(&cursor)
		if err != nil {
			return err
		}
		if err := m.Legacy.PutImportCursor(ctx, raw); err != nil {
			return err
		}
		editor, engine, err = m.openEditor(ctx, &res.Root, nil, namespace, &cursor.NextLocal, cursor.MaxInoSeen)
		if err != nil {
			return err
		}
		chunkOps, chunkBytes = 0, 0
		return nil
	}

	// One pass over the FULL stream: every non-synthetic entry feeds the
	// canonical tree hash incrementally (the hash must cover the whole
	// resolved manifest on every run, resume included — never buffered
	// content, bounded shard state); entries beyond the durable cursor
	// import into the tree.
	imported := false
	streamAfter := int64(-1)
	for {
		page, err := m.Legacy.EntriesPage(ctx, streamAfter, legacyEntryPage)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		for i := range page {
			entry := &page[i]
			streamAfter = entry.Ord
			if !entry.Synthetic {
				if err := hashStream.Add(hashEntryOf(entry)); err != nil {
					return nil, corruptf("tree hash stream: %v", err)
				}
			}
			if entry.Ord <= cursor.AfterOrd {
				// Already imported into the flushed root; aliases still need
				// their first-path registration for later occurrences.
				if _, seen := inoFirstPath[entry.AssignedIno]; !seen && entry.AssignedIno != 0 {
					inoFirstPath[entry.AssignedIno] = entry.Path
				}
				continue
			}
			written, err := m.importEntry(ctx, engine, editor, entry, inoFirstPath)
			if err != nil {
				return nil, err
			}
			imported = true
			cursor.AfterOrd = entry.Ord
			chunkOps++
			chunkBytes += written
			if chunkOps >= importChunkOps || chunkBytes >= importChunkBytes {
				if err := flush(); err != nil {
					return nil, err
				}
			}
		}
	}

	// The recomputed canonical tree hash proves the resolved stream matches
	// the pinned anchor commit exactly (synthetic ancestors excluded).
	treeHash := hashStream.Root()
	if err := m.Legacy.VerifyTreeHash(ctx, treeHash); err != nil {
		return nil, err
	}

	// An EMPTY resolved manifest (zero entries, no prior flush, no base)
	// still converts to a valid filesystem: the root directory alone.
	// Without this the editor refuses the empty transaction and an empty
	// adopted branch could never enter journal service. Timestamp 0 keeps
	// the reduction deterministic across workers and retries.
	if !imported && baseRoot == nil && cursor.RootHex == "" {
		if err := engine.EnsureRoot(ctx, 0); err != nil {
			return nil, err
		}
	}

	res, err := editor.Commit(ctx, m.Spool, m.Spool)
	if err != nil {
		return nil, err
	}
	cursor.RootHex = res.Root.Hex()
	cursor.RootSize = res.Root.Size
	cursor.MaxInoSeen = engine.MaxInoSeen()
	if raw, err := json.Marshal(&cursor); err == nil {
		if err := m.Legacy.PutImportCursor(ctx, raw); err != nil {
			return nil, err
		}
	}
	return m.assemble(ctx, res, engine, nil, namespace, cursor.NextLocal, asOfSeq)
}

func hashEntryOf(e *LegacyEntry) treehash.Entry {
	out := treehash.Entry{
		Path:       e.Path,
		Kind:       e.Kind,
		Mode:       e.Mode,
		Size:       int64(e.Size),
		Executable: e.Executable,
		LinkTarget: e.LinkTarget,
		UID:        e.UID,
		GID:        e.GID,
	}
	if e.BlobDigest != "" {
		out.Blob = &treehash.Blob{
			Digest:      e.BlobDigest,
			Size:        e.BlobSize,
			Compression: e.Compression,
			Packed:      e.Packed,
		}
	}
	if len(e.ChunksJSON) > 0 {
		var chunks []chunkRef
		if err := json.Unmarshal(e.ChunksJSON, &chunks); err == nil {
			for _, c := range chunks {
				out.Chunks = append(out.Chunks, treehash.Chunk{
					Digest: c.Digest, Size: c.Size, Offset: c.Offset,
				})
			}
		}
	}
	return out
}

// importEntry folds one resolved entry through the SHARED transition engine
// (identical create/mkdir/link/nlink semantics as journal replay) and then
// pins the exact manifest metadata. Returns staged content bytes.
func (m *Materializer) importEntry(
	ctx context.Context, engine *fstransition.Engine, editor *pft2.Editor,
	entry *LegacyEntry, inoFirstPath map[uint64]string,
) (int64, error) {
	if entry.AssignedIno == 0 {
		return 0, corruptf("entry %q has no assigned inode", entry.Path)
	}
	parent, name := splitParent(entry.Path)
	tsMs := entry.MtimeMs

	// Crash/resume idempotency: a rerun since the last flushed cursor may
	// replay entries the flushed root already contains. The existing name is
	// accepted iff it carries the exact assigned inode; anything else is
	// definite corruption.
	verifyExisting := func() error {
		existing, ok, err := editor.GetDirEntry(ctx, parentIno(ctx, editor, parent), name)
		if err != nil {
			return err
		}
		if !ok || existing.Ino != entry.AssignedIno {
			return corruptf("import %q: name exists with inode %d, want %d",
				entry.Path, existing.Ino, entry.AssignedIno)
		}
		return nil
	}

	if first, aliased := inoFirstPath[entry.AssignedIno]; aliased {
		// Hardlink alias: identical identity was verified in the database;
		// the alias shares content and metadata, nlink accumulates.
		if entry.Kind == "directory" {
			return 0, corruptf("directory %q aliases ino %d (first %q)", entry.Path, entry.AssignedIno, first)
		}
		if err := engine.Link(ctx, parent, name, entry.AssignedIno, tsMs); err != nil {
			if errors.Is(err, fstransition.ErrExist) {
				return 0, verifyExisting()
			}
			return 0, fmt.Errorf("alias %q of %q: %w", entry.Path, first, err)
		}
		return 0, nil
	}
	inoFirstPath[entry.AssignedIno] = entry.Path

	rec := wal.Record{Path: entry.Path, Ino: entry.AssignedIno, TsMs: tsMs, Mode: entry.Mode, Excl: true}
	switch entry.Kind {
	case "directory":
		rec.Op = wal.OpMkdir
	case "file":
		rec.Op = wal.OpCreate
	case "symlink":
		rec.Op = wal.OpSymlink
		rec.Target = entry.LinkTarget
		if entry.LinkTarget == "" {
			return 0, corruptf("symlink %q has an empty target", entry.Path)
		}
	default:
		return 0, corruptf("entry %q kind %q", entry.Path, entry.Kind)
	}
	outs, err := engine.Apply(ctx, rec)
	if err != nil {
		return 0, err
	}
	if outs[0].Err != nil {
		if errors.Is(outs[0].Err, fstransition.ErrExist) {
			if err := verifyExisting(); err != nil {
				return 0, err
			}
		} else {
			return 0, corruptf("import %q: %v", entry.Path, outs[0].Err)
		}
	}

	// Exact manifest metadata (times, ownership, mode) on the new inode.
	meta, ok, err := editor.GetInode(ctx, entry.AssignedIno)
	if err != nil || !ok {
		return 0, corruptf("imported inode %d not live: %v", entry.AssignedIno, err)
	}
	meta.Mode = entry.Mode & 0o7777
	meta.UID = entry.UID
	meta.GID = entry.GID
	meta.MtimeMs = entry.MtimeMs
	meta.CtimeMs = entry.CtimeMs
	meta.AtimeMs = entry.AtimeMs
	if err := editor.PutInode(ctx, meta); err != nil {
		return 0, err
	}

	if entry.Kind != "file" || entry.Size == 0 {
		if entry.Kind == "file" {
			if err := editor.SetFileSize(ctx, entry.AssignedIno, 0); err != nil {
				return 0, err
			}
		}
		return 0, nil
	}
	return m.importFileContent(ctx, editor, entry)
}

// importFileContent streams the file bytes (whole blob or chunk refs, gzip
// decompressed when flagged) into 4 KiB cells, verifying every digest, size,
// and offset fact. All-zero cells become holes automatically.
func (m *Materializer) importFileContent(ctx context.Context, editor *pft2.Editor, entry *LegacyEntry) (int64, error) {
	fullHash := sha256.New()
	var written int64
	writeAt := func(offset int64, data []byte) error {
		pos := uint64(offset)
		remaining := data
		for len(remaining) > 0 {
			cellStart := pos - (pos % pft2.CellBytes)
			in := int(pos - cellStart)
			n := pft2.CellBytes - in
			if n > len(remaining) {
				n = len(remaining)
			}
			cell := remaining[:n]
			if in != 0 || n != pft2.CellBytes {
				merged, err := editor.ReadCell(ctx, entry.AssignedIno, cellStart)
				if err != nil {
					return err
				}
				buf := make([]byte, pft2.CellBytes)
				copy(buf, merged)
				copy(buf[in:], cell)
				cell = buf
			}
			if err := editor.WriteCell(ctx, entry.AssignedIno, cellStart, cell); err != nil {
				return err
			}
			pos += uint64(n)
			remaining = remaining[n:]
			written += int64(n)
		}
		return nil
	}

	if len(entry.ChunksJSON) > 0 {
		var chunks []chunkRef
		if err := json.Unmarshal(entry.ChunksJSON, &chunks); err != nil {
			return 0, corruptf("entry %q chunk refs: %v", entry.Path, err)
		}
		if len(chunks) > maxChunksPerFile {
			return 0, corruptf("entry %q has %d chunks (bound %d)", entry.Path, len(chunks), maxChunksPerFile)
		}
		sort.Slice(chunks, func(i, j int) bool { return chunks[i].Offset < chunks[j].Offset })
		expected := int64(0)
		for _, c := range chunks {
			if c.Offset != expected {
				return 0, corruptf("entry %q chunk offsets are not contiguous at %d", entry.Path, c.Offset)
			}
			data, err := m.Blobs.Blob(ctx, c.Digest, c.Size)
			if err != nil {
				return written, err
			}
			if int64(len(data)) != c.Size || "sha256:"+hexDigest(sha256.Sum256(data)) != c.Digest {
				return 0, corruptf("entry %q chunk %s facts mismatch", entry.Path, c.Digest)
			}
			fullHash.Write(data)
			if err := writeAt(c.Offset, data); err != nil {
				return written, err
			}
			expected += c.Size
		}
		if uint64(expected) != entry.Size {
			return 0, corruptf("entry %q chunked size %d, manifest says %d", entry.Path, expected, entry.Size)
		}
		full := "sha256:" + hexDigest(sha256FromHash(fullHash))
		if entry.BlobDigest != "" && full != entry.BlobDigest {
			return 0, corruptf("entry %q chunked content hash %s, manifest blob %s", entry.Path, full, entry.BlobDigest)
		}
	} else {
		if entry.BlobDigest == "" {
			return 0, corruptf("file entry %q has neither blob nor chunks", entry.Path)
		}
		stored, err := m.Blobs.Blob(ctx, entry.BlobDigest, entry.BlobSize)
		if err != nil {
			return written, err
		}
		if "sha256:"+hexDigest(sha256.Sum256(stored)) != entry.BlobDigest {
			return 0, corruptf("entry %q stored blob hash mismatch", entry.Path)
		}
		data := stored
		if entry.Compression == "gzip" {
			data, err = gunzipBounded(stored, int64(entry.Size))
			if err != nil {
				return 0, corruptf("entry %q gzip: %v", entry.Path, err)
			}
		}
		if uint64(len(data)) != entry.Size {
			return 0, corruptf("entry %q content is %d bytes, manifest says %d", entry.Path, len(data), entry.Size)
		}
		if err := writeAt(0, data); err != nil {
			return written, err
		}
	}
	if err := editor.SetFileSize(ctx, entry.AssignedIno, entry.Size); err != nil {
		return written, err
	}
	return written, nil
}

func addProjectionCount(c *pfc2.ProjectionCounts, kind pfc2.EntryKind) {
	switch kind {
	case pfc2.EntrySession:
		c.Sessions++
	case pfc2.EntryTombstone:
		c.Tombstones++
	case pfc2.EntrySlot:
		c.Slots++
	case pfc2.EntryLock:
		c.Locks++
	case pfc2.EntryCheckout:
		c.Checkouts++
	case pfc2.EntryPin:
		c.Pins++
	case pfc2.EntryFlush:
		c.Flushes++
	}
}

func sha256FromHash(h interface{ Sum([]byte) []byte }) [32]byte {
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// gunzipBounded decompresses with an exact expected-size bound (plus one
// byte to detect overrun), refusing decompression bombs.
func gunzipBounded(compressed []byte, expected int64) ([]byte, error) {
	if expected < 0 || expected > maxGzipBlobBytes {
		return nil, fmt.Errorf("expected size %d outside bounds", expected)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := make([]byte, 0, expected)
	buf := make([]byte, 64<<10)
	for {
		n, err := zr.Read(buf)
		out = append(out, buf[:n]...)
		if int64(len(out)) > expected {
			return nil, fmt.Errorf("decompressed beyond the declared %d bytes", expected)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func splitParent(path string) (string, string) {
	idx := strings.LastIndexByte(path, '/')
	if idx < 0 {
		return "", path
	}
	return path[:idx], path[idx+1:]
}

// parentIno resolves a directory path to its inode by walking dirents from
// the root. Import order (path-sorted, parents synthesized) guarantees the
// chain exists; a broken chain is corruption and surfaces as ino 0.
func parentIno(ctx context.Context, editor *pft2.Editor, dir string) uint64 {
	cur := pft2.RootIno
	if dir == "" {
		return cur
	}
	for _, part := range strings.Split(dir, "/") {
		entry, ok, err := editor.GetDirEntry(ctx, cur, part)
		if err != nil || !ok {
			return 0
		}
		cur = entry.Ino
	}
	return cur
}
