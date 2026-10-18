package lantrace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Schema is the stream grammar version carried by every header. A change that
// alters the meaning of an existing key gets a new schema string.
const Schema = "pfs-lan-trace-1"

const (
	// MaxLineBytes bounds one record including its newline. The largest legal
	// event is well under half of it; see TestLargestEventFitsOneLine.
	MaxLineBytes = 4096
	// MaxNameBytes is the decoded bound of name_hex, the POSIX NAME_MAX.
	MaxNameBytes = 255
	// MaxLabelBytes bounds every opaque label.
	MaxLabelBytes = 64
	// MaxNanos bounds every nanosecond value so it stays exact in any JSON
	// consumer that parses numbers as IEEE doubles (about 104 days).
	MaxNanos Nanos = 1<<53 - 1
	// MaxErrno bounds errno to the range every supported kernel uses.
	MaxErrno Errno = 4095
	// MaxStreams bounds the producer streams of one collection.
	MaxStreams = 64
)

// Label is a short opaque identifier: a letter followed by up to 63 letters,
// digits, '.', '_', ':' or '-'. Spaces, slashes and every other byte are
// rejected, so a label cannot hold free text or a multi-component path. It
// can still hold any short string in that alphabet; keeping secrets out of
// labels is the producer content rule, not something validation can prove.
type Label string

func (l Label) valid() bool {
	if len(l) == 0 || len(l) > MaxLabelBytes {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// NameHex is one raw directory-entry name from the authorized synthetic
// corpus, encoded as lowercase hex: even length, 1 to MaxNameBytes bytes.
type NameHex string

func (n NameHex) valid() bool {
	if len(n) == 0 || len(n)%2 != 0 || len(n) > 2*MaxNameBytes {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// EncodeName returns the name_hex encoding of raw, or an error when raw is
// empty or longer than MaxNameBytes.
func EncodeName(raw []byte) (NameHex, error) {
	if len(raw) == 0 || len(raw) > MaxNameBytes {
		return "", fmt.Errorf("lantrace: name must be 1 to %d bytes", MaxNameBytes)
	}
	return NameHex(hex.EncodeToString(raw)), nil
}

// Nanos is a duration or monotonic offset in nanoseconds, at most MaxNanos.
type Nanos uint64

func (n Nanos) valid() bool { return n <= MaxNanos }

// Errno is a kernel error number, at most MaxErrno.
type Errno uint16

func (e Errno) valid() bool { return e <= MaxErrno }

// OpaqueLabel derives the run-local label prefix-<16 hex> from a non-secret
// identity, such as an authority session ID. Producers on both sides of a
// join derive the same label from the same identity without logging it, and
// the run label keeps it from correlating across runs. Never pass a secret,
// token or capability as identity.
func OpaqueLabel(prefix string, run Label, identity []byte) (Label, error) {
	if len(prefix) == 0 || len(prefix) > 8 || !Label(prefix).valid() {
		return "", errors.New("lantrace: label prefix must be a label of at most 8 bytes")
	}
	if !run.valid() {
		return "", errors.New("lantrace: invalid run label")
	}
	if len(identity) == 0 {
		return "", errors.New("lantrace: empty identity")
	}
	h := sha256.New()
	h.Write([]byte(run))
	h.Write([]byte{0})
	h.Write(identity)
	return Label(prefix + "-" + hex.EncodeToString(h.Sum(nil)[:8])), nil
}

// enum is a closed set of category strings in declaration order.
type enum[T ~string] struct {
	ordered []T
	set     map[T]struct{}
}

func newEnum[T ~string](values ...T) enum[T] {
	e := enum[T]{ordered: values, set: make(map[T]struct{}, len(values))}
	for _, v := range values {
		e.set[v] = struct{}{}
	}
	return e
}

func (e enum[T]) has(v T) bool { _, ok := e.set[v]; return ok }

// Layer names the producer process class of a stream.
type Layer string

const (
	LayerFrontend    Layer = "frontend"     // Swift FSKit extension
	LayerDaemon      Layer = "daemon"       // Go portablefsd data plane
	LayerAuthority   Layer = "authority"    // Go XFS authority
	LayerLinuxClient Layer = "linux_client" // Go kernel-FUSE mount client
)

var layers = newEnum(LayerFrontend, LayerDaemon, LayerAuthority, LayerLinuxClient)

func (v Layer) valid() bool { return layers.has(v) }

// Kind names what an event records. The rules table fixes its fields.
type Kind string

const (
	KindCallback     Kind = "callback"      // framework callback entry, reply and publication completion
	KindLocal        Kind = "local"         // one pfslocal request's lifecycle
	KindCache        Kind = "cache"         // daemon cache candidate or final exposure decision
	KindSource       Kind = "source"        // daemon source-publication lifetime of one callback
	KindOpen         Kind = "open"          // OPEN attribution, including avoided OPENs
	KindRelease      Kind = "release"       // final Close or Reclaim of one resource
	KindReleaseBatch Kind = "release_batch" // Close/Reclaim batch formation, send, ack and transfer
	KindAuthority    Kind = "authority"     // one authority request turn
	KindBarrier      Kind = "barrier"       // durability barrier selected for one mutation
	KindSyscall      Kind = "syscall"       // one physical durability syscall
	KindWait         Kind = "wait"          // one completed wait
	KindOccupancy    Kind = "occupancy"     // resource occupancy sample or final inventory
	KindMkdirWitness Kind = "mkdir_witness" // MKDIR child-search witness and seeding decision
	KindRenewal      Kind = "renewal"       // one session renewal
	KindSuperblock   Kind = "superblock"    // dirty-load condition of one storage superblock
)

var kinds = newEnum(KindCallback, KindLocal, KindCache, KindSource, KindOpen, KindRelease,
	KindReleaseBatch, KindAuthority, KindBarrier, KindSyscall, KindWait, KindOccupancy,
	KindMkdirWitness, KindRenewal, KindSuperblock)

func (v Kind) valid() bool { return kinds.has(v) }

// Phase names the point in a kind's lifecycle an event marks.
type Phase string

const (
	PhaseEntry               Phase = "entry"                // callback entered
	PhaseReply               Phase = "reply"                // callback replied; daemon wrote or frontend read a reply; authority replied
	PhasePublicationComplete Phase = "publication_complete" // frontend sent the callback's PublicationAck
	PhaseSend                Phase = "send"                 // request written to its transport
	PhaseEnqueue             Phase = "enqueue"              // daemon read a pfslocal request and queued it
	PhaseDispatch            Phase = "dispatch"             // daemon began executing a request
	PhaseOutcome             Phase = "outcome"              // daemon determined a request's result
	PhaseExposure            Phase = "exposure"             // daemon made the final exposure decision
	PhaseDisposition         Phase = "disposition"          // ResourceReplyDisposition sent or received
	PhaseReceive             Phase = "receive"              // client received a reply; authority received a request
	PhaseCandidate           Phase = "candidate"            // cache candidate evaluated
	PhaseFinal               Phase = "final"                // final cache exposure; final inventory
	PhaseAcquire             Phase = "acquire"              // source acquired
	PhaseActiveInc           Phase = "active_inc"           // active-request count incremented
	PhaseActiveDec           Phase = "active_dec"           // active-request count decremented
	PhasePostState           Phase = "post_state"           // PostState applied
	PhaseClaimSettled        Phase = "claim_settled"        // claim settled
	PhaseAck                 Phase = "ack"                  // PublicationAck arrived
	PhaseRelease             Phase = "release"              // source released
	PhaseForming             Phase = "forming"              // release batch began forming
	PhaseSent                Phase = "sent"                 // release batch sent
	PhaseAcked               Phase = "acked"                // release batch acknowledged
	PhaseTransferred         Phase = "transferred"          // release ownership transferred
	PhaseSample              Phase = "sample"               // occupancy sample
)

var phases = newEnum(PhaseEntry, PhaseReply, PhasePublicationComplete, PhaseSend, PhaseEnqueue,
	PhaseDispatch, PhaseOutcome, PhaseExposure, PhaseDisposition, PhaseReceive, PhaseCandidate,
	PhaseFinal, PhaseAcquire, PhaseActiveInc, PhaseActiveDec, PhasePostState, PhaseClaimSettled,
	PhaseAck, PhaseRelease, PhaseForming, PhaseSent, PhaseAcked, PhaseTransferred, PhaseSample)

func (v Phase) valid() bool { return phases.has(v) }

// CallbackKind names a framework callback. Linux FUSE operations map onto the
// same names (opendir to open, release to close, forget to reclaim, readdir to
// enumerate, unlink and rmdir to remove, fsync to synchronize).
type CallbackKind string

const (
	CallbackActivate      CallbackKind = "activate"
	CallbackDeactivate    CallbackKind = "deactivate"
	CallbackMount         CallbackKind = "mount"
	CallbackUnmount       CallbackKind = "unmount"
	CallbackSynchronize   CallbackKind = "synchronize"
	CallbackGetAttr       CallbackKind = "get_attr"
	CallbackSetAttr       CallbackKind = "set_attr"
	CallbackLookup        CallbackKind = "lookup"
	CallbackReclaim       CallbackKind = "reclaim"
	CallbackReadlink      CallbackKind = "readlink"
	CallbackCreate        CallbackKind = "create"
	CallbackMkdir         CallbackKind = "mkdir"
	CallbackSymlink       CallbackKind = "symlink"
	CallbackLink          CallbackKind = "link"
	CallbackRemove        CallbackKind = "remove"
	CallbackRename        CallbackKind = "rename"
	CallbackEnumerate     CallbackKind = "enumerate"
	CallbackOpen          CallbackKind = "open"
	CallbackClose         CallbackKind = "close"
	CallbackRead          CallbackKind = "read"
	CallbackWrite         CallbackKind = "write"
	CallbackXattrGet      CallbackKind = "xattr_get"
	CallbackXattrSet      CallbackKind = "xattr_set"
	CallbackXattrList     CallbackKind = "xattr_list"
	CallbackStatfs        CallbackKind = "statfs"
	CallbackFlush         CallbackKind = "flush"
	CallbackFallocate     CallbackKind = "fallocate"
	CallbackCopyFileRange CallbackKind = "copy_file_range"
	CallbackLock          CallbackKind = "lock"
)

var callbackKinds = newEnum(CallbackActivate, CallbackDeactivate, CallbackMount, CallbackUnmount,
	CallbackSynchronize, CallbackGetAttr, CallbackSetAttr, CallbackLookup, CallbackReclaim,
	CallbackReadlink, CallbackCreate, CallbackMkdir, CallbackSymlink, CallbackLink, CallbackRemove,
	CallbackRename, CallbackEnumerate, CallbackOpen, CallbackClose, CallbackRead, CallbackWrite,
	CallbackXattrGet, CallbackXattrSet, CallbackXattrList, CallbackStatfs, CallbackFlush,
	CallbackFallocate, CallbackCopyFileRange, CallbackLock)

func (v CallbackKind) valid() bool { return callbackKinds.has(v) }

// Origin separates framework GetAttr from GetAttr work the frontend generates
// itself for enumeration or "..".
type Origin string

const (
	OriginFramework            Origin = "framework"
	OriginSyntheticEnumeration Origin = "synthetic_enumeration"
	OriginSyntheticDotDot      Origin = "synthetic_dotdot"
)

var origins = newEnum(OriginFramework, OriginSyntheticEnumeration, OriginSyntheticDotDot)

func (v Origin) valid() bool { return origins.has(v) }

// LocalOp names a pfslocal request body (pfslocal/pfslocal.proto Envelope).
// PublicationAck and ResourceReplyDisposition are recorded as phases.
type LocalOp string

const (
	LocalHello            LocalOp = "hello"
	LocalResolve          LocalOp = "resolve"
	LocalLookup           LocalOp = "lookup"
	LocalGetAttr          LocalOp = "get_attr"
	LocalSetAttr          LocalOp = "set_attr"
	LocalOpen             LocalOp = "open"
	LocalClose            LocalOp = "close"
	LocalRead             LocalOp = "read"
	LocalWrite            LocalOp = "write"
	LocalCreate           LocalOp = "create"
	LocalMkdir            LocalOp = "mkdir"
	LocalRemove           LocalOp = "remove"
	LocalRename           LocalOp = "rename"
	LocalSymlink          LocalOp = "symlink"
	LocalReadlink         LocalOp = "readlink"
	LocalXattrGet         LocalOp = "xattr_get"
	LocalXattrList        LocalOp = "xattr_list"
	LocalXattrRemove      LocalOp = "xattr_remove"
	LocalStatfs           LocalOp = "statfs"
	LocalReclaim          LocalOp = "reclaim"
	LocalSubscribeEvents  LocalOp = "subscribe_events"
	LocalHardLink         LocalOp = "hard_link"
	LocalSyncVolume       LocalOp = "sync_volume"
	LocalEnumerateEntries LocalOp = "enumerate_entries"
)

var localOps = newEnum(LocalHello, LocalResolve, LocalLookup, LocalGetAttr, LocalSetAttr, LocalOpen,
	LocalClose, LocalRead, LocalWrite, LocalCreate, LocalMkdir, LocalRemove, LocalRename, LocalSymlink,
	LocalReadlink, LocalXattrGet, LocalXattrList, LocalXattrRemove, LocalStatfs, LocalReclaim,
	LocalSubscribeEvents, LocalHardLink, LocalSyncVolume, LocalEnumerateEntries)

func (v LocalOp) valid() bool { return localOps.has(v) }

// AuthorityOp names an authority request body (proto/authority/v1 Request).
type AuthorityOp string

const (
	AuthorityHello                   AuthorityOp = "hello"
	AuthorityAttach                  AuthorityOp = "attach"
	AuthorityResume                  AuthorityOp = "resume"
	AuthorityKeepAlive               AuthorityOp = "keep_alive"
	AuthorityDetach                  AuthorityOp = "detach"
	AuthorityCancel                  AuthorityOp = "cancel"
	AuthorityReauthorize             AuthorityOp = "reauthorize"
	AuthorityLookup                  AuthorityOp = "lookup"
	AuthorityGetAttr                 AuthorityOp = "get_attr"
	AuthoritySetAttr                 AuthorityOp = "set_attr"
	AuthorityCreate                  AuthorityOp = "create"
	AuthorityMkdir                   AuthorityOp = "mkdir"
	AuthorityUnlink                  AuthorityOp = "unlink"
	AuthorityRename                  AuthorityOp = "rename"
	AuthorityLink                    AuthorityOp = "link"
	AuthoritySymlink                 AuthorityOp = "symlink"
	AuthorityReadlink                AuthorityOp = "readlink"
	AuthorityOpen                    AuthorityOp = "open"
	AuthorityClose                   AuthorityOp = "close"
	AuthorityRead                    AuthorityOp = "read"
	AuthorityFsync                   AuthorityOp = "fsync"
	AuthorityReadDir                 AuthorityOp = "read_dir"
	AuthorityReclaim                 AuthorityOp = "reclaim"
	AuthorityFlush                   AuthorityOp = "flush"
	AuthorityGetXattr                AuthorityOp = "get_xattr"
	AuthoritySetXattr                AuthorityOp = "set_xattr"
	AuthorityListXattr               AuthorityOp = "list_xattr"
	AuthorityRemoveXattr             AuthorityOp = "remove_xattr"
	AuthorityStatFS                  AuthorityOp = "stat_fs"
	AuthoritySyncFS                  AuthorityOp = "sync_fs"
	AuthorityFallocate               AuthorityOp = "fallocate"
	AuthorityCopyFileRange           AuthorityOp = "copy_file_range"
	AuthorityTmpfile                 AuthorityOp = "tmpfile"
	AuthorityGetLock                 AuthorityOp = "get_lock"
	AuthoritySetLock                 AuthorityOp = "set_lock"
	AuthorityActivate                AuthorityOp = "activate"
	AuthorityAbortAttach             AuthorityOp = "abort_attach"
	AuthorityTerminalDeliveryReceipt AuthorityOp = "terminal_delivery_receipt"
	AuthorityApplyRoutes             AuthorityOp = "apply_routes"
	AuthorityWrite                   AuthorityOp = "write"
	AuthoritySubscribe               AuthorityOp = "subscribe"
	AuthorityRenewSubscription       AuthorityOp = "renew_subscription"
	AuthorityNextControlEvent        AuthorityOp = "next_control_event"
	AuthorityChangeAck               AuthorityOp = "change_ack"
	AuthorityDelegationRecallAck     AuthorityOp = "delegation_recall_ack"
	AuthorityDelegationBreakAck      AuthorityOp = "delegation_break_ack"
	AuthorityDelegationModeChangeAck AuthorityOp = "delegation_mode_change_ack"
	AuthorityBarrier                 AuthorityOp = "barrier"
	AuthorityDelegationRelease       AuthorityOp = "delegation_release"
	AuthorityCloseBatch              AuthorityOp = "close_batch"
	AuthorityWaitVisibility          AuthorityOp = "wait_visibility"
)

var authorityOps = newEnum(AuthorityHello, AuthorityAttach, AuthorityResume, AuthorityKeepAlive,
	AuthorityDetach, AuthorityCancel, AuthorityReauthorize, AuthorityLookup, AuthorityGetAttr,
	AuthoritySetAttr, AuthorityCreate, AuthorityMkdir, AuthorityUnlink, AuthorityRename, AuthorityLink,
	AuthoritySymlink, AuthorityReadlink, AuthorityOpen, AuthorityClose, AuthorityRead, AuthorityFsync,
	AuthorityReadDir, AuthorityReclaim, AuthorityFlush, AuthorityGetXattr, AuthoritySetXattr,
	AuthorityListXattr, AuthorityRemoveXattr, AuthorityStatFS, AuthoritySyncFS, AuthorityFallocate,
	AuthorityCopyFileRange, AuthorityTmpfile, AuthorityGetLock, AuthoritySetLock, AuthorityActivate,
	AuthorityAbortAttach, AuthorityTerminalDeliveryReceipt, AuthorityApplyRoutes, AuthorityWrite,
	AuthoritySubscribe, AuthorityRenewSubscription, AuthorityNextControlEvent, AuthorityChangeAck,
	AuthorityDelegationRecallAck, AuthorityDelegationBreakAck, AuthorityDelegationModeChangeAck,
	AuthorityBarrier, AuthorityDelegationRelease, AuthorityCloseBatch, AuthorityWaitVisibility)

func (v AuthorityOp) valid() bool { return authorityOps.has(v) }

// foregroundAuthorityOps are the filesystem requests a callback waits on. The
// §9.1 baseline's 426 foreground requests are exactly these opcodes; session,
// renewal, release and coherence-control traffic is background even when its
// pressure reaches the critical path, which waits record separately.
var foregroundAuthorityOps = newEnum(AuthorityLookup, AuthorityGetAttr, AuthoritySetAttr,
	AuthorityCreate, AuthorityMkdir, AuthorityUnlink, AuthorityRename, AuthorityLink, AuthoritySymlink,
	AuthorityReadlink, AuthorityOpen, AuthorityRead, AuthorityFsync, AuthorityReadDir, AuthorityFlush,
	AuthorityGetXattr, AuthoritySetXattr, AuthorityListXattr, AuthorityRemoveXattr, AuthorityStatFS,
	AuthoritySyncFS, AuthorityFallocate, AuthorityCopyFileRange, AuthorityTmpfile, AuthorityGetLock,
	AuthoritySetLock, AuthorityWrite, AuthorityBarrier, AuthorityWaitVisibility)

// Dispatch separates an original authority send from a replay or retry.
type Dispatch string

const (
	DispatchOriginal Dispatch = "original"
	DispatchReplay   Dispatch = "replay"
	DispatchRetry    Dispatch = "retry"
)

var dispatches = newEnum(DispatchOriginal, DispatchReplay, DispatchRetry)

func (v Dispatch) valid() bool { return dispatches.has(v) }

// Outcome is the bounded result class; errno carries the detail.
type Outcome string

const (
	OutcomeOK        Outcome = "ok"
	OutcomeError     Outcome = "error"
	OutcomeCancelled Outcome = "cancelled"
	OutcomeUncertain Outcome = "uncertain"
	OutcomeTerminal  Outcome = "terminal"
)

var outcomes = newEnum(OutcomeOK, OutcomeError, OutcomeCancelled, OutcomeUncertain, OutcomeTerminal)

func (v Outcome) valid() bool { return outcomes.has(v) }

// LookupPolarity separates a positive authority Lookup from a stamped negative
// answer, which the wire encodes as an errno-zero response.
type LookupPolarity string

const (
	LookupPositive        LookupPolarity = "positive"
	LookupStampedNegative LookupPolarity = "stamped_negative"
)

var lookupPolarities = newEnum(LookupPositive, LookupStampedNegative)

func (v LookupPolarity) valid() bool { return lookupPolarities.has(v) }

// Publication is a PublicationAck's semantic commit.
type Publication string

const (
	PublicationPublished    Publication = "published"
	PublicationNotPublished Publication = "not_published"
)

var publications = newEnum(PublicationPublished, PublicationNotPublished)

func (v Publication) valid() bool { return publications.has(v) }

// Candidate names the local answer source a cache decision evaluated.
type Candidate string

const (
	CandidateAttrCache    Candidate = "attr_cache"   // GetAttr from settled source-effect attributes
	CandidateEntryCache   Candidate = "entry_cache"  // Lookup from settled source-effect name knowledge
	CandidateCompleteness Candidate = "completeness" // absence proven by a complete-directory certificate
)

var candidates = newEnum(CandidateAttrCache, CandidateEntryCache, CandidateCompleteness)

func (v Candidate) valid() bool { return candidates.has(v) }

// CacheResult is the answer a candidate offered, or miss.
type CacheResult string

const (
	CachePositive CacheResult = "positive"
	CacheNegative CacheResult = "negative"
	CacheMiss     CacheResult = "miss"
)

var cacheResults = newEnum(CachePositive, CacheNegative, CacheMiss)

func (v CacheResult) valid() bool { return cacheResults.has(v) }

// Coordinate says whether the decision's item or (parent, name) coordinate was
// already known to the producer's bounded state.
type Coordinate string

const (
	CoordinateFirst    Coordinate = "first"
	CoordinateRepeated Coordinate = "repeated"
)

var coordinates = newEnum(CoordinateFirst, CoordinateRepeated)

func (v Coordinate) valid() bool { return coordinates.has(v) }

// MissReason is the bounded miss category. The first ten match the daemon's
// fixed cache-result counters; certificate and search_permission are the
// completeness refusals.
type MissReason string

const (
	MissCold             MissReason = "cold"
	MissHeld             MissReason = "held"
	MissHorizon          MissReason = "horizon"
	MissAuthorization    MissReason = "authorization"
	MissUnknownName      MissReason = "unknown_name"
	MissResource         MissReason = "resource"
	MissTerminal         MissReason = "terminal"
	MissClock            MissReason = "clock"
	MissBypass           MissReason = "bypass"
	MissCertificate      MissReason = "certificate"
	MissSearchPermission MissReason = "search_permission"
)

var missReasons = newEnum(MissCold, MissHeld, MissHorizon, MissAuthorization, MissUnknownName,
	MissResource, MissTerminal, MissClock, MissBypass, MissCertificate, MissSearchPermission)

func (v MissReason) valid() bool { return missReasons.has(v) }

// ProofState is the session proof state at decision time.
type ProofState string

const (
	ProofValid    ProofState = "valid"
	ProofExpired  ProofState = "expired"
	ProofAbsent   ProofState = "absent"
	ProofRenewing ProofState = "renewing"
)

var proofStates = newEnum(ProofValid, ProofExpired, ProofAbsent, ProofRenewing)

func (v ProofState) valid() bool { return proofStates.has(v) }

// SourceState is the active source-effect or claim state at decision time.
type SourceState string

const (
	SourceNone         SourceState = "none"
	SourceActive       SourceState = "active"
	SourceClaimPending SourceState = "claim_pending"
	SourceSettled      SourceState = "settled"
)

var sourceStates = newEnum(SourceNone, SourceActive, SourceClaimPending, SourceSettled)

func (v SourceState) valid() bool { return sourceStates.has(v) }

// CertState is the completeness certificate state of the parent directory.
type CertState string

const (
	CertPresent CertState = "present"
	CertAbsent  CertState = "absent"
	CertDropped CertState = "dropped"
)

var certStates = newEnum(CertPresent, CertAbsent, CertDropped)

func (v CertState) valid() bool { return certStates.has(v) }

// CertDrop is why a completeness certificate was discarded.
type CertDrop string

const (
	CertDropNamespaceCut  CertDrop = "namespace_cut"
	CertDropPermissionCut CertDrop = "permission_cut"
	CertDropColdCut       CertDrop = "cold_cut"
	CertDropCapacity      CertDrop = "capacity"
	CertDropTerminal      CertDrop = "terminal"
)

var certDrops = newEnum(CertDropNamespaceCut, CertDropPermissionCut, CertDropColdCut,
	CertDropCapacity, CertDropTerminal)

func (v CertDrop) valid() bool { return certDrops.has(v) }

// SearchState is the parent's search-permission status at decision time.
type SearchState string

const (
	SearchPermitted SearchState = "permitted"
	SearchDenied    SearchState = "denied"
	SearchUnknown   SearchState = "unknown"
)

var searchStates = newEnum(SearchPermitted, SearchDenied, SearchUnknown)

func (v SearchState) valid() bool { return searchStates.has(v) }

// Exposure is the final exposure decision: the cached answer was exposed, or
// the request was changed to an ordinary authority read.
type Exposure string

const (
	ExposureAccepted     Exposure = "accepted"
	ExposureOrdinaryRead Exposure = "ordinary_read"
)

var exposures = newEnum(ExposureAccepted, ExposureOrdinaryRead)

func (v Exposure) valid() bool { return exposures.has(v) }

// OpenReason attributes one OPEN decision.
type OpenReason string

const (
	OpenFirst            OpenReason = "first"
	OpenExpansion        OpenReason = "expansion"
	OpenReopenAfterClose OpenReason = "reopen_after_close"
	OpenDirectoryCursor  OpenReason = "directory_cursor"
	OpenCreateReuse      OpenReason = "create_reuse"
)

var openReasons = newEnum(OpenFirst, OpenExpansion, OpenReopenAfterClose, OpenDirectoryCursor, OpenCreateReuse)

func (v OpenReason) valid() bool { return openReasons.has(v) }

// Mode is a requested access mode.
type Mode string

const (
	ModeRead      Mode = "read"
	ModeWrite     Mode = "write"
	ModeReadWrite Mode = "read_write"
	ModeDirectory Mode = "directory"
)

var modes = newEnum(ModeRead, ModeWrite, ModeReadWrite, ModeDirectory)

func (v Mode) valid() bool { return modes.has(v) }

// LiveMode is the access of the live descriptor(s) when an OPEN is decided.
type LiveMode string

const (
	LiveNone      LiveMode = "none"
	LiveRead      LiveMode = "read"
	LiveWrite     LiveMode = "write"
	LiveReadWrite LiveMode = "read_write"
	LiveDirectory LiveMode = "directory"
)

var liveModes = newEnum(LiveNone, LiveRead, LiveWrite, LiveReadWrite, LiveDirectory)

func (v LiveMode) valid() bool { return liveModes.has(v) }

// RPC says whether a real authority request was emitted or avoided.
type RPC string

const (
	RPCEmitted RPC = "emitted"
	RPCAvoided RPC = "avoided"
)

var rpcs = newEnum(RPCEmitted, RPCAvoided)

func (v RPC) valid() bool { return rpcs.has(v) }

// ReleaseKind names the release request family.
type ReleaseKind string

const (
	ReleaseClose   ReleaseKind = "close"
	ReleaseReclaim ReleaseKind = "reclaim"
)

var releaseKinds = newEnum(ReleaseClose, ReleaseReclaim)

func (v ReleaseKind) valid() bool { return releaseKinds.has(v) }

// Barrier is the durability barrier selected from operation semantics.
type Barrier string

const (
	BarrierHandleFsync Barrier = "handle_fsync"
	BarrierSyncfs      Barrier = "syncfs"
)

var barriers = newEnum(BarrierHandleFsync, BarrierSyncfs)

func (v Barrier) valid() bool { return barriers.has(v) }

// Syscall is a physical durability syscall.
type Syscall string

const (
	SyscallFsync     Syscall = "fsync"
	SyscallFdatasync Syscall = "fdatasync"
	SyscallSyncfs    Syscall = "syncfs"
)

var syscalls = newEnum(SyscallFsync, SyscallFdatasync, SyscallSyncfs)

func (v Syscall) valid() bool { return syscalls.has(v) }

// WaitKind names what a completed wait waited for. Transport, replay-slot and
// operation-slot waits are recorded apart from authority execution.
type WaitKind string

const (
	WaitReservation     WaitKind = "reservation"
	WaitCallbackWindow  WaitKind = "callback_window"
	WaitTransport       WaitKind = "transport"
	WaitReplaySlot      WaitKind = "replay_slot"
	WaitOperationSlot   WaitKind = "operation_slot"
	WaitNamespaceWrite  WaitKind = "namespace_write"
	WaitLinuxWithdrawal WaitKind = "linux_withdrawal"
)

var waitKinds = newEnum(WaitReservation, WaitCallbackWindow, WaitTransport, WaitReplaySlot,
	WaitOperationSlot, WaitNamespaceWrite, WaitLinuxWithdrawal)

func (v WaitKind) valid() bool { return waitKinds.has(v) }

// Resource names an occupancy gauge or final inventory.
type Resource string

const (
	ResourcePendingReservations Resource = "pending_reservations"
	ResourceCallbackWindow      Resource = "callback_window"
	ResourceReleaseForming      Resource = "release_forming"
	ResourceReleaseInflight     Resource = "release_inflight"
	ResourceAuthorityItems      Resource = "authority_items"
	ResourceAuthorityOpens      Resource = "authority_opens"
	ResourceLiveItems           Resource = "live_items"
	ResourceLiveDescriptors     Resource = "live_descriptors"
)

var resources = newEnum(ResourcePendingReservations, ResourceCallbackWindow, ResourceReleaseForming,
	ResourceReleaseInflight, ResourceAuthorityItems, ResourceAuthorityOpens, ResourceLiveItems,
	ResourceLiveDescriptors)

func (v Resource) valid() bool { return resources.has(v) }

// Witness is MkdirReply's kernel-evaluated child_search_permitted bit.
type Witness string

const (
	WitnessPermitted Witness = "permitted"
	WitnessDenied    Witness = "denied"
)

var witnesses = newEnum(WitnessPermitted, WitnessDenied)

func (v Witness) valid() bool { return witnesses.has(v) }

// Seed is the daemon's seeding decision for a new directory.
type Seed string

const (
	SeedMembershipAndSearch Seed = "membership_and_search" // true witness survived ordering checks
	SeedMembershipOnly      Seed = "membership_only"       // false witness: empty membership, no negative answers
	SeedSuperseded          Seed = "superseded"            // a later namespace, permission or cold cut won
	SeedMismatch            Seed = "mismatch"              // Item/PostState identity or snapshot did not match
)

var seeds = newEnum(SeedMembershipAndSearch, SeedMembershipOnly, SeedSuperseded, SeedMismatch)

func (v Seed) valid() bool { return seeds.has(v) }

// RenewalOrigin names who started a renewal; the daemon is the only owner.
type RenewalOrigin string

const (
	RenewalInitial  RenewalOrigin = "initial"
	RenewalPeriodic RenewalOrigin = "periodic"
)

var renewalOrigins = newEnum(RenewalInitial, RenewalPeriodic)

func (v RenewalOrigin) valid() bool { return renewalOrigins.has(v) }

// RenewalOutcome is how a renewal settled.
type RenewalOutcome string

const (
	RenewalInstalled        RenewalOutcome = "installed"
	RenewalExpiredOnReceipt RenewalOutcome = "expired_on_receipt"
	RenewalLocalDeadline    RenewalOutcome = "local_deadline"
	RenewalRefused          RenewalOutcome = "refused"
	RenewalTerminal         RenewalOutcome = "terminal"
	RenewalTransportLoss    RenewalOutcome = "transport_loss"
	RenewalMalformed        RenewalOutcome = "malformed"
	RenewalEpochMismatch    RenewalOutcome = "epoch_mismatch"
	RenewalClockFailure     RenewalOutcome = "clock_failure"
)

var renewalOutcomes = newEnum(RenewalInstalled, RenewalExpiredOnReceipt, RenewalLocalDeadline,
	RenewalRefused, RenewalTerminal, RenewalTransportLoss, RenewalMalformed, RenewalEpochMismatch,
	RenewalClockFailure)

func (v RenewalOutcome) valid() bool { return renewalOutcomes.has(v) }

// Load is a superblock's dirty-load condition for the run.
type Load string

const (
	LoadQuiet         Load = "quiet"
	LoadDirtyNeighbor Load = "dirty_neighbor"
)

var loads = newEnum(LoadQuiet, LoadDirtyNeighbor)

func (v Load) valid() bool { return loads.has(v) }

// Event is one trace event. Producers fill only the fields their kind allows;
// zero means absent. Recorder supplies seq and t_ns.
type Event struct {
	Kind Kind `json:"kind"`

	// Run-local identities.
	Mount            Label   `json:"mount,omitempty"`             // run-local mount label
	Conn             uint64  `json:"conn,omitempty"`              // daemon frontend-connection incarnation, never reused
	ConnNS           Label   `json:"conn_ns,omitempty"`           // run-unique namespace of conn, held identically by frontend and daemon
	Callback         uint64  `json:"callback,omitempty"`          // frontend-local callback ID, unique per frontend process
	Operation        uint64  `json:"operation,omitempty"`         // pfslocal operation_id, scoped by conn
	Request          uint64  `json:"request,omitempty"`           // pfslocal request_id (or disposition target), scoped by conn
	Successor        uint64  `json:"successor,omitempty"`         // operation a delayed ack is correlated to, scoped by conn
	Session          Label   `json:"session,omitempty"`           // run-local authority session label
	AuthorityRequest uint64  `json:"authority_request,omitempty"` // authority request_id, scoped by session
	Item             uint64  `json:"item,omitempty"`              // stable local item incarnation
	Parent           uint64  `json:"parent,omitempty"`            // stable local parent incarnation
	NameHex          NameHex `json:"name_hex,omitempty"`          // raw synthetic-corpus name, lowercase hex
	Batch            uint64  `json:"batch,omitempty"`             // producer-local release batch ID
	Superblock       Label   `json:"superblock,omitempty"`        // run-local storage superblock label

	// Categories.
	Phase          Phase          `json:"phase,omitempty"`
	CallbackKind   CallbackKind   `json:"callback_kind,omitempty"`
	Origin         Origin         `json:"origin,omitempty"`
	LocalOp        LocalOp        `json:"local_op,omitempty"`
	AuthorityOp    AuthorityOp    `json:"authority_op,omitempty"`
	Dispatch       Dispatch       `json:"dispatch,omitempty"`
	Outcome        Outcome        `json:"outcome,omitempty"`
	Lookup         LookupPolarity `json:"lookup,omitempty"`
	Publication    Publication    `json:"publication,omitempty"`
	Candidate      Candidate      `json:"candidate,omitempty"`
	CacheResult    CacheResult    `json:"cache_result,omitempty"`
	Coordinate     Coordinate     `json:"coordinate,omitempty"`
	MissReason     MissReason     `json:"miss_reason,omitempty"`
	Proof          ProofState     `json:"proof,omitempty"`
	SourceState    SourceState    `json:"source_state,omitempty"`
	Cert           CertState      `json:"cert,omitempty"`
	CertDrop       CertDrop       `json:"cert_drop,omitempty"`
	Search         SearchState    `json:"search,omitempty"`
	Exposure       Exposure       `json:"exposure,omitempty"`
	OpenReason     OpenReason     `json:"open_reason,omitempty"`
	Mode           Mode           `json:"mode,omitempty"`
	LiveMode       LiveMode       `json:"live_mode,omitempty"`
	RPC            RPC            `json:"rpc,omitempty"`
	ReleaseKind    ReleaseKind    `json:"release_kind,omitempty"`
	Barrier        Barrier        `json:"barrier,omitempty"`
	Syscall        Syscall        `json:"syscall,omitempty"`
	Wait           WaitKind       `json:"wait,omitempty"`
	Resource       Resource       `json:"resource,omitempty"`
	Witness        Witness        `json:"witness,omitempty"`
	Seed           Seed           `json:"seed,omitempty"`
	RenewalOrigin  RenewalOrigin  `json:"renewal_origin,omitempty"`
	RenewalOutcome RenewalOutcome `json:"renewal_outcome,omitempty"`
	Load           Load           `json:"load,omitempty"`

	// Bounded measures.
	Errno        Errno  `json:"errno,omitempty"`
	Flags        uint32 `json:"flags,omitempty"`         // requested open flags
	Count        uint32 `json:"count,omitempty"`         // occupancy, batch entries, active count or pending count
	Limit        uint32 `json:"limit,omitempty"`         // configured bound of the occupied resource
	Tokens       uint32 `json:"tokens,omitempty"`        // authority tokens released
	Waiters      uint32 `json:"waiters,omitempty"`       // waiters coalesced onto one syscall
	CommittedSeq uint64 `json:"committed_seq,omitempty"` // authority committed sequence
	VisibleSeq   uint64 `json:"visible_seq,omitempty"`   // authority visible sequence
	CutSeq       uint64 `json:"cut_seq,omitempty"`       // namespace cut a directory was seeded at
	ProofAge     Nanos  `json:"proof_age_ns,omitempty"`  // proof age at decision time
	Duration     Nanos  `json:"dur_ns,omitempty"`        // in-process interval: wait, syscall, turn or execution
}

// fieldSet is a bitmask over Event fields in declaration order.
type fieldSet uint64

type eventField struct {
	key   string
	index int
	bit   fieldSet
}

var (
	eventFields     []eventField
	eventFieldByKey = map[string]eventField{}
)

// rule is the per-kind grammar: allowed layers and phases, and the fields
// that must or may appear. kind is always required, and phase is required
// exactly when the kind has phases.
type rule struct {
	layers   []Layer
	phases   []Phase
	required string
	optional string
}

var allLayers = layers.ordered

var ruleSpecs = map[Kind]rule{
	KindCallback: {
		layers:   []Layer{LayerFrontend, LayerLinuxClient},
		phases:   []Phase{PhaseEntry, PhaseReply, PhasePublicationComplete},
		required: "callback callback_kind",
		optional: "mount conn conn_ns operation origin item parent name_hex outcome errno publication",
	},
	KindLocal: {
		layers: []Layer{LayerFrontend, LayerDaemon},
		phases: []Phase{PhaseSend, PhaseEnqueue, PhaseDispatch, PhaseOutcome, PhaseExposure,
			PhaseReply, PhaseDisposition},
		required: "conn request local_op",
		optional: "conn_ns mount callback operation origin item parent name_hex outcome errno count",
	},
	KindCache: {
		layers:   []Layer{LayerDaemon},
		phases:   []Phase{PhaseCandidate, PhaseFinal},
		required: "conn request candidate cache_result",
		optional: "conn_ns mount operation item parent name_hex coordinate miss_reason proof proof_age_ns source_state cert cert_drop search exposure",
	},
	KindSource: {
		layers: []Layer{LayerDaemon},
		phases: []Phase{PhaseAcquire, PhaseActiveInc, PhaseActiveDec, PhasePostState,
			PhaseClaimSettled, PhaseAck, PhaseRelease},
		required: "conn operation",
		optional: "conn_ns mount request successor count publication",
	},
	KindOpen: {
		layers:   []Layer{LayerFrontend, LayerDaemon, LayerLinuxClient},
		required: "item open_reason mode rpc",
		optional: "mount conn conn_ns callback operation request live_mode flags",
	},
	KindRelease: {
		layers:   []Layer{LayerFrontend, LayerDaemon, LayerLinuxClient},
		required: "item release_kind",
		optional: "mount conn conn_ns batch",
	},
	KindReleaseBatch: {
		layers:   []Layer{LayerDaemon, LayerLinuxClient},
		phases:   []Phase{PhaseForming, PhaseSent, PhaseAcked, PhaseTransferred},
		required: "release_kind batch",
		optional: "mount session count tokens",
	},
	KindAuthority: {
		layers:   []Layer{LayerDaemon, LayerLinuxClient, LayerAuthority},
		phases:   []Phase{PhaseSend, PhaseReceive, PhaseReply},
		required: "session authority_request authority_op",
		optional: "mount conn conn_ns operation request dispatch outcome errno lookup committed_seq visible_seq dur_ns",
	},
	KindBarrier: {
		layers:   []Layer{LayerAuthority},
		required: "barrier",
		optional: "session authority_request superblock",
	},
	KindSyscall: {
		layers:   []Layer{LayerAuthority},
		required: "syscall dur_ns",
		optional: "superblock waiters outcome errno",
	},
	KindWait: {
		layers:   allLayers,
		required: "wait dur_ns",
		optional: "mount conn conn_ns callback operation request session authority_request count",
	},
	KindOccupancy: {
		layers:   allLayers,
		phases:   []Phase{PhaseSample, PhaseFinal},
		required: "resource",
		optional: "mount session count limit",
	},
	KindMkdirWitness: {
		layers:   []Layer{LayerDaemon},
		required: "item witness seed",
		optional: "mount conn conn_ns request session authority_request parent cut_seq",
	},
	KindRenewal: {
		layers:   []Layer{LayerDaemon},
		required: "renewal_origin renewal_outcome",
		optional: "mount session authority_request dur_ns",
	},
	KindSuperblock: {
		layers:   []Layer{LayerAuthority},
		required: "superblock load",
		optional: "count",
	},
}

type compiledRule struct {
	layers   map[Layer]struct{}
	phases   map[Phase]struct{}
	required fieldSet
	allowed  fieldSet
}

var rules = map[Kind]compiledRule{}

func init() {
	t := reflect.TypeOf(Event{})
	if t.NumField() > 64 {
		panic("lantrace: Event has more fields than fieldSet can hold")
	}
	for i := 0; i < t.NumField(); i++ {
		key, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		f := eventField{key: key, index: i, bit: 1 << i}
		eventFields = append(eventFields, f)
		eventFieldByKey[key] = f
	}
	for _, k := range kinds.ordered {
		spec, ok := ruleSpecs[k]
		if !ok {
			panic("lantrace: kind without a rule: " + string(k))
		}
		r := compiledRule{
			layers:   map[Layer]struct{}{},
			phases:   map[Phase]struct{}{},
			required: keysToSet("kind " + spec.required),
		}
		if len(spec.phases) > 0 {
			r.required |= keysToSet("phase")
		}
		r.allowed = r.required | keysToSet(spec.optional)
		for _, l := range spec.layers {
			r.layers[l] = struct{}{}
		}
		for _, p := range spec.phases {
			r.phases[p] = struct{}{}
		}
		rules[k] = r
	}
}

func keysToSet(keys string) fieldSet {
	var s fieldSet
	for _, key := range strings.Fields(keys) {
		f, ok := eventFieldByKey[key]
		if !ok {
			panic("lantrace: rule names unknown field " + key)
		}
		s |= f.bit
	}
	return s
}

type validator interface{ valid() bool }

// validate checks e against the grammar for a stream of the given layer and
// returns the set of present fields. Errors name keys and categories only,
// never a field value, so a rejected value cannot leak through a log.
func (e *Event) validate(layer Layer) (fieldSet, error) {
	var present fieldSet
	v := reflect.ValueOf(e).Elem()
	for _, f := range eventFields {
		fv := v.Field(f.index)
		if fv.IsZero() {
			continue
		}
		present |= f.bit
		if val, ok := fv.Interface().(validator); ok && !val.valid() {
			return 0, fmt.Errorf("lantrace: field %q has an invalid value", f.key)
		}
	}
	r, ok := rules[e.Kind]
	if !ok {
		return 0, errors.New(`lantrace: field "kind" is missing`)
	}
	if _, ok := r.layers[layer]; !ok {
		return 0, fmt.Errorf("lantrace: %s events are not allowed in a %s stream", e.Kind, layer)
	}
	if missing := r.required &^ present; missing != 0 {
		return 0, fmt.Errorf("lantrace: %s event is missing field %q", e.Kind, firstKey(missing))
	}
	if extra := present &^ r.allowed; extra != 0 {
		return 0, fmt.Errorf("lantrace: %s event does not allow field %q", e.Kind, firstKey(extra))
	}
	if e.Phase != "" {
		if _, ok := r.phases[e.Phase]; !ok {
			return 0, fmt.Errorf("lantrace: %s event does not allow phase %s", e.Kind, e.Phase)
		}
	}
	return present, nil
}

func firstKey(s fieldSet) string {
	for _, f := range eventFields {
		if s&f.bit != 0 {
			return f.key
		}
	}
	return ""
}
