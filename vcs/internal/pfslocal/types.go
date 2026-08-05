// Package pfslocal implements the frozen pfslocal v1 Unix-socket protocol used
// between portablefsd and local filesystem frontends.
package pfslocal

const (
	ProtocolMajor = 1
	// ProtocolMinor 6 adds Envelope.PublicationRetracted.
	//
	// It is a MINOR BUMP rather than a silently additive field, which breaks
	// with the rule the O_APPEND and chflags fields follow (see pfslocal.proto:
	// "deliberately NOT gated behind a minor bump ... these fields default to
	// false, which reproduces the previous behavior exactly"). Defaulting to
	// false does NOT reproduce the previous behaviour here: a frontend that
	// ignores the flag installs, into the kernel, state the daemon has already
	// retracted because a delegation handoff crossed it. That is a silent
	// correctness failure, not a missing feature, so the two sides must not be
	// able to pair at all. The daemon refuses any frontend whose minor is below
	// its own (portablefsd/frontend.go), and that refusal IS the gate.
	//
	// ProtocolMinor 7 adds HelloReply.RequestDeadlineMs.
	//
	// It is a MINOR BUMP for the same reason: the default does not reproduce
	// the previous behaviour, it reproduces the DEFECT. A frontend that ignores
	// the field keeps its own compiled-in reply deadline, and the whole point of
	// the field is that a frontend's compiled-in deadline has no relationship to
	// the daemon's budgets and was observed live to expire FIRST — costing the
	// mount its kernel-coherence barrier permanently. Pairing a daemon that
	// knows its bound with a frontend that ignores it is precisely the pairing
	// that broke, so the two must not be able to pair at all.
	//
	// ProtocolMinor 8 adds the macOS v3 coherence contract, exact two-phase
	// visibility events, and cursor acknowledgments. Ignoring those fields can
	// leave stale kernel state serving, so the existing minimum-minor gate is
	// the compatibility boundary.
	//
	// ProtocolMinor 9 adds the strict-v3 end-to-end liveness proof. A frontend
	// which only knows that its UDS is live cannot distinguish a responsive
	// daemon from one that has lost its authority session.
	ProtocolMinor = 9
	MaxFrameBytes = 16 << 20
)

type Envelope struct {
	RequestID              uint64
	PublicationAckRequired bool
	OperationID            uint64
	// PublicationRetracted says that everything this envelope's LOGICAL
	// OPERATION has published must not be installed. The frontend discards the
	// operation's collected values and fails the framework callback rather than
	// returning them, so nothing reaches the kernel; the syscall retries and
	// reads state taken after the boundary that caused the retraction.
	//
	// ── WHY IT RIDES A REPLY AND IS NOT A MESSAGE OF ITS OWN ────────────────
	//
	// The retraction has to be observed BEFORE the framework installs the
	// operation's results, and the install happens the instant the callback
	// returns. A standalone message cannot promise that: the frontend dispatches
	// received frames onto concurrent tasks, so a retraction written before the
	// reply can still be PROCESSED after it. Riding the reply's own envelope
	// removes the question — one frame, one delivery, no ordering to lose.
	//
	// And there is always such a reply. The only case that retracts is a handoff
	// crossing an operation with participants left and all of them parked; a
	// parked participant is a request in flight that will be answered, and the
	// callback cannot return before its last request is answered. So a
	// retraction always has a carrier that precedes the install.
	PublicationRetracted bool
	Body                 any
}

type Hello struct {
	ProtocolMajor uint32
	ProtocolMinor uint32
	ClientName    string
	ClientVersion string
}

type HelloReply struct {
	ProtocolMajor uint32
	ProtocolMinor uint32
	DaemonVersion string
	// RequestDeadlineMs is how long a frontend must be willing to wait for one
	// reply before concluding this daemon has stopped answering. See
	// pfslocal.proto and Server.frontendRequestDeadline.
	RequestDeadlineMs uint32
}

type PublicationAck struct {
	PublishedRequestID uint64
	OperationID        uint64
}

type ResolveRequest struct{ AttachRef string }

type ResolveReply struct {
	Root         Item
	RootAttr     Attr
	VolumeID     string
	Branch       string
	VolumeName   string
	Capabilities Capabilities
	V3Coherence  *V3CoherenceContract
}

type V3CoherenceContract struct {
	AuthorityProtocolMajor uint32
	AuthorityEpoch         []byte
	SessionID              []byte
	CachePolicy            string
	RepairBudgetMillis     uint64
	// InitialCursor is absent for the genesis cut before the authority has
	// emitted any visibility sequence. When present it is a positive COMPLETE.
	InitialCursor *VisibilityCursor
}

type V3LivenessRequest struct {
	AuthorityEpoch []byte
	SessionID      []byte
}

type V3LivenessReply struct {
	AuthorityEpoch []byte
	SessionID      []byte
}

type Capabilities struct {
	Symlinks        bool
	HardLinks       bool
	Xattrs          bool
	CaseSensitive   bool
	MaxNameBytes    uint32
	MaxFileSize     uint64
	PreferredIOSize uint32
	// FlagsSupported is true exactly when this attach's AUTHORITY durably
	// stores BSD file flags (fsproto.FeatureFlagPersistence). Per-attach,
	// never hardcoded.
	//
	// It is informational to the frontend and is NOT a forwarding gate: an
	// attach's namespace is not all authority. A machine-local graft's backing
	// is a real host inode, so chflags(2) on it is the durable store and no
	// authority feature is involved — gating the volume on this field would
	// refuse graft chflags that would have worked. The daemon decides per
	// target; the frontend gates on FlagsUnderstood.
	FlagsSupported bool
	// FlagsUnderstood is true exactly when the daemon serving this connection
	// PARSES SetAttrRequest.SetFlags/Flags. It is a statement about protocol
	// comprehension, not about any authority or any object, and every daemon
	// that reads those fields sets it unconditionally.
	//
	// It exists because SetFlags/Flags are appended pfslocal fields at the
	// same protocol minor: a daemon predating them discards both, applies the
	// rest of the setattr and answers success — a chflags(2) that succeeds
	// while nothing changed. Such a daemon also predates this field, so it
	// decodes false and the frontend's gate closes on its own. The frontend
	// forwards flags changes exactly when this is true, and answers its
	// mount-time volume capability (FSKit doesNotSupportImmutableFiles) from
	// it, because per-object refusal arrives as an errno on the request.
	FlagsUnderstood bool
}

// Item is the frontend-visible filesystem object identity. portablefsd keeps
// ItemID tied to the authority's stable inode when one is available, falling
// back to a deterministic path inode only for authority entries that lack one.
// ItemGeneration is a per-attach identity epoch persisted in the daemon
// state-dir; it is not a cache/coherence version and must survive daemon
// restarts so kernel-held FSItems remain valid for revived attaches.
type Item struct {
	ItemID         uint64
	ItemGeneration uint64
	StableIdentity [16]byte
}

type ItemKind int32

const (
	ItemKindUnspecified ItemKind = 0
	ItemKindFile        ItemKind = 1
	ItemKindDirectory   ItemKind = 2
	ItemKindSymlink     ItemKind = 3
)

type Attr struct {
	Item           Item
	Kind           ItemKind
	Mode           uint32
	Nlink          uint32
	UID            uint32
	GID            uint32
	Size           uint64
	MtimeMs        int64
	CtimeMs        int64
	AtimeMs        int64
	BirthtimeMs    int64
	ContentVersion uint64
	Parent         *Item
	Flags          uint32
	AllocSize      uint64
}

type ErrorReply struct {
	Errno   int32
	Message string
}

type LookupRequest struct {
	Dir  Item
	Name []byte
}
type LookupReply struct{ Attr Attr }

type EnumerateRequest struct {
	Dir        Item
	Cookie     uint64
	MaxEntries uint32
	WantAttrs  bool
}

type DirEntry struct {
	Name   []byte
	Attr   Attr
	Cookie uint64
}

type EnumerateReply struct {
	Entries    []DirEntry
	NextCookie uint64
	DirVersion uint64
}

type GetAttrRequest struct {
	Item   Item
	Handle uint64
}
type GetAttrReply struct{ Attr Attr }

type SetAttrRequest struct {
	Item    Item
	Mode    *uint32
	UID     *uint32
	GID     *uint32
	Size    *uint64
	MtimeMs *int64
	AtimeMs *int64
	Handle  uint64
	// SetFlags/Flags is the chflags(2) group: SetFlags is the intent and Flags
	// is the ABSOLUTE new BSD file-flag word. A bool+value pair rather than a
	// *uint32 because 0 is a legal value (clear every flag) — the intent has to
	// survive a zero payload. SetFlags is false in every frame an older
	// frontend mints, which is exactly the previous "no flag change" meaning,
	// so the fields needed no protocol-minor bump (same rule as the O_APPEND
	// intent fields; see pfslocal.proto).
	SetFlags bool
	Flags    uint32
}
type SetAttrReply struct{ Attr Attr }

type OpenMode int32

const (
	OpenModeUnspecified OpenMode = 0
	OpenModeRead        OpenMode = 1
	OpenModeWrite       OpenMode = 2
	OpenModeReadWrite   OpenMode = 3
)

type OpenRequest struct {
	Item Item
	Mode OpenMode
	// Append carries O_APPEND as a STICKY property of the descriptor. Every
	// write through the resulting handle is then resolved at the authority's
	// EOF in sequencer order, never at a frontend-computed absolute offset —
	// which is the only way concurrent appends from two machines cannot
	// collide. Frontends that learn the intent per-write instead set
	// WriteRequest.Append.
	Append bool
}
type OpenReply struct{ Handle uint64 }

type CloseRequest struct{ Handle uint64 }
type CloseReply struct {
	Retired    bool
	CloseErrno int32
}

type ReadRequest struct {
	Handle uint64
	Offset uint64
	Length uint32
}
type ReadReply struct{ Data []byte }

type WriteRequest struct {
	Handle uint64
	Offset uint64
	Data   []byte
	// Append requests O_APPEND semantics for THIS write: the authority (or,
	// under an exclusive delegation, the locally authoritative view) picks the
	// offset at EOF. Offset must be zero and is ignored. A handle opened with
	// OpenRequest.Append/CreateRequest.Append appends regardless of this bit.
	Append bool
}
type WriteReply struct {
	Written uint32
	Attr    Attr
}

type FsyncRequest struct{ Handle uint64 }
type FsyncReply struct{}

type CreateRequest struct {
	Dir       Item
	Name      []byte
	Mode      uint32
	Exclusive bool
	// Append is O_APPEND on the O_CREAT open, sticky on the returned handle
	// exactly as for OpenRequest.Append.
	Append bool
}
type CreateReply struct {
	Attr   Attr
	Handle uint64
}

type MkdirRequest struct {
	Dir  Item
	Name []byte
	Mode uint32
}
type MkdirReply struct{ Attr Attr }

type RemoveRequest struct {
	Dir       Item
	Name      []byte
	Directory bool
}
type RemoveReply struct{}

type RenameRequest struct {
	FromDir   Item
	FromName  []byte
	ToDir     Item
	ToName    []byte
	NoReplace bool
}
type RenameReply struct{}

type SymlinkRequest struct {
	Dir    Item
	Name   []byte
	Target []byte
}
type SymlinkReply struct{ Attr Attr }

type ReadlinkRequest struct{ Item Item }
type ReadlinkReply struct{ Target []byte }

type HardLinkRequest struct {
	Item Item
	Dir  Item
	Name []byte
}
type HardLinkReply struct {
	Name []byte
	Attr Attr
}

type XattrGetRequest struct {
	Item   Item
	Name   string
	Handle uint64
}
type XattrGetReply struct{ Value []byte }

type XattrSetRequest struct {
	Item        Item
	Name        string
	Value       []byte
	CreateOnly  bool
	ReplaceOnly bool
	Handle      uint64
}
type XattrSetReply struct{}

type XattrListRequest struct {
	Item   Item
	Handle uint64
}
type XattrListReply struct{ Names []string }

type XattrRemoveRequest struct {
	Item   Item
	Name   string
	Handle uint64
}
type XattrRemoveReply struct{}

// SyncVolumeRequest asks the daemon for the REAL volume barrier: success
// means every accepted mutation is locally synced, durable and applied at the authority,
// AND acknowledged by every live protocol subscriber at its supported
// frontend boundary. There is no degraded local-only success — local WAL
// failure or an unreachable/slow/fenced authority fails the op (EIO).
// Degraded is retired wire ballast (always false) kept for frame
// compatibility.
type SyncVolumeRequest struct{}
type SyncVolumeReply struct{ Degraded bool }

type StatfsRequest struct{}
type StatfsReply struct {
	BlockSize   uint64
	TotalBlocks uint64
	FreeBlocks  uint64
	TotalFiles  uint64
	FreeFiles   uint64
}

type ReclaimRequest struct{ Item Item }
type ReclaimReply struct{}

type SubscribeEventsRequest struct{}
type SubscribeEventsReply struct{}

type VisibilityPhase int32

const (
	VisibilityPhaseUnspecified VisibilityPhase = 0
	VisibilityPhasePrepare     VisibilityPhase = 1
	VisibilityPhaseComplete    VisibilityPhase = 2
)

type VisibilityScope int32

const (
	VisibilityScopeUnspecified VisibilityScope = 0
	VisibilityScopeNamespace   VisibilityScope = 1
	VisibilityScopeData        VisibilityScope = 2
	VisibilityScopeAttributes  VisibilityScope = 3
)

type VisibilityCursor struct {
	Sequence uint64
	Phase    VisibilityPhase
}

type VisibilityTarget struct {
	Scope          VisibilityScope
	Identity       []byte
	ParentIdentity []byte
	Name           []byte
	Size           int64
}

type RoutesChange struct {
	Revision []byte
	Rules    []byte
}

type V3VisibilityEvent struct {
	AuthorityEpoch     []byte
	Cursor             VisibilityCursor
	InitiatorSessionID []byte
	MutationSlot       uint32
	Targets            []VisibilityTarget
	MutationSequence   uint64
	Routes             *RoutesChange
	// LocalOperationID is nonzero only for this mount's own authority
	// mutation. It names the exact pfslocal publication unit that PREPARE must
	// exempt and deferred COMPLETE must wait to observe published.
	LocalOperationID uint64
}

type VisibilityAckRequest struct {
	AuthorityEpoch []byte
	Cursor         VisibilityCursor
	Blocked        bool
	Reason         string
}

type VisibilityAckReply struct{}

type Event struct{ Kind any }

type Invalidation struct {
	Item             Item
	ContentChanged   bool
	AttrsChanged     bool
	NamespaceChanged bool
	ContentVersion   uint64
}

type AttachState struct {
	State  AttachStateState
	Detail string
}

type AttachStateState int32

const (
	AttachStateUnspecified AttachStateState = 0
	AttachStateAttached    AttachStateState = 1
	AttachStateWarming     AttachStateState = 2
	AttachStateDegraded    AttachStateState = 3
	AttachStateDetaching   AttachStateState = 4
)
