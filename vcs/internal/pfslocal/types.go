// Package pfslocal implements the exact pfslocal 2.0 Unix-socket protocol used
// between portablefsd and local filesystem frontends.
package pfslocal

const (
	ProtocolMajor = 2
	ProtocolMinor = 0
	MaxFrameBytes = 16 << 20
)

type Envelope struct {
	RequestID              uint64
	PublicationAckRequired bool
	// OperationID is connection-scoped. Mount-shared callback state must also
	// carry a never-reused connection incarnation, including ack and cleanup.
	OperationID uint64
	Body        any
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
	// OperationID names only a callback on this exact frontend connection.
	OperationID    uint64
	SemanticCommit PublicationSemanticCommit
}

type PublicationSemanticCommit uint32

const (
	PublicationSemanticCommitUnspecified  PublicationSemanticCommit = 0
	PublicationSemanticCommitPublished    PublicationSemanticCommit = 1
	PublicationSemanticCommitNotPublished PublicationSemanticCommit = 2
)

// ResourceReplyDisposition is the final ownership verdict for one successful
// resource-bearing reply on this exact connection.
type ResourceReplyDisposition struct {
	TargetRequestID uint64
	// AcceptHandles transfers every handle in this reply to VolumeCore. False
	// abandons them. A Create reply can accept its handle independently of its
	// item because those resources cross different ownership boundaries.
	AcceptHandles bool
	// AcceptedItemCount transfers this exact prefix of the reply's ordered item
	// occurrence sequence to FSKit. A count, rather than item IDs, preserves
	// duplicate hard-link entries and order.
	AcceptedItemCount uint32
}

type ResolveRequest struct{ AttachRef string }

type ResolveReply struct {
	Root         Item
	RootAttr     Attr
	VolumeID     string
	VolumeName   string
	Capabilities Capabilities
}

// Capabilities contains numeric limits; filesystem semantics are fixed by 2.0.
type Capabilities struct {
	MaxNameBytes    uint32
	MaxFileSize     uint64
	PreferredIOSize uint32
}

// Item is a daemon-local ownership handle for one retained authority
// capability, not a file identity: after reclaim the same file returns under a
// new ItemID, and Attr.FileID is what names the file. ItemIDs are allocated
// monotonically and never reused within an attach. ItemGeneration is the
// attach's persisted identity epoch; StableIdentity is the authority identity
// shared by every hard-link alias.
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
	Item        Item
	Kind        ItemKind
	Mode        uint32
	Nlink       uint32
	UID         uint32
	GID         uint32
	Size        uint64
	MtimeMs     int64
	CtimeMs     int64
	AtimeMs     int64
	BirthtimeMs int64
	// ContentVersion is conservative and may advance without a logical change.
	ContentVersion uint64
	Parent         *Item
	Flags          uint32
	AllocSize      uint64
	// FileID is the filesystem object number FSKit reports: 1 for the volume
	// root, the authority inode in [2, UInt64.max) for every other object. Hard-link
	// aliases share it and it survives reclaim; it authorizes nothing.
	FileID uint64
	// ParentFileID is the FileID of the parent binding described by Parent,
	// zero when there is none. Enumeration entries carry it without Parent.
	ParentFileID uint64
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

type DirEntry struct {
	Name   []byte
	Attr   Attr
	Cookie uint64
}

// EnumerateEntriesRequest lists one page of a directory as non-owning entry
// snapshots, using the mandatory retained read handle.
type EnumerateEntriesRequest struct {
	Dir        Item
	Cookie     uint64
	MaxEntries uint32
	WantAttrs  bool
	Handle     uint64
}

// EnumerateEntriesReply carries entries whose Attr names the object by
// FileID only: Attr.Item and Attr.Parent are empty and ParentFileID is the
// listed directory. The reply transfers no item ownership and takes no
// ResourceReplyDisposition.
type EnumerateEntriesReply struct {
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
	// SetFlags selects an absolute BSD flags change, including clearing to zero.
	// Unsupported flags refuse the entire compound SetAttr before application.
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
type RenameReply struct {
	NewPostIdentity []byte
	OldPostIdentity []byte
}

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

// SyncVolumeRequest requests the authority's real durability barrier.
// An unreachable or fenced authority fails the request.
type SyncVolumeRequest struct{}
type SyncVolumeReply struct{}

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

type Event struct{ Kind any }

type CacheProof struct {
	HorizonNanos                   uint64
	AuthorizationDeadlineUnixNanos uint64
}

type AttachState struct {
	State  AttachStateState
	Detail string
}

type AttachStateState int32

const (
	AttachStateUnspecified AttachStateState = 0
	AttachStateAttached    AttachStateState = 1
	AttachStateDegraded    AttachStateState = 3
	AttachStateDetaching   AttachStateState = 4
)
