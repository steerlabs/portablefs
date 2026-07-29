// Package pfslocal implements the frozen pfslocal v1 Unix-socket protocol used
// between portablefsd and local filesystem frontends.
package pfslocal

const (
	ProtocolMajor = 1
	ProtocolMinor = 0
	MaxFrameBytes = 16 << 20
)

type Envelope struct {
	RequestID uint64
	Body      any
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
}

type ResolveRequest struct{ AttachRef string }

type ResolveReply struct {
	Root         Item
	RootAttr     Attr
	VolumeID     string
	Branch       string
	VolumeName   string
	Capabilities Capabilities
}

type Capabilities struct {
	Symlinks        bool
	HardLinks       bool
	Xattrs          bool
	CaseSensitive   bool
	MaxNameBytes    uint32
	MaxFileSize     uint64
	PreferredIOSize uint32
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

type GetAttrRequest struct{ Item Item }
type GetAttrReply struct{ Attr Attr }

type SetAttrRequest struct {
	Item    Item
	Mode    *uint32
	UID     *uint32
	GID     *uint32
	Size    *uint64
	MtimeMs *int64
	AtimeMs *int64
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
}
type OpenReply struct{ Handle uint64 }

type CloseRequest struct{ Handle uint64 }
type CloseReply struct{}

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
	Item Item
	Name string
}
type XattrGetReply struct{ Value []byte }

type XattrSetRequest struct {
	Item        Item
	Name        string
	Value       []byte
	CreateOnly  bool
	ReplaceOnly bool
}
type XattrSetReply struct{}

type XattrListRequest struct{ Item Item }
type XattrListReply struct{ Names []string }

type XattrRemoveRequest struct {
	Item Item
	Name string
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
