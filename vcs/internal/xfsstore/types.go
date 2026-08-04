// Package xfsstore exposes one authoritative XFS directory through
// descriptor-relative operations. It has no path-based operation API: a host
// path is accepted once, at volume bootstrap, and every later operation uses a
// server-issued object or open-handle capability.
package xfsstore

import (
	"errors"
	"io/fs"
)

var (
	ErrUnsupportedPlatform = errors.New("xfsstore: production storage requires Linux")
	ErrNotXFS              = errors.New("xfsstore: volume root is not on XFS")
	ErrStaleObject         = errors.New("xfsstore: stale object capability")
	ErrStaleOpen           = errors.New("xfsstore: stale open-handle capability")
	ErrClosed              = errors.New("xfsstore: volume is closed")
	ErrFenced              = errors.New("xfsstore: authoritative storage is fenced")
	ErrOutcomeUncertain    = errors.New("xfsstore: operation changed XFS before a later local step failed")
	ErrWrongDevice         = errors.New("xfsstore: object crossed the volume device boundary")
	ErrProjectIsolation    = errors.New("xfsstore: XFS project inheritance does not match the volume")
	ErrForbiddenType       = errors.New("xfsstore: object type is not remotely accessible")
	ErrForbiddenXattr      = errors.New("xfsstore: extended attribute namespace is forbidden")
)

func outcomeUncertain(err error) error {
	return errors.Join(ErrOutcomeUncertain, err)
}

// Config contains provisioned identity, not tuning knobs. Project zero is
// never a production volume because XFS does not enforce project-zero limits.
type Config struct {
	ExpectedProjectID uint32
	// PortableFS v3 volumes are single-principal workspaces. Every inode is
	// owned by the unprivileged authority service identity; mount frontends
	// project that principal to the mounting user on each machine.
	ExpectedOwnerUID uint32
	ExpectedOwnerGID uint32
}

// Capability is a cryptographically random, epoch-local reference. Values are
// opaque to clients and useful only to the Volume instance that issued them.
type Capability [16]byte

type Kind uint8

const (
	KindRegular Kind = iota + 1
	KindDirectory
	KindSymlink
)

// Attr is the portable part of Linux statx. Change is assigned by the upper
// authority after an ordered mutation; XFS remains the metadata source.
type Attr struct {
	Kind        Kind
	Ino         uint64
	Size        int64
	Blocks      uint64
	Mode        fs.FileMode
	UID         uint32
	GID         uint32
	Nlink       uint32
	DeviceMajor uint32
	DeviceMinor uint32
	ATimeNS     int64
	MTimeNS     int64
	CTimeNS     int64
	BirthTimeNS int64
}

type Dirent struct {
	Name string
	Kind Kind
	Ino  uint64
}

type FSStat struct {
	BlockSize       uint64
	Blocks          uint64
	BlocksFree      uint64
	BlocksAvailable uint64
	Files           uint64
	FilesFree       uint64
	NameMax         uint32
}

type XattrMode uint8

const (
	XattrUpsert XattrMode = iota
	XattrCreate
	XattrReplace
)

// OpenFlags is the intentionally small set of file-open behavior exposed on
// the remote protocol. Arbitrary Linux flags are never accepted from a peer.
type OpenFlags struct {
	Read     bool
	Write    bool
	Append   bool
	Truncate bool
	Sync     bool
	DataSync bool
}

// RenameFlags map to renameat2's atomic behaviors.
type RenameFlags uint32

const (
	RenameNoReplace RenameFlags = 1 << iota
	RenameExchange
)
