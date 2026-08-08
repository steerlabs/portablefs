package directstoreharness

import (
	"errors"
	"fmt"
)

const (
	ReplicaCount = 3
	ClientNode   = NodeID(ReplicaCount)
	AnyNode      = NodeID(255)
)

type NodeID uint8

func (n NodeID) String() string {
	if n == ClientNode {
		return "client"
	}
	return fmt.Sprintf("replica-%d", n)
}

type ExactID struct {
	Client   uint32
	Sequence uint64
}

type Mutation struct {
	ID    ExactID
	Value uint64
}

type MutationStatus uint8

const (
	MutationUnknown MutationStatus = iota
	MutationSuccess
	MutationUnavailable
	MutationNoSpace
	MutationIntegrityFailure
)

type MutationReply struct {
	Status MutationStatus
	ID     ExactID
	Index  uint64
	Value  uint64
	Root   Digest
}

type ReadStatus uint8

const (
	ReadSuccess ReadStatus = iota
	ReadUnavailable
	ReadIntegrityFailure
)

type ReadReply struct {
	Status ReadStatus
	Index  uint64
	Value  uint64
	Node   NodeID
}

// Target is the seam implemented by the in-memory protocol fixture and later
// by the Phase 1 replica-process adapter. All nondeterminism must flow through
// Environment; a target that consults a clock or an independent RNG cannot be
// replayed from the harness seed.
type Target interface {
	Mutate(Mutation) MutationReply
	LinearizableRead(minimumIndex uint64) ReadReply
	Recover() error
	Audit() AuditSnapshot
}

type TargetFactory func(*Environment) Target

type ReplicaAudit struct {
	Node         NodeID
	Alive        bool
	CommitIndex  uint64
	AppliedIndex uint64
	Value        uint64
	Root         Digest
}

type CommitAudit struct {
	Index       uint64
	Root        Digest
	Operation   ExactID
	Certificate uint8
	Leader      NodeID
}

type ApplyAudit struct {
	Node      NodeID
	Index     uint64
	Root      Digest
	Operation ExactID
}

// AuditSnapshot contains only facts created since the preceding Audit call.
// Replica state is current. Keeping observations incremental makes million-op
// checking constant-space in the target.
type AuditSnapshot struct {
	Replicas []ReplicaAudit
	Commits  []CommitAudit
	Applies  []ApplyAudit
}

type CutKind uint8

const (
	PersistenceCut CutKind = iota
	MessageCut
)

type CutPoint struct {
	ID       string
	Kind     CutKind
	Scenario string
	Actors   []string
}

// Catalog is deliberately data, not control flow. The authoritative Phase 0
// table can be converted without teaching the harness a second list of cuts.
type Catalog []CutPoint

type FaultKind uint8

const (
	NoFault FaultKind = iota
	KillBefore
	KillAfter
	PartitionLink
	DropMessage
	DuplicateMessage
	ShortWrite
	NoSpace
	ChecksumFailure
)

func (k FaultKind) String() string {
	switch k {
	case NoFault:
		return "none"
	case KillBefore:
		return "kill-before"
	case KillAfter:
		return "kill-after"
	case PartitionLink:
		return "partition-link"
	case DropMessage:
		return "drop-message"
	case DuplicateMessage:
		return "duplicate-message"
	case ShortWrite:
		return "short-write"
	case NoSpace:
		return "enospc"
	case ChecksumFailure:
		return "checksum-failure"
	default:
		return fmt.Sprintf("fault-%d", k)
	}
}

type Fault struct {
	Kind  FaultKind
	Point string
	Node  NodeID
	From  NodeID
	To    NodeID
	Links uint8
}

type Violation struct {
	Property  string
	Detail    string
	Seed      uint64
	Operation uint64
	TraceHash Digest
}

func (v *Violation) Error() string {
	return fmt.Sprintf("%s at operation %d (seed %d): %s", v.Property, v.Operation, v.Seed, v.Detail)
}

var (
	ErrProcessKilled = errors.New("direct-store harness: process killed")
	ErrPartitioned   = errors.New("direct-store harness: link partitioned")
	ErrNoSpace       = errors.New("direct-store harness: no space")
	ErrChecksum      = errors.New("direct-store harness: checksum failure")
)
