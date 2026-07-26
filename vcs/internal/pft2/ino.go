package pft2

import (
	"fmt"
)

// Uint64String is a uint64 that crosses JSON boundaries as a canonical ASCII
// decimal string, never as a JSON number. Inode and allocator values use it
// so a JavaScript peer can parse with BigInt and 2^53+ values survive
// round-trips exactly.
type Uint64String uint64

// MarshalJSON encodes the value as `"1234"`.
func (v Uint64String) MarshalJSON() ([]byte, error) {
	return []byte(`"` + FormatUint64Decimal(uint64(v)) + `"`), nil
}

// UnmarshalJSON accepts exactly a canonical decimal string.
func (v *Uint64String) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return invalidf("uint64 value must be a decimal string, got %s", data)
	}
	parsed, err := ParseUint64Decimal(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	*v = Uint64String(parsed)
	return nil
}

// FormatUint64Decimal renders the canonical ASCII decimal form.
func FormatUint64Decimal(v uint64) string {
	return fmt.Sprintf("%d", v)
}

// ParseUint64Decimal parses a canonical ASCII decimal uint64: digits only, no
// sign or whitespace, no leading zeros (except exactly "0"), and no overflow.
func ParseUint64Decimal(s string) (uint64, error) {
	if len(s) == 0 || len(s) > 20 {
		return 0, invalidf("decimal %q has invalid length", s)
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, invalidf("decimal %q has a leading zero", s)
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, invalidf("decimal %q contains a non-digit", s)
		}
		digit := uint64(c - '0')
		if v > (1<<64-1-digit)/10 {
			return 0, invalidf("decimal %q overflows uint64", s)
		}
		v = v*10 + digit
	}
	return v, nil
}

// ComposeIno composes a stable inode id from a branch allocation namespace
// and a per-namespace local counter, without hashing:
//
//	ino = (namespace << 32) | localCounter
//
// namespace is 1..MaxInodeNamespace and localCounter is
// 1..MaxInodeLocalCounter, so the result is positive and fits a PostgreSQL
// signed BIGINT. Namespace 0 is reserved for inode 1 and verified legacy
// inode ids and is never composed. Out-of-range inputs return the typed
// terminal exhaustion errors; neither value wraps or is reused.
func ComposeIno(namespace uint32, localCounter uint64) (uint64, error) {
	if namespace < 1 || namespace > MaxInodeNamespace {
		return 0, fmt.Errorf("%w: namespace %d outside 1..%d",
			ErrInodeNamespaceExhausted, namespace, MaxInodeNamespace)
	}
	if localCounter < 1 || localCounter > MaxInodeLocalCounter {
		return 0, fmt.Errorf("%w: namespace %d local counter %d outside 1..%d",
			ErrInodeCounterExhausted, namespace, localCounter, MaxInodeLocalCounter)
	}
	return uint64(namespace)<<32 | localCounter, nil
}

// SplitIno decomposes an inode id into (namespace, localCounter). Namespace 0
// identifies inode 1 and verified legacy inode ids (the whole id is the local
// part). Inode ids above MaxIno are invalid.
func SplitIno(ino uint64) (namespace uint32, localCounter uint64, err error) {
	if ino < 1 || ino > MaxIno {
		return 0, 0, invalidf("ino %d outside 1..%d", ino, MaxIno)
	}
	namespace = uint32(ino >> 32)
	localCounter = ino & MaxInodeLocalCounter
	if namespace != 0 && localCounter == 0 {
		return 0, 0, invalidf("ino %d has namespace %d with local counter 0", ino, namespace)
	}
	return namespace, localCounter, nil
}

// InodeAllocator hands out sequential inode ids for one branch namespace. It
// is a pure counter helper: durability of nextLocal is the caller's problem
// (RecoveryRoot.NextLocal / the database), and instances are not safe for
// concurrent use.
type InodeAllocator struct {
	namespace uint32
	nextLocal uint64
}

// NewInodeAllocator resumes allocation for namespace at nextLocal
// (1..MaxInodeLocalCounter+1; the +1 value resumes an already-exhausted
// namespace, whose next Allocate fails typed).
func NewInodeAllocator(namespace uint32, nextLocal uint64) (*InodeAllocator, error) {
	if namespace < 1 || namespace > MaxInodeNamespace {
		return nil, fmt.Errorf("%w: namespace %d outside 1..%d",
			ErrInodeNamespaceExhausted, namespace, MaxInodeNamespace)
	}
	if nextLocal < 1 || nextLocal > MaxInodeLocalCounter+1 {
		return nil, invalidf("namespace %d next local counter %d outside 1..%d",
			namespace, nextLocal, MaxInodeLocalCounter+1)
	}
	return &InodeAllocator{namespace: namespace, nextLocal: nextLocal}, nil
}

// Namespace reports the allocator's immutable namespace.
func (a *InodeAllocator) Namespace() uint32 { return a.namespace }

// NextLocal reports the next unassigned local counter value
// (MaxInodeLocalCounter+1 once exhausted), for persisting into a
// RecoveryRoot.
func (a *InodeAllocator) NextLocal() uint64 { return a.nextLocal }

// Allocate returns the next inode id, or the typed terminal
// ErrInodeCounterExhausted once the namespace's 2^32-1 ids are consumed. The
// counter never wraps.
func (a *InodeAllocator) Allocate() (uint64, error) {
	ino, err := ComposeIno(a.namespace, a.nextLocal)
	if err != nil {
		return 0, err
	}
	a.nextLocal++
	return ino, nil
}
