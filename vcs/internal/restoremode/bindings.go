package restoremode

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	bindingsMagic      = "PFSRBND1"
	bindingsVersion    = uint32(1)
	bindingHeaderBytes = len(bindingsMagic) + 4 + 4
	bindingRecordBytes = 4 + 16
)

type Bindings struct {
	identities [][16]byte
	byIdentity map[[16]byte]uint32
	digest     [32]byte
}

func LoadBindings(path string, maxEntries uint32) (*Bindings, error) {
	if maxEntries == 0 {
		return nil, errors.New("restoremode: bindings bound must be positive")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open restore bindings: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < int64(bindingHeaderBytes+sha256.Size) {
		return nil, errors.New("restoremode: invalid restore bindings size or type")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(bindingHeaderBytes)+int64(maxEntries)*bindingRecordBytes+sha256.Size+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, errors.New("restoremode: incomplete restore bindings")
	}
	if string(raw[:len(bindingsMagic)]) != bindingsMagic || binary.LittleEndian.Uint32(raw[len(bindingsMagic):bindingHeaderBytes-4]) != bindingsVersion {
		return nil, errors.New("restoremode: invalid restore bindings header")
	}
	count := binary.LittleEndian.Uint32(raw[bindingHeaderBytes-4 : bindingHeaderBytes])
	want := uint64(bindingHeaderBytes) + uint64(count)*bindingRecordBytes + sha256.Size
	if count == 0 || count > maxEntries || uint64(len(raw)) != want {
		return nil, errors.New("restoremode: invalid restore bindings count")
	}
	body, seal := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
	digest := sha256.Sum256(body)
	if !equalBytes(digest[:], seal) {
		return nil, errors.New("restoremode: restore bindings SHA-256 seal mismatch")
	}
	b := &Bindings{identities: make([][16]byte, count), byIdentity: make(map[[16]byte]uint32, count), digest: digest}
	var prior uint32
	for i := uint32(0); i < count; i++ {
		at := bindingHeaderBytes + int(i)*bindingRecordBytes
		record := body[at : at+bindingRecordBytes]
		entry := binary.LittleEndian.Uint32(record[:4])
		if i > 0 && entry <= prior {
			return nil, fmt.Errorf("restoremode: binding index %d is not after %d", entry, prior)
		}
		if entry >= count {
			return nil, fmt.Errorf("restoremode: binding index %d is outside the entry count", entry)
		}
		prior = entry
		copy(b.identities[entry][:], record[4:])
		if b.identities[entry] == ([16]byte{}) {
			return nil, fmt.Errorf("restoremode: binding %d has zero identity", i)
		}
		// Hardlink aliases intentionally repeat an inode identity. The first
		// record is the namespace-plan entry that created the inode and is also
		// the sole entry used by the hydrator's drain order.
		if _, duplicate := b.byIdentity[b.identities[entry]]; !duplicate {
			b.byIdentity[b.identities[entry]] = entry
		}
	}
	return b, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

func (b *Bindings) Len() int {
	if b == nil {
		return 0
	}
	return len(b.identities)
}

func (b *Bindings) Entry(identity [16]byte) (uint32, bool) {
	if b == nil {
		return 0, false
	}
	entry, ok := b.byIdentity[identity]
	return entry, ok
}

func (b *Bindings) Identity(entry uint32) ([16]byte, bool) {
	if b == nil || uint64(entry) >= uint64(len(b.identities)) {
		return [16]byte{}, false
	}
	return b.identities[entry], true
}

func (b *Bindings) IdentityMap() map[[16]byte]uint32 {
	out := make(map[[16]byte]uint32, len(b.byIdentity))
	for identity, entry := range b.byIdentity {
		out[identity] = entry
	}
	return out
}

func (b *Bindings) Digest() [32]byte {
	if b == nil {
		return [32]byte{}
	}
	return b.digest
}
