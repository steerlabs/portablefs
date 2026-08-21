package hydrator

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/archive"
)

// The manifest-entry to inode-identity table (restore-mode.md, "Authority <->
// hydrator socket protocol"): the restorer writes it as it materializes the
// namespace, and the authority loads it at restore-mode start to key its
// hydration map by restored-inode identity rather than by path. Renames then
// cannot move chunk state, and the members of a hardlink group share one map
// entry by construction because they share one inode identity.
//
// The contract pins the semantic content — entryIndex u32 to a 16-byte inode
// identity, in entry order, sealed with a trailing SHA-256 — and this file pins
// the byte layout around it:
//
//	"PFSRBND1" | version u32 | count u32 | (entryIndex u32 | identity 16B)... |
//	SHA-256 over every preceding byte
//
// All integers are little-endian, matching the manifest format.
const (
	bindingsMagic   = "PFSRBND1"
	BindingsVersion = uint32(1)
	bindingRecord   = 4 + 16
	bindingsHeader  = len(bindingsMagic) + 4 + 4
	bindingsSeal    = sha256.Size
)

// Binding is one entry's restored inode identity.
type Binding struct {
	EntryIndex uint32
	Identity   [16]byte
}

// EncodeBindings renders the table. Records must be in entry order, which is
// the order the restorer materializes them in, so a consumer can index directly
// rather than search.
func EncodeBindings(bindings []Binding) ([]byte, error) {
	if len(bindings) == 0 {
		return nil, fmt.Errorf("%w: a restored volume always has at least its root entry", ErrInvalid)
	}
	if len(bindings) > archive.MaxEntries {
		return nil, fmt.Errorf("%w: %d bindings exceed the %d entry bound", ErrInvalid, len(bindings), archive.MaxEntries)
	}
	out := make([]byte, 0, bindingsHeader+len(bindings)*bindingRecord+bindingsSeal)
	out = append(out, bindingsMagic...)
	out = binary.LittleEndian.AppendUint32(out, BindingsVersion)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(bindings)))
	previous := uint32(0)
	for index, binding := range bindings {
		if index > 0 && binding.EntryIndex <= previous {
			return nil, fmt.Errorf("%w: binding %d is not in entry order", ErrInvalid, index)
		}
		previous = binding.EntryIndex
		out = binary.LittleEndian.AppendUint32(out, binding.EntryIndex)
		out = append(out, binding.Identity[:]...)
	}
	seal := sha256.Sum256(out)
	return append(out, seal[:]...), nil
}

// DecodeBindings parses and verifies the table. The count is checked against
// the bytes actually present before anything is allocated, and the seal is
// checked before any record is believed.
func DecodeBindings(payload []byte) ([]Binding, error) {
	if len(payload) < bindingsHeader+bindingsSeal {
		return nil, fmt.Errorf("%w: bindings table is %d bytes", ErrInvalid, len(payload))
	}
	if string(payload[:len(bindingsMagic)]) != bindingsMagic {
		return nil, fmt.Errorf("%w: bindings table has no magic", ErrInvalid)
	}
	body := payload[len(bindingsMagic):]
	version := binary.LittleEndian.Uint32(body[:4])
	if version != BindingsVersion {
		return nil, fmt.Errorf("%w: bindings table version %d is not %d", ErrInvalid, version, BindingsVersion)
	}
	count := uint64(binary.LittleEndian.Uint32(body[4:8]))
	if count > uint64(archive.MaxEntries) {
		return nil, fmt.Errorf("%w: bindings table claims %d entries", ErrInvalid, count)
	}
	want := uint64(bindingsHeader) + count*bindingRecord + uint64(bindingsSeal)
	if uint64(len(payload)) != want {
		return nil, fmt.Errorf("%w: bindings table is %d bytes for %d entries, expected %d", ErrInvalid, len(payload), count, want)
	}
	seal := sha256.Sum256(payload[:len(payload)-bindingsSeal])
	if subtle.ConstantTimeCompare(seal[:], payload[len(payload)-bindingsSeal:]) != 1 {
		return nil, fmt.Errorf("%w: bindings table seal does not match its content", ErrInvalid)
	}
	bindings := make([]Binding, 0, count)
	at := bindingsHeader
	previous := uint32(0)
	for index := uint64(0); index < count; index++ {
		binding := Binding{EntryIndex: binary.LittleEndian.Uint32(payload[at : at+4])}
		copy(binding.Identity[:], payload[at+4:at+bindingRecord])
		if index > 0 && binding.EntryIndex <= previous {
			return nil, fmt.Errorf("%w: binding %d is not in entry order", ErrInvalid, index)
		}
		previous = binding.EntryIndex
		bindings = append(bindings, binding)
		at += bindingRecord
	}
	return bindings, nil
}
