// Package mountmembership defines the shared durable mount-membership format.
// Callers own safe file access, locking, persistence and quiescence proofs.
package mountmembership

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
)

const (
	Filename = "mount.membership"
	Header   = "PFS-MEMBERSHIP-1"
	MaxBytes = 1 << 20
)

type Profile string

const (
	ProfileLinux          Profile = "linux"
	ProfileFSKitExclusive Profile = "fskit-exclusive"
	ProfileCacheless      Profile = "cacheless"
)

type Record struct {
	SessionID [16]byte
	Profile   Profile
}

func validProfile(profile Profile) bool {
	return profile == ProfileLinux || profile == ProfileFSKitExclusive || profile == ProfileCacheless
}

func volumeLine(volumeID string) ([]byte, error) {
	if len(volumeID) == 0 || len(volumeID) > (MaxBytes-len(Header)-2)/2 {
		return nil, fmt.Errorf("mountmembership: invalid volume identity size")
	}
	return []byte(hex.EncodeToString([]byte(volumeID))), nil
}

// Encode returns the complete canonical file, sorting a copy of records by
// session ID. The bound is checked before allocating the encoded file so the
// durable writer can refuse growth before changing its on-disk state.
func Encode(volumeID string, records []Record) ([]byte, error) {
	volume, err := volumeLine(volumeID)
	if err != nil {
		return nil, err
	}
	// The shortest record is 32 hex bytes, a tab, "linux", and a newline.
	if len(records) > MaxBytes/39 {
		return nil, fmt.Errorf("mountmembership: file exceeds %d bytes", MaxBytes)
	}
	size := len(Header) + len(volume) + 2
	for _, record := range records {
		if record.SessionID == ([16]byte{}) || !validProfile(record.Profile) {
			return nil, fmt.Errorf("mountmembership: invalid session or profile")
		}
		size += 34 + len(record.Profile)
		if size > MaxBytes {
			return nil, fmt.Errorf("mountmembership: file exceeds %d bytes", MaxBytes)
		}
	}
	ordered := append([]Record(nil), records...)
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(ordered[i].SessionID[:], ordered[j].SessionID[:]) < 0
	})
	encoded := make([]byte, 0, size)
	encoded = append(encoded, Header...)
	encoded = append(encoded, '\n')
	encoded = append(encoded, volume...)
	encoded = append(encoded, '\n')
	for i, record := range ordered {
		if i > 0 && record.SessionID == ordered[i-1].SessionID {
			return nil, fmt.Errorf("mountmembership: duplicate session ID")
		}
		encoded = hex.AppendEncode(encoded, record.SessionID[:])
		encoded = append(encoded, '\t')
		encoded = append(encoded, record.Profile...)
		encoded = append(encoded, '\n')
	}
	return encoded, nil
}

// Decode validates the whole file against the expected volume's exact bytes.
// On any error it returns nil, never a usable prefix or a false empty set.
// Records must already be sorted; no malformed or trailing line is skipped.
func Decode(data []byte, expectedVolumeID string) ([]Record, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("mountmembership: file exceeds %d bytes", MaxBytes)
	}
	volume, err := volumeLine(expectedVolumeID)
	if err != nil {
		return nil, err
	}
	header, remaining, ok := bytes.Cut(data, []byte{'\n'})
	if !ok || string(header) != Header {
		return nil, fmt.Errorf("mountmembership: invalid header")
	}
	binding, remaining, ok := bytes.Cut(remaining, []byte{'\n'})
	if !ok || !bytes.Equal(binding, volume) {
		return nil, fmt.Errorf("mountmembership: unequal volume binding")
	}
	var records []Record
	for len(remaining) != 0 {
		line, rest, terminated := bytes.Cut(remaining, []byte{'\n'})
		if !terminated || len(line) < 34 || line[32] != '\t' {
			return nil, fmt.Errorf("mountmembership: malformed record")
		}
		var record Record
		for _, digit := range line[:32] {
			if !(digit >= '0' && digit <= '9' || digit >= 'a' && digit <= 'f') {
				return nil, fmt.Errorf("mountmembership: session ID is not lowercase hex")
			}
		}
		if _, err := hex.Decode(record.SessionID[:], line[:32]); err != nil {
			return nil, fmt.Errorf("mountmembership: decode session ID: %w", err)
		}
		record.Profile = Profile(line[33:])
		if record.SessionID == ([16]byte{}) || !validProfile(record.Profile) {
			return nil, fmt.Errorf("mountmembership: invalid session or profile")
		}
		if len(records) > 0 && bytes.Compare(records[len(records)-1].SessionID[:], record.SessionID[:]) >= 0 {
			return nil, fmt.Errorf("mountmembership: duplicate or unordered session ID")
		}
		records = append(records, record)
		remaining = rest
	}
	return records, nil
}
