package localroutes

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrGitIndexUnsupported means the index is well-formed but this parser
// cannot enumerate its paths — version 4 stores path names prefix-compressed
// against the previous entry. Callers must treat it as "cannot prove", never
// as "nothing is tracked": the tracked-file guard is a refusal to activate a
// route over version-controlled content, so an unreadable index has to be
// reported honestly rather than silently passed.
var ErrGitIndexUnsupported = errors.New("localroutes: unsupported git index version")

// ParseGitIndexPaths extracts the tracked paths from a .git/index file
// (versions 2 and 3). It is deliberately a pure function over bytes: the
// activation guard reads the index through the volume client and does its own
// I/O policy, and this half stays testable without one.
//
// The format is the documented one: a 12-byte header ("DIRC", version, entry
// count), then per entry 62 bytes of stat/oid/flags, an optional 2-byte
// extended-flags word (version 3 only, when the extended bit is set), and a
// NUL-terminated path padded with NULs to a multiple of 8 bytes.
func ParseGitIndexPaths(data []byte) ([]string, error) {
	const headerLen = 12
	if len(data) < headerLen || string(data[:4]) != "DIRC" {
		return nil, fmt.Errorf("localroutes: not a git index")
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("%w: %d", ErrGitIndexUnsupported, version)
	}
	count := binary.BigEndian.Uint32(data[8:12])
	// Try the two repository object formats Git defines. SHA-256 repositories
	// widen both each entry's object ID and the trailer checksum from 20 to 32
	// bytes; guessing one layout would turn a valid index into a false-clean
	// parse under the other.
	var parsedWithoutTrailer, checksumMismatch bool
	for _, hashLen := range []int{sha1.Size, sha256.Size} {
		paths, entriesEnd, err := parseGitIndexEntries(data, version, count, hashLen)
		if err != nil {
			if errors.Is(err, ErrGitIndexUnsupported) {
				return nil, err
			}
			continue
		}
		parsedWithoutTrailer = true
		if entriesEnd+hashLen != len(data) {
			// Anything between entries and checksum is an extension. In
			// particular link (split index) and sdir (sparse index) can name
			// tracked paths absent from the entries above, so partial parsing is
			// not proof and must fail closed.
			continue
		}
		payload, trailer := data[:entriesEnd], data[entriesEnd:]
		var valid bool
		switch hashLen {
		case sha1.Size:
			sum := sha1.Sum(payload)
			valid = bytes.Equal(sum[:], trailer)
		case sha256.Size:
			sum := sha256.Sum256(payload)
			valid = bytes.Equal(sum[:], trailer)
		}
		if !valid {
			// The other object format changes every entry's fixed width. An
			// accidental length match under this layout must not prevent trying
			// that exact alternative before reporting corruption.
			checksumMismatch = true
			continue
		}
		return paths, nil
	}
	if checksumMismatch {
		return nil, errors.New("localroutes: git index checksum does not match its contents")
	}
	if parsedWithoutTrailer {
		return nil, fmt.Errorf("%w: split, sparse, or other index extensions are not a complete tracked-path proof", ErrGitIndexUnsupported)
	}
	return nil, errors.New("localroutes: git index entries are truncated or malformed")
}

func parseGitIndexEntries(data []byte, version, count uint32, hashLen int) ([]string, int, error) {
	const headerLen = 12
	fixedLen := 42 + hashLen // 40-byte stat data, object ID, 2-byte flags
	if uint64(count) > uint64(len(data)/fixedLen) {
		return nil, 0, errors.New("localroutes: git index entry count exceeds its bytes")
	}
	paths := make([]string, 0, int(count))
	off := headerLen
	for i := uint32(0); i < count; i++ {
		start := off
		if off+fixedLen > len(data) {
			return nil, 0, fmt.Errorf("localroutes: git index truncated in entry %d", i)
		}
		mode := binary.BigEndian.Uint32(data[off+24 : off+28])
		if mode&0o170000 == 0o040000 {
			return nil, 0, fmt.Errorf("%w: sparse-directory entry %d", ErrGitIndexUnsupported, i)
		}
		flags := binary.BigEndian.Uint16(data[off+fixedLen-2 : off+fixedLen])
		off += fixedLen
		if version == 3 && flags&0x4000 != 0 {
			if off+2 > len(data) {
				return nil, 0, fmt.Errorf("localroutes: git index truncated in entry %d", i)
			}
			off += 2
		}
		end := off
		for end < len(data) && data[end] != 0 {
			end++
		}
		if end >= len(data) {
			return nil, 0, fmt.Errorf("localroutes: git index entry %d has an unterminated path", i)
		}
		pathLen := end - off
		if encoded := int(flags & 0x0fff); encoded != 0x0fff && encoded != pathLen {
			return nil, 0, fmt.Errorf("localroutes: git index entry %d path length is %d, header says %d", i, pathLen, encoded)
		}
		paths = append(paths, string(data[off:end]))
		// Entries are padded with 1..8 NULs so the next one starts 8-byte
		// aligned relative to the start of the index.
		off = start + ((end-start)/8+1)*8
	}
	return paths, off, nil
}

// FirstTrackedMatch returns the first tracked path the rule set would route,
// with the route root and rule that decided it. Activation must fail on a
// non-empty result: a machine-local route over version-controlled content
// would hide committed files from every other machine while git still
// believes it owns them.
func (rs RuleSet) FirstTrackedMatch(trackedPaths []string) (path, root, rule string, found bool) {
	if rs.Empty() {
		return "", "", "", false
	}
	for _, p := range trackedPaths {
		if root, rule, ok := rs.MatchRule(p); ok {
			return p, root, rule, true
		}
	}
	return "", "", "", false
}
