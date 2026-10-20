// Package pathcomponent validates raw filesystem name components.
package pathcomponent

import "bytes"

// ValidName admits one raw component with the filesystem's 255-byte bound.
// It preserves opaque bytes; UTF-8 is not a filesystem-name requirement.
func ValidName(name []byte) bool {
	return len(name) > 0 && len(name) <= 255 && !bytes.Equal(name, []byte(".")) &&
		!bytes.Equal(name, []byte("..")) && !bytes.ContainsAny(name, "\x00/")
}
