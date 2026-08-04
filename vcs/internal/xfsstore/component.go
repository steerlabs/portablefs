package xfsstore

import (
	"io/fs"
	"strings"
)

const nameMax = 255

// ValidateComponent accepts exactly one Linux directory-entry name. In
// particular, path cleaning is wrong here: it could turn malformed authority
// input into a different valid name.
func ValidateComponent(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > nameMax ||
		strings.IndexByte(name, 0) >= 0 || strings.IndexByte(name, '/') >= 0 {
		return fs.ErrInvalid
	}
	return nil
}

// ValidateXattr permits only portable user attributes. PortableFS internal
// metadata, Linux security state, ACL internals, and trusted attributes never
// cross the remote boundary.
func ValidateXattr(name string) error {
	if name == "" || len(name) > nameMax || strings.IndexByte(name, 0) >= 0 ||
		!strings.HasPrefix(name, "user.") ||
		strings.HasPrefix(name, "user.portablefs.") {
		return ErrForbiddenXattr
	}
	return nil
}
