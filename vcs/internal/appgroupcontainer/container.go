// Package appgroupcontainer resolves the signed macOS app-group container for
// the current process. Callers must use the returned URL-derived path; spelling
// ~/Library/Group Containers/<group> does not acquire macOS Data Vault access.
package appgroupcontainer

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Resolve returns the canonical absolute filesystem path supplied by the
// platform app-group API for the exact signed group identifier.
func Resolve(identifier string) (string, error) {
	if identifier == "" || strings.IndexByte(identifier, 0) >= 0 {
		return "", fmt.Errorf("resolve app-group container: invalid identifier %q", identifier)
	}
	path, err := resolveNative(identifier)
	if err != nil {
		return "", err
	}
	return validateResolvedPath(identifier, path)
}

func validateResolvedPath(identifier, path string) (string, error) {
	if !filepath.IsAbs(path) || path == string(filepath.Separator) || filepath.Clean(path) != path {
		return "", fmt.Errorf("resolve app-group container %q: platform returned invalid path %q", identifier, path)
	}
	return path, nil
}
