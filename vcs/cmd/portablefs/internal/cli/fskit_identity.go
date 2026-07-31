package cli

import (
	"fmt"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
)

// kernelMountIdentity is the product-neutral subset of a kernel mount record
// needed for ownership decisions. The filesystem type and resource scheme are
// both immutable parts of this product's FSKit identity.
type kernelMountIdentity struct {
	fsType string
	path   string
	source string
}

func isPortableFSKernelType(fsType string) bool {
	return fsType == fskitidentity.FSType
}

// portableFSKernelPaths returns only mounts owned by this PortableFS release.
// Foreign FSKit mounts are ignored before their source is parsed: another
// product's malformed source must never poison PortableFS lifecycle checks.
func portableFSKernelPaths(mounts []kernelMountIdentity) ([]string, error) {
	var paths []string
	for _, mount := range mounts {
		if !isPortableFSKernelType(mount.fsType) {
			continue
		}
		ref, ok := strings.CutPrefix(mount.source, fskitidentity.ResourcePrefix)
		if !ok || !mountid.ValidAttachRef(ref) {
			return nil, fmt.Errorf(
				"PortableFS kernel mount at %s has invalid attach source %q",
				mount.path,
				mount.source,
			)
		}
		paths = append(paths, mount.path)
	}
	return paths, nil
}

func validateFSKitKernelIdentity(
	actualType, actualSource, expectedType, expectedSource string,
) error {
	if expectedType != fskitidentity.FSType {
		return fmt.Errorf(
			"recorded filesystem type is %q, want signed release type %q",
			expectedType,
			fskitidentity.FSType,
		)
	}
	if actualType != fskitidentity.FSType {
		return fmt.Errorf(
			"filesystem type is %q, want %q",
			actualType,
			fskitidentity.FSType,
		)
	}
	if actualSource != expectedSource {
		return fmt.Errorf("mount source is %q, want %q", actualSource, expectedSource)
	}
	return nil
}
