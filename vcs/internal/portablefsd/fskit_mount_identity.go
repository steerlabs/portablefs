package portablefsd

import (
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
)

func validateExactFSKitKernelMount(fsType, source, attachRef string) error {
	expectedSource := fskitidentity.ResourcePrefix + attachRef
	if fsType != fskitidentity.FSType || source != expectedSource {
		return fmt.Errorf(
			"kernel mount is %s from %s, want %s from %s",
			fsType,
			source,
			fskitidentity.FSType,
			expectedSource,
		)
	}
	return nil
}
