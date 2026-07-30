package cli

import (
	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
)

// resolveStrategy picks the ONE mount transport per platform: FSKit on
// macOS, FUSE on Linux. The choice is pure and never depends on installed
// packages or mutable host state.
func resolveStrategy(explicit, goos string) (string, error) {
	transport, err := mounthost.SelectTransport(explicit, goos)
	return string(transport), err
}
