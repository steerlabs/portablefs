//go:build darwin && cgo

package appgroupcontainer

import (
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/darwinnative"
)

func resolveNative(identifier string) (string, error) {
	path, err := darwinnative.ResolveAppGroupContainer(identifier)
	if err != nil {
		return "", fmt.Errorf("resolve app-group container %q: %w", identifier, err)
	}
	return path, nil
}
