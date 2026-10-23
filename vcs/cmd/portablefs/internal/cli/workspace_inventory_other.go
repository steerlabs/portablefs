//go:build !linux

package cli

func platformManagedMountStates() ([]mountState, error) { return nil, nil }
