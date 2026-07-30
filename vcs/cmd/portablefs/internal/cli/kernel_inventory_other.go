//go:build !darwin && !linux

package cli

func portableFSKernelInventory() ([]string, error) { return nil, nil }
