//go:build !darwin && !linux

package cli

// platformKernelMountsAt has no kernel mount table to consult on unsupported
// platforms; PortableFS cannot mount there either.
func platformKernelMountsAt(string) ([]kernelMountIdentity, error) { return nil, nil }
