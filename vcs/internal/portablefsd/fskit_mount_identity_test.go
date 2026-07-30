package portablefsd

import "testing"

func TestValidateExactFSKitKernelMountIsolatesProducts(t *testing.T) {
	const (
		ref    = "att_AAAAAAAAAAAAAAAAAAAAAA"
		source = "pfs://" + ref
	)
	if err := validateExactFSKitKernelMount("pfs", source, ref); err != nil {
		t.Fatalf("exact PortableFS mount: %v", err)
	}
	if err := validateExactFSKitKernelMount("portablefs", source, ref); err == nil {
		t.Fatal("foreign FSKit product accepted for exact unmount")
	}
	if err := validateExactFSKitKernelMount(
		"pfs",
		"pfs://att_BBBBBBBBBBBBBBBBBBBBBB",
		ref,
	); err == nil {
		t.Fatal("wrong attach source accepted for exact unmount")
	}
}
