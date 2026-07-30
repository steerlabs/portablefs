package cli

import (
	"strings"
	"testing"
)

func TestPortableFSKernelPathsIsolatesOtherFSKitProducts(t *testing.T) {
	mounts := []kernelMountIdentity{
		{
			fsType: "portablefs",
			path:   "/Users/test/.opensteer/work",
			source: "pfs://att_AAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			fsType: "portablefs",
			path:   "/Users/test/.opensteer/foreign-malformed",
			source: "foreign-resource",
		},
		{
			fsType: "pfs",
			path:   "/Users/test/PortableFS/work",
			source: "pfs://att_BBBBBBBBBBBBBBBBBBBBBB",
		},
	}

	paths, err := portableFSKernelPaths(mounts)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/Users/test/PortableFS/work" {
		t.Fatalf("paths = %v, want only the OSS PortableFS mount", paths)
	}
}

func TestPortableFSKernelPathsRejectsMalformedOwnedMount(t *testing.T) {
	_, err := portableFSKernelPaths([]kernelMountIdentity{{
		fsType: "pfs",
		path:   "/Users/test/PortableFS/broken",
		source: "pfs://not-an-attach-ref",
	}})
	if err == nil || !strings.Contains(err.Error(), "invalid attach source") {
		t.Fatalf("error = %v, want invalid owned attach source", err)
	}
}

func TestValidateFSKitKernelIdentityRequiresExactProductAndSource(t *testing.T) {
	const source = "pfs://att_AAAAAAAAAAAAAAAAAAAAAA"
	if err := validateFSKitKernelIdentity("pfs", source, "pfs", source); err != nil {
		t.Fatalf("exact identity: %v", err)
	}
	if err := validateFSKitKernelIdentity("portablefs", source, "pfs", source); err == nil {
		t.Fatal("foreign FSKit product accepted as PortableFS")
	}
	if err := validateFSKitKernelIdentity("portablefs", source, "portablefs", source); err == nil {
		t.Fatal("foreign recorded type redefined the signed PortableFS identity")
	}
	if err := validateFSKitKernelIdentity(
		"pfs",
		"pfs://att_BBBBBBBBBBBBBBBBBBBBBB",
		"pfs",
		source,
	); err == nil {
		t.Fatal("wrong attach source accepted as PortableFS mount")
	}
}

func TestFSKitTypeOverrideCannotChangeSignedIdentity(t *testing.T) {
	_, err := fskitConfigFromEnv(func(name string) string {
		if name == fskitTypeEnv {
			return "portablefs"
		}
		return ""
	})
	if err == nil || !strings.Contains(err.Error(), "signed FSKit identity") {
		t.Fatalf("error = %v, want signed identity mismatch", err)
	}
}
