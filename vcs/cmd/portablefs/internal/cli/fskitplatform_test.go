package cli

import "testing"

func TestFSKitSupportedProductVersions(t *testing.T) {
	for _, version := range []string{"26.0", "26.6.1", "27.0", "27.2"} {
		if err := validateFSKitProductVersion(version); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []string{"", "beta", "25.7", "28.0", "0"} {
		if err := validateFSKitProductVersion(version); err == nil {
			t.Fatalf("accepted %q", version)
		}
	}
}
