//go:build linux

package xfsstore

import "testing"

func TestAuthorityKernelFloor(t *testing.T) {
	for _, test := range []struct {
		release string
		ok      bool
	}{
		{"4.19.300", false}, {"5.10.250", false}, {"5.15.180-vendor", false},
		{"5.16.99", false}, {"5.17.0-rc1", false}, {"5.17.0", true},
		{"5.17.1-custom", true}, {"6.8.0-100-generic", true}, {"6.12.100", true},
		{"7.0.0", true}, {"", false}, {"5.x.0", false}, {"5.17", false},
	} {
		t.Run(test.release, func(t *testing.T) {
			if err := validateAuthorityKernel(test.release); (err == nil) != test.ok {
				t.Fatalf("kernel %q: %v; supported=%v", test.release, err, test.ok)
			}
		})
	}
	if err := checkAuthorityKernel(); err != nil {
		t.Fatal(err)
	}
}
