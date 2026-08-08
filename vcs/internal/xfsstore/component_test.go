package xfsstore

import (
	"strings"
	"testing"
)

func TestValidateComponent(t *testing.T) {
	t.Parallel()
	valid := []string{"a", "hello world", "..x", "x..", "é", strings.Repeat("x", 255)}
	for _, name := range valid {
		if err := ValidateComponent(name); err != nil {
			t.Errorf("ValidateComponent(%q): %v", name, err)
		}
	}
	invalid := []string{"", ".", "..", "/", "a/b", "a\x00b", strings.Repeat("x", 256)}
	for _, name := range invalid {
		if err := ValidateComponent(name); err == nil {
			t.Errorf("ValidateComponent(%q) succeeded", name)
		}
	}
}

func FuzzValidateComponent(f *testing.F) {
	for _, seed := range []string{"", ".", "..", "file", "a/b", "a\x00b", "é"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		err := ValidateComponent(name)
		if err == nil {
			if name == "" || name == "." || name == ".." || len(name) > nameMax || strings.ContainsAny(name, "/\x00") {
				t.Fatalf("accepted unsafe component %q", name)
			}
		}
	})
}

func TestValidateXattr(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"user.comment", "user.com.apple.FinderInfo"} {
		if err := ValidateXattr(name); err != nil {
			t.Errorf("ValidateXattr(%q): %v", name, err)
		}
	}
	for _, name := range []string{"", "security.capability", "trusted.overlay.opaque", "system.posix_acl_access", "user.portablefs.secret"} {
		if err := ValidateXattr(name); err == nil {
			t.Errorf("ValidateXattr(%q) succeeded", name)
		}
	}
}
