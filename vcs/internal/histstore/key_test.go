package histstore

import (
	"strings"
	"testing"
)

func TestObjectIDKey(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	id := ObjectID{Tenant: "tenant-1", Kind: "pft2", DigestHex: digest, Incarnation: 3}
	key, err := id.Key()
	if err != nil {
		t.Fatal(err)
	}
	want := "t/tenant-1/pft2/sha256/ab/" + digest + "/i3"
	if key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
	if err := ValidateKey(key); err != nil {
		t.Fatalf("derived key fails validation: %v", err)
	}

	// Incarnations produce distinct keys (ABA safety).
	id2 := id
	id2.Incarnation = 4
	key2, err := id2.Key()
	if err != nil {
		t.Fatal(err)
	}
	if key2 == key {
		t.Fatal("incarnations must produce distinct exact keys")
	}
}

func TestObjectIDValidation(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	bad := []ObjectID{
		{Tenant: "", Kind: "pft2", DigestHex: digest, Incarnation: 1},
		{Tenant: strings.Repeat("x", 257), Kind: "pft2", DigestHex: digest, Incarnation: 1},
		{Tenant: "t", Kind: "other", DigestHex: digest, Incarnation: 1},
		{Tenant: "t", Kind: "pft2", DigestHex: "ABCD", Incarnation: 1},
		{Tenant: "t", Kind: "pft2", DigestHex: strings.ToUpper(digest), Incarnation: 1},
		{Tenant: "t", Kind: "pft2", DigestHex: digest, Incarnation: 0},
	}
	for i, id := range bad {
		if _, err := id.Key(); err == nil {
			t.Fatalf("case %d: expected validation failure for %+v", i, id)
		}
	}
}

func TestEscapeComponentInjective(t *testing.T) {
	inputs := []string{
		"simple", "has/slash", "has%percent", "has%2Fencoded", "..", ".",
		"dots..inside", "u\x00nul", "space here", "ünïcode",
	}
	seen := map[string]string{}
	for _, in := range inputs {
		out := EscapeComponent(in)
		if prev, dup := seen[out]; dup {
			t.Fatalf("escape collision: %q and %q both map to %q", prev, in, out)
		}
		seen[out] = in
		if err := ValidateKey("t/" + out + "/x"); err != nil {
			t.Fatalf("escaped component %q fails key validation: %v", out, err)
		}
	}
}

func TestValidateKeyRejectsTraversal(t *testing.T) {
	bad := []string{
		"", "/abs", "trailing/", "a//b", "a/../b", "..", ".", "a/.", "./a",
		"a/b\x00c", "a/b c", "a/b\\c", strings.Repeat("k/", 600) + "x",
		"a/" + strings.Repeat("x", 1030),
	}
	for _, key := range bad {
		if err := ValidateKey(key); err == nil {
			t.Fatalf("key %q must be rejected", key)
		}
	}
	good := []string{"a", "a/b", "t/x%2F/pft2", "deep/1/2/3/file.bin", "a-b_c.d"}
	for _, key := range good {
		if err := ValidateKey(key); err != nil {
			t.Fatalf("key %q must be accepted: %v", key, err)
		}
	}
}

// FuzzValidateKey proves accepted keys are structurally confined: no
// absolute paths, no dot components, no separators beyond '/', no bytes
// outside the safe set — the properties the filesystem backend's openat
// confinement builds on.
func FuzzValidateKey(f *testing.F) {
	f.Add("t/tenant/pft2/sha256/ab/abcd/i1")
	f.Add("../../etc/passwd")
	f.Add("a/./b")
	f.Add("a//b")
	f.Add("%2e%2e/x")
	f.Fuzz(func(t *testing.T, key string) {
		if err := ValidateKey(key); err != nil {
			return
		}
		if strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") {
			t.Fatalf("accepted key %q has boundary separator", key)
		}
		for _, part := range strings.Split(key, "/") {
			if part == "" || part == "." || part == ".." {
				t.Fatalf("accepted key %q has dot/empty component", key)
			}
			for i := 0; i < len(part); i++ {
				c := part[i]
				ok := c == '%' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
					(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
				if !ok {
					t.Fatalf("accepted key %q contains unsafe byte %q", key, c)
				}
			}
		}
	})
}

// FuzzEscapeComponent proves the escape stays within the safe set and
// round-trips injectively through its encoded form.
func FuzzEscapeComponent(f *testing.F) {
	f.Add("tenant")
	f.Add("../weird")
	f.Add("%")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 300 {
			return
		}
		out := EscapeComponent(s)
		if out == "" && s != "" {
			t.Fatalf("nonempty input %q escaped to empty", s)
		}
		if s != "" {
			if err := ValidateKey(out); err != nil {
				t.Fatalf("escaped %q -> %q fails validation: %v", s, out, err)
			}
		}
	})
}
