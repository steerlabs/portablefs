package cellhost

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAuthorityConfigIsStrictAndLauncherArgumentsUseOnlyFixedPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.json")
	payload := `{"version":1,"volume_id":"22222222-2222-4222-8222-222222222222","cell_id":"11111111-1111-4111-8111-111111111111","authorization_domain":"org","owner":"owner","product_issuer":"opensteer","authority_id":"v.example","authority_generation":3,"project_id":10001,"prior_strict_mounts_fenced":true}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadAuthorityConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	arguments := AuthorityArguments(config)
	for _, forbidden := range []string{"-listen", "/etc/", "/srv/portablefs/", "systemctl", "sh", "bash"} {
		if slices.Contains(arguments, forbidden) || strings.Contains(strings.Join(arguments, "\x00"), forbidden+config.VolumeID) {
			t.Fatalf("launcher arguments exposed forbidden input %q: %q", forbidden, arguments)
		}
	}
	for _, required := range []string{
		"/srv/portablefs-volume",
		"/run/portablefs-volume/authority-3.key",
		"/var/lib/portablefs-volume/visibility.membership",
		"/var/lib/portablefs-write-staging",
	} {
		if !slices.Contains(arguments, required) {
			t.Fatalf("launcher arguments omit fixed path %q: %q", required, arguments)
		}
	}

	if err := os.WriteFile(path, []byte(strings.TrimSuffix(payload, "}")+`,"command":"rm"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthorityConfig(path); err == nil {
		t.Fatal("unknown authority config field was accepted")
	}
}
