//go:build darwin && !portablefs_devhost

package cli

import "testing"

func TestSourceMacOSBundleIdentitySupportsExactCustomForkIdentity(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	const appID = "org.example.portablefs"
	addTestBundleIdentity(t, app, appID)
	got, err := sourceMacOSBundleIdentity(app)
	if err != nil {
		t.Fatal(err)
	}
	if got != appID {
		t.Fatalf("app id = %q, want %q", got, appID)
	}
}
