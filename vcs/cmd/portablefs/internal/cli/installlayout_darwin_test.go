//go:build darwin

package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
)

func selectedTestAppID() string {
	if compiledMacOSInstallLayout.requiredAppID != "" {
		return compiledMacOSInstallLayout.requiredAppID
	}
	return "org.example.portablefs"
}

func writeBundleFixturePlist(t *testing.T, path string, value map[string]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/plutil", "-convert", "xml1", path).CombinedOutput(); err != nil {
		t.Fatalf("write fixture plist: %v: %s", err, out)
	}
}

func makeCompleteBundleFixture(t *testing.T, root string, layout macOSInstallLayout, appID string) string {
	t.Helper()
	app := makeFakeMacOSAppWithLayout(t, root, "fixture", layout)
	addTestBundleIdentityWithLayout(t, app, appID, layout)
	extension := filepath.Join(app, "Contents", "Extensions", layout.extensionExecutable+".appex")
	writeBundleFixturePlist(t, filepath.Join(extension, "Contents", "Info.plist"), map[string]any{
		"CFBundleIdentifier":         appID + "." + layout.extensionExecutable,
		"CFBundleExecutable":         layout.extensionExecutable,
		"CFBundleShortVersionString": "1.2.3",
		"PFSAppGroupIdentifier":      fskitidentity.AppGroup,
		"EXAppExtensionAttributes": map[string]any{
			"EXExtensionPointIdentifier": fskitExtensionType,
			"FSShortName":                "pfs", "FSSupportsGenericURLResources": true,
			"FSSupportedSchemes": []string{"dev.portablefs.oss"},
			"FSPersonalities":    map[string]any{"PortableFSPersonality": map[string]any{"FSName": "pfs"}},
		},
	})
	service := filepath.Join(app, "Contents", "Library", "LaunchAgents", "PortableFSDService.app")
	writeBundleFixturePlist(t, filepath.Join(service, "Contents", "Info.plist"), map[string]any{
		"CFBundleDevelopmentRegion": "en", "CFBundleExecutable": "portablefsd",
		"CFBundleIdentifier": appID + ".PortableFSDService", "CFBundleInfoDictionaryVersion": "6.0",
		"CFBundleName": "PortableFSDService", "CFBundlePackageType": "APPL",
		"CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "1",
		"LSBackgroundOnly": true, "LSMinimumSystemVersion": layout.serviceMinimumOS,
		"NSLocalNetworkUsageDescription":   "PortableFS connects to filesystem authorities on your local network to mount and access your files.",
		"NSNetworkVolumesUsageDescription": "PortableFS accesses the volumes you mount to keep their files consistent with the filesystem authority.",
	})
	writeBundleFixturePlist(t, filepath.Join(filepath.Dir(service), appID+".portablefsd.plist"), map[string]any{
		"Label": appID + ".portablefsd", "BundleProgram": "Contents/" + macOSPortableFSDRelativePath,
		"RunAtLoad": true, "KeepAlive": true,
	})
	for _, path := range []string{
		filepath.Join(app, "Contents", "MacOS", layout.appExecutable),
		filepath.Join(extension, "Contents", "MacOS", layout.extensionExecutable),
		filepath.Join(app, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath)),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 99\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if layout.codeIdentity == macOSInstallDeveloperIDRelease {
		workspace := filepath.Join(app, "Contents/Library/LaunchAgents/PortableFSWorkspaceService.app/Contents")
		if err := os.MkdirAll(filepath.Join(workspace, "MacOS"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workspace, "MacOS/portablefs-workspace-service"), []byte("#!/bin/sh\nexit 99\n"), 0755); err != nil {
			t.Fatal(err)
		}
		writeBundleFixturePlist(t, filepath.Join(workspace, "Info.plist"), map[string]any{"CFBundleIdentifier": appID + ".WorkspaceService", "CFBundleExecutable": "portablefs-workspace-service"})
		writeBundleFixturePlist(t, filepath.Join(filepath.Dir(filepath.Dir(workspace)), appID+".workspace.plist"), map[string]any{"Label": appID + ".workspace", "BundleProgram": "Contents/Library/LaunchAgents/PortableFSWorkspaceService.app/Contents/MacOS/portablefs-workspace-service", "RunAtLoad": true, "KeepAlive": true})
	}
	return app
}

func TestCompiledBundleEntryPointsEnforceOneLayout(t *testing.T) {
	layout := compiledMacOSInstallLayout
	appID := selectedTestAppID()
	other := macOSInstallLayout{
		appName: "PortableFSKitDev.app", stagedAppName: "PortableFSKitDev.next",
		appExecutable: "PortableFSKitDev", extensionExecutable: "PortableFSDev",
		serviceMinimumOS: "26.0", requiredAppID: "dev.portablefs.oss.KitDev", codeIdentity: macOSInstallDevelopmentHost,
	}
	if layout.codeIdentity == macOSInstallDevelopmentHost {
		other = macOSInstallLayout{appName: "PortableFS.app", stagedAppName: "PortableFS.next", appExecutable: "PortableFS", extensionExecutable: "PortableFSExt", serviceMinimumOS: "26.0", codeIdentity: macOSInstallDeveloperIDRelease}
	}
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
		want   string
	}{
		{"complete unsigned bundle", func(*testing.T, string) {}, "verify staged app code hierarchy"},
		{"wrong host", func(t *testing.T, app string) {
			writeTestBundleInfo(t, filepath.Join(app, "Contents", "Info.plist"), appID, "WrongHost")
		}, "source bundle identity mismatch"},
		{"wrong extension suffix", func(t *testing.T, app string) {
			writeTestBundleInfo(t, filepath.Join(app, "Contents", "Extensions", layout.extensionExecutable+".appex", "Contents", "Info.plist"), appID+".WrongExtension", layout.extensionExecutable)
		}, "source bundle identity mismatch"},
		{"renamed extension unchanged identifier", func(t *testing.T, app string) {
			ext := filepath.Join(app, "Contents", "Extensions", layout.extensionExecutable+".appex")
			if err := os.Rename(ext, filepath.Join(filepath.Dir(ext), "Renamed.appex")); err != nil {
				t.Fatal(err)
			}
		}, "read CFBundleIdentifier"},
		{"missing extension", func(t *testing.T, app string) {
			if err := os.RemoveAll(filepath.Join(app, "Contents", "Extensions")); err != nil {
				t.Fatal(err)
			}
		}, "read CFBundleIdentifier"},
		{"extra extension", func(t *testing.T, app string) {
			if err := os.Mkdir(filepath.Join(app, "Contents", "Extensions", "Extra.appex"), 0755); err != nil {
				t.Fatal(err)
			}
		}, "must contain exactly " + layout.extensionExecutable},
		{"extra service", func(t *testing.T, app string) {
			if err := os.Mkdir(filepath.Join(app, "Contents", "Library", "LaunchAgents", "Extra.app"), 0755); err != nil {
				t.Fatal(err)
			}
		}, "must contain its exact service applications"},
		{"extra agent", func(t *testing.T, app string) {
			if err := os.WriteFile(filepath.Join(app, "Contents", "Library", "LaunchAgents", "Extra.plist"), []byte("{}"), 0644); err != nil {
				t.Fatal(err)
			}
		}, "exactly its sealed PortableFS LaunchAgent"},
		{"symlink substitution", func(t *testing.T, app string) {
			path := filepath.Join(app, "Contents", "Helpers", "portablefs")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/usr/bin/true", path); err != nil {
				t.Fatal(err)
			}
		}, "unexpected symlink"},
		{"service provisioning profile", func(t *testing.T, app string) {
			if err := os.WriteFile(filepath.Join(app, "Contents", "Library", "LaunchAgents", "PortableFSDService.app", "Contents", "embedded.provisionprofile"), []byte("profile"), 0644); err != nil {
				t.Fatal(err)
			}
		}, "unexpectedly embeds a provisioning profile"},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := makeCompleteBundleFixture(t, t.TempDir(), layout, appID)
			if _, err := validateMacOSInstallSource(app); err == nil || !strings.Contains(err.Error(), "installer must run the CLI nested") {
				t.Fatalf("source execution guard = %v", err)
			}
			if got, err := sourceMacOSBundleIdentity(app); err != nil || got != appID {
				t.Fatalf("complete selected source = %q, %v", got, err)
			}
			test.mutate(t, app)
			// Both publication and live-owner authentication must enforce the selected contract.
			for name, validate := range map[string]func() error{
				"publication": func() error { return validateStagedBundleForPublication(app, "1.2.3", appID) },
				"owner": func() error {
					_, err := authenticateDaemonRelease(filepath.Join(app, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath)), "1.2.3")
					return err
				},
			} {
				if err := validate(); err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("%s refusal = %v, want %q", name, err, test.want)
				}
			}
		})
	}
	t.Run("other artifact", func(t *testing.T) {
		id := other.requiredAppID
		if id == "" {
			id = "org.example.portablefs"
		}
		app := makeCompleteBundleFixture(t, t.TempDir(), other, id)
		if _, err := validateMacOSInstallSource(app); err == nil {
			t.Fatal("other product accepted as install source")
		}
		if _, err := sourceMacOSBundleIdentity(app); err == nil {
			t.Fatal("other product accepted as owner")
		}
	})
	if layout.requiredAppID != "" {
		t.Run("wrong development app ID", func(t *testing.T) {
			app := makeCompleteBundleFixture(t, t.TempDir(), layout, "dev.portablefs.oss.Counterfeit")
			if _, err := sourceMacOSBundleIdentity(app); err == nil {
				t.Fatal("wrong development app ID accepted")
			}
		})
	}
}

func TestMacOSComponentSigningMatrix(t *testing.T) {
	const team = "B47U2LLKHW"
	for _, policy := range []macOSInstallCodeIdentityPolicy{macOSInstallDeveloperIDRelease, macOSInstallDevelopmentHost} {
		for _, component := range []string{"host", "extension", "CLI", "daemon service", "daemon"} {
			for _, authority := range []string{"Developer ID Application", "Apple Development", "adhoc", ""} {
				want := authority == "Developer ID Application"
				if policy == macOSInstallDevelopmentHost && (component == "host" || component == "extension" || component == "CLI") {
					want = authority == "Apple Development"
				}
				output := "Identifier=test.bundle\nTeamIdentifier=" + team + "\nCodeDirectory v=20500 flags=0x10000(runtime)\nAuthority=" + authority + ": Fixture\n"
				if err := validateMacOSCodeSignature(output, policy, component, team, "test.bundle"); (err == nil) != want {
					t.Fatalf("policy=%d component=%s authority=%s: %v", policy, component, authority, err)
				}
			}
		}
	}
	valid := "Identifier=test.bundle\nTeamIdentifier=" + team + "\nCodeDirectory v=20500 flags=0x10000(runtime)\nAuthority=Developer ID Application: Fixture\n"
	for _, output := range []string{
		strings.ReplaceAll(valid, team, "WRONGTEAM"),
		strings.ReplaceAll(valid, "0x10000(runtime)", "0x0(none)"),
		strings.ReplaceAll(valid, "Identifier=test.bundle", "Identifier=wrong.bundle"),
		valid + "TeamIdentifier=" + team + "\n", valid + "Identifier=test.bundle\n",
		valid + "Authority=Developer ID Application: Duplicate\n", "Signature=adhoc\n",
	} {
		if err := validateMacOSCodeSignature(output, macOSInstallDeveloperIDRelease, "host", team, "test.bundle"); err == nil {
			t.Fatalf("invalid signature accepted: %s", output)
		}
	}
}

func TestMacOSComponentEntitlementMatrix(t *testing.T) {
	const group = "B47U2LLKHW.pfsoss"
	for _, component := range []string{"host", "extension", "CLI", "daemon service", "daemon"} {
		for _, test := range []struct {
			name         string
			entitlements map[string]any
			want         bool
		}{
			{"empty", map[string]any{}, component == "CLI"},
			{"group", map[string]any{"com.apple.security.application-groups": []any{group}}, component != "CLI"},
			{"wrong group", map[string]any{"com.apple.security.application-groups": []any{"wrong"}}, false},
			{"extra group", map[string]any{"com.apple.security.application-groups": []any{group, "extra"}}, false},
			{"wrong type", map[string]any{"com.apple.security.application-groups": group}, false},
			{"task allow", map[string]any{"com.apple.security.application-groups": []any{group}, "com.apple.security.get-task-allow": true}, component == "host" || component == "extension"},
		} {
			if err := validateMacOSComponentEntitlements(test.entitlements, component, group); (err == nil) != test.want {
				t.Fatalf("%s/%s: %v", component, test.name, err)
			}
		}
	}
}

func TestMacOSCodeArchitecturePolicies(t *testing.T) {
	for _, test := range []struct {
		output                  string
		production, development bool
	}{
		{"arm64 x86_64", true, true}, {"arm64", false, true}, {"x86_64", false, true},
		{"", false, false}, {"arm64 arm64", false, false}, {"arm64 unknown", false, false},
	} {
		for _, policy := range []macOSInstallCodeIdentityPolicy{macOSInstallDeveloperIDRelease, macOSInstallDevelopmentHost} {
			want := test.production
			if policy == macOSInstallDevelopmentHost {
				want = test.development
			}
			if _, err := macOSCodeArchitectures(test.output, policy); (err == nil) != want {
				t.Fatalf("policy=%d architectures=%q: %v", policy, test.output, err)
			}
		}
	}
}

func TestServicePurposeDescriptionsAreAnExactSealedContract(t *testing.T) {
	for _, test := range []struct{ name, key, value string }{
		{"missing local network purpose", "NSLocalNetworkUsageDescription", ""},
		{"wrong local network purpose", "NSLocalNetworkUsageDescription", `"different"`},
		{"missing volume purpose", "NSNetworkVolumesUsageDescription", ""},
		{"wrong volume purpose type", "NSNetworkVolumesUsageDescription", `true`},
		{"extra service policy", "Unexpected", `true`},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := makeCompleteBundleFixture(t, t.TempDir(), compiledMacOSInstallLayout, selectedTestAppID())
			path := filepath.Join(app, "Contents", "Library", "LaunchAgents", "PortableFSDService.app", "Contents", "Info.plist")
			if err := validatePortableFSDServiceInfo(path, selectedTestAppID()+".PortableFSDService", "1.2.3", "26.0"); err != nil {
				t.Fatal(err)
			}
			object, err := plistJSONObject(path)
			if err != nil {
				t.Fatal(err)
			}
			if test.value == "" {
				delete(object, test.key)
			} else {
				object[test.key] = json.RawMessage(test.value)
			}
			data, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0644); err != nil {
				t.Fatal(err)
			}
			if err := validatePortableFSDServiceInfo(path, selectedTestAppID()+".PortableFSDService", "1.2.3", "26.0"); err == nil {
				t.Fatal("changed service policy accepted")
			}
		})
	}
}
