//go:build darwin && cgo

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/accountsession"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
)

// These flags exist only in the test executable. The maintained unsigned gate
// cannot provide Apple certificates or notarization and does not claim them.
var signedBundleFixtures = flag.Bool("portablefs-test-signed-bundles", false, "exercise isolated native bundles using the configured signing identities")
var fixtureDevelopmentSigner = flag.String("portablefs-test-development-signer", "Apple Development: Tim Seokboem Jang (F5R8J7D2YC)", "exact Apple Development fixture identity")
var fixtureServiceSigner = flag.String("portablefs-test-service-signer", "Developer ID Application: TrendUp AI, Inc. (B47U2LLKHW)", "exact Developer ID Application fixture identity")
var signedOwnerArtifact = flag.String("portablefs-test-owner-artifact", "", "read-only complete signed-owner validation of an existing app")

// A signed copy of the test executable acts as the incoming embedded helper.
// Only this test binary has private-root injection; shipped CLI inputs do not.
func init() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case "version", "lifecycle":
		os.Exit(Main(os.Args[1:], "1.2.3"))
	case "portablefs-test-source":
		if len(os.Args) != 3 {
			os.Exit(64)
		}
		_, err := validateMacOSInstallSource(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case "portablefs-test-command":
		if len(os.Args) < 6 {
			os.Exit(64)
		}
		home, socket, daemon := os.Args[2], os.Args[3], os.Args[4]
		resolveFSKitAccountHome = func() (string, error) { return home, nil }
		state := filepath.Join(home, ".local", "state", "portablefs")
		e := &cmdEnv{stdout: os.Stdout, stderr: os.Stderr, stdin: os.Stdin, version: "1.2.3", getenv: func(string) string { return "" }, stateDir: state, lifecycleStateDir: state,
			kernelInventoryFn:  func() ([]string, error) { return nil, nil },
			fsKitConfigForTest: &fskitConfig{controlSock: socket, daemonPathForTest: daemon},
		}
		os.Exit(e.run(os.Args[5:]))
	}
}

func TestSignedOwnerArtifact(t *testing.T) {
	if *signedOwnerArtifact == "" {
		t.Skip("signed artifact qualification requires -portablefs-test-owner-artifact")
	}
	app, err := filepath.EvalSymlinks(*signedOwnerArtifact)
	if err != nil {
		t.Fatal(err)
	}
	version, err := plistValue(filepath.Join(app, "Contents", "Info.plist"), "CFBundleShortVersionString")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateDaemonRelease(filepath.Join(app, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath)), version); err != nil {
		t.Fatal(err)
	}
}

func requireFixtureSigning(t *testing.T) {
	t.Helper()
	if !*signedBundleFixtures {
		t.Skip("native signing qualification requires -portablefs-test-signed-bundles")
	}
}

func fixtureSign(t *testing.T, path, identity, identifier string, entitlements map[string]any) {
	t.Helper()
	args := []string{"--force", "--sign", identity, "--options", "runtime", "--identifier", identifier, "--timestamp=none"}
	if entitlements != nil {
		file := filepath.Join(t.TempDir(), "entitlements.plist")
		writeBundleFixturePlist(t, file, entitlements)
		args = append(args, "--entitlements", file)
	}
	args = append(args, path)
	if out, err := exec.Command("/usr/bin/codesign", args...).CombinedOutput(); err != nil {
		t.Fatalf("sign isolated fixture: %v: %s", err, out)
	}
}

func makeSignedBundleFixture(t *testing.T, root string, incoming bool) string {
	t.Helper()
	layout := compiledMacOSInstallLayout
	appID := selectedTestAppID()
	app := makeCompleteBundleFixture(t, root, layout, appID)
	resources := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(resources, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(app, "marker"), filepath.Join(resources, "marker")); err != nil {
		t.Fatal(err)
	}
	identity, err := json.Marshal(fskitidentity.Current())
	if err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(t.TempDir(), "bundle-peer")
	if out, err := exec.Command("/usr/bin/clang", "-arch", "arm64", "-arch", "x86_64", "-DROUTING_IDENTITY="+strconv.Quote(string(identity)), "testdata/bundle_peer.c", "-o", peer).CombinedOutput(); err != nil {
		t.Fatalf("compile signed fixture: %v: %s", err, out)
	}
	cli := filepath.Join(app, "Contents", "Helpers", "portablefs")
	extension := filepath.Join(app, "Contents", "Extensions", layout.extensionExecutable+".appex")
	service := filepath.Join(app, "Contents", "Library", "LaunchAgents", "PortableFSDService.app")
	daemon := filepath.Join(app, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath))
	for _, path := range []string{cli, filepath.Join(app, "Contents", "MacOS", layout.appExecutable), filepath.Join(extension, "Contents", "MacOS", layout.extensionExecutable), daemon} {
		source := peer
		if incoming && path == cli {
			source, err = os.Executable()
			if err != nil {
				t.Fatal(err)
			}
		}
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	signer := *fixtureServiceSigner
	if layout.codeIdentity == macOSInstallDevelopmentHost {
		signer = *fixtureDevelopmentSigner
	}
	groups := map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}}
	fixtureSign(t, cli, signer, "portablefs", nil)
	fixtureSign(t, service, *fixtureServiceSigner, appID+".PortableFSDService", groups)
	fixtureSign(t, extension, signer, appID+"."+layout.extensionExecutable, groups)
	fixtureSign(t, app, signer, appID, groups)
	return app
}

func TestNativeSignedBundlePolicy(t *testing.T) {
	requireFixtureSigning(t)
	app := makeSignedBundleFixture(t, t.TempDir(), false)
	daemon := filepath.Join(app, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath))
	_, err := authenticateDaemonRelease(daemon, "1.2.3")
	if compiledMacOSInstallLayout.codeIdentity == macOSInstallDeveloperIDRelease {
		if err == nil || (!strings.Contains(err.Error(), "Gatekeeper") && !strings.Contains(err.Error(), "notarization")) {
			t.Fatalf("unnotarized shipping fixture = %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"Apple Development daemon", func(t *testing.T, app string) {
			fixtureSign(t, filepath.Join(app, "Contents", "Library", "LaunchAgents", "PortableFSDService.app"), *fixtureDevelopmentSigner, selectedTestAppID()+".PortableFSDService", map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}})
			fixtureSign(t, app, *fixtureDevelopmentSigner, selectedTestAppID(), map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}})
		}},
		{"Developer ID CLI", func(t *testing.T, app string) {
			fixtureSign(t, filepath.Join(app, "Contents", "Helpers", "portablefs"), *fixtureServiceSigner, "portablefs", nil)
			fixtureSign(t, app, *fixtureDevelopmentSigner, selectedTestAppID(), map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}})
		}},
		{"entitled CLI", func(t *testing.T, app string) {
			fixtureSign(t, filepath.Join(app, "Contents", "Helpers", "portablefs"), *fixtureDevelopmentSigner, "portablefs", map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}})
			fixtureSign(t, app, *fixtureDevelopmentSigner, selectedTestAppID(), map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}})
		}},
		{"daemon task allowance", func(t *testing.T, app string) {
			fixtureSign(t, filepath.Join(app, "Contents", "Library", "LaunchAgents", "PortableFSDService.app"), *fixtureServiceSigner, selectedTestAppID()+".PortableFSDService", map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}, "com.apple.security.get-task-allow": true})
			fixtureSign(t, app, *fixtureDevelopmentSigner, selectedTestAppID(), map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}})
		}},
		{"host missing runtime", func(t *testing.T, app string) {
			file := filepath.Join(t.TempDir(), "entitlements.plist")
			writeBundleFixturePlist(t, file, map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}})
			if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", *fixtureDevelopmentSigner, "--options", "0", "--timestamp=none", "--entitlements", file, "--identifier", selectedTestAppID(), app).CombinedOutput(); err != nil {
				t.Fatalf("sign runtime-negative fixture: %v: %s", err, out)
			}
		}},
		{"changed sealed resource", func(t *testing.T, app string) {
			if err := os.WriteFile(filepath.Join(app, "Contents", "Resources", "marker"), []byte("changed"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"ad-hoc host", func(t *testing.T, app string) {
			fixtureSign(t, app, "-", selectedTestAppID(), map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}})
		}},
		{"signature plist mismatch", func(t *testing.T, app string) {
			fixtureSign(t, app, *fixtureDevelopmentSigner, "wrong.identifier", map[string]any{"com.apple.security.application-groups": []any{fskitidentity.AppGroup}})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := makeSignedBundleFixture(t, t.TempDir(), false)
			test.mutate(t, copy)
			if _, err := authenticateDaemonRelease(filepath.Join(copy, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath)), "1.2.3"); err == nil {
				t.Fatal("invalid signed bundle authenticated")
			}
		})
	}
}

func startSignedBundlePeer(t *testing.T, daemon, socket string) (*exec.Cmd, string, string) {
	t.Helper()
	identityFile, inventoryFile := filepath.Join(filepath.Dir(socket), "identity.response"), filepath.Join(filepath.Dir(socket), "inventory.response")
	sha, err := daemonctl.FileSHA256(daemon)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := daemonctl.EncodeIdentity(daemonctl.Identity{SchemaVersion: 1, ControlProtocol: 2, PFSLocalMajor: 2, DaemonVersion: "1.2.3", ExecutableSHA256: sha})
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{identityFile: append([]byte("200\n"), identity...), inventoryFile: []byte("200\n{\"attachment_count\":0}")} {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(daemon, socket, identityFile, inventoryFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "ready" {
		t.Fatalf("signed peer startup: %v", scanner.Err())
	}
	go func() {
		for scanner.Scan() {
		}
	}()
	return cmd, identityFile, inventoryFile
}

func TestNativeSignedDevelopmentExpectedOwnerGuard(t *testing.T) {
	requireFixtureSigning(t)
	if compiledMacOSInstallLayout.codeIdentity != macOSInstallDevelopmentHost {
		t.Skip("shipping signed-owner tests run separately")
	}
	root := shortSocketDir(t)
	incoming := makeSignedBundleFixture(t, filepath.Join(root, "incoming"), true)
	outgoing := makeSignedBundleFixture(t, filepath.Join(root, "staged-outgoing"), false)
	cli := filepath.Join(incoming, "Contents", "Helpers", "portablefs")
	if out, err := exec.Command(cli, "portablefs-test-source", incoming).CombinedOutput(); err != nil {
		t.Fatalf("real nested source entry: %v: %s", err, out)
	}
	daemon := filepath.Join(outgoing, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath))
	expected, err := authenticateDaemonRelease(daemon, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "control.sock")
	peer, identityFile, inventoryFile := startSignedBundlePeer(t, daemon, socket)
	command := func(home string, release *daemonRelease) *exec.Cmd {
		args := []string{"portablefs-test-command", home, socket, daemon, "lifecycle", "hold-install-exclusive", "--json"}
		if release != nil {
			args = append(args, "--expected-daemon-version", release.identity.DaemonVersion, "--expected-daemon-sha256", release.identity.ExecutableSHA256, "--expected-daemon-path", release.path, "--expected-daemon-cdhash", release.identity.CodeDirectoryHash)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		t.Cleanup(cancel)
		return exec.CommandContext(ctx, cli, args...)
	}
	t.Run("zero readiness held exclusions and EOF", func(t *testing.T) {
		home := filepath.Join(root, "home")
		cmd := command(home, &expected)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = stdin.Close()
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			t.Fatalf("readiness: %v: %s", err, stderr.String())
		}
		var ready installExclusiveReadiness
		if err := json.Unmarshal([]byte(line), &ready); err != nil || ready != (installExclusiveReadiness{SchemaVersion: 1, Held: true, Purpose: "service-update"}) {
			t.Fatalf("readiness=%s error=%v", line, err)
		}
		state := filepath.Join(home, ".local", "state", "portablefs")
		if guard, err := accountsession.AcquireShared(state); err == nil {
			_ = guard.Close()
			t.Fatal("account exclusion absent")
		}
		if guard, err := mountlifecycle.AcquireShared(state); err == nil {
			_ = guard.Close()
			t.Fatal("mount exclusion absent")
		}
		if err := stdin.Close(); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("EOF release: %v: %s", err, stderr.String())
		}
		for _, acquire := range []func(string) (io.Closer, error){func(s string) (io.Closer, error) { return accountsession.AcquireShared(s) }, func(s string) (io.Closer, error) { return mountlifecycle.AcquireShared(s) }} {
			guard, err := acquire(state)
			if err != nil {
				t.Fatal(err)
			}
			_ = guard.Close()
		}
	})
	for _, test := range []struct {
		name   string
		mutate func(*daemonRelease)
	}{
		{"path", func(r *daemonRelease) { r.path = strings.Replace(r.path, "staged-outgoing", "absent", 1) }},
		{"hash", func(r *daemonRelease) { r.identity.ExecutableSHA256 = strings.Repeat("a", 64) }},
		{"CDHash", func(r *daemonRelease) { r.identity.CodeDirectoryHash = strings.Repeat("b", 40) }},
		{"version", func(r *daemonRelease) { r.identity.DaemonVersion = "4.5.6" }},
	} {
		t.Run(test.name+" mismatch cannot select absence", func(t *testing.T) {
			release := expected
			test.mutate(&release)
			cmd := command(filepath.Join(root, "refusal-home"), &release)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil || stdout.Len() != 0 || strings.Contains(stderr.String(), "absent-daemon registry") {
				t.Fatalf("mismatch error=%v readiness=%s stderr=%s", err, &stdout, &stderr)
			}
		})
	}
	originalIdentity, err := os.ReadFile(identityFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, file, response string }{
		{"nonzero attachment inventory", inventoryFile, "200\n{\"attachment_count\":1}"},
		{"terminal attachment inventory", inventoryFile, "200\n{\"attachment_count\":3}"},
		{"malformed inventory", inventoryFile, "200\n{}"},
		{"refused inventory", inventoryFile, "409\nrefused"},
		{"malformed identity", identityFile, "200\n{}"},
		{"refused identity", identityFile, "404\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(test.file, []byte(test.response), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := command(filepath.Join(root, "refusal-home"), &expected)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil || stdout.Len() != 0 || strings.Contains(stderr.String(), "absent-daemon registry") {
				t.Fatalf("refusal error=%v readiness=%s stderr=%s", err, &stdout, &stderr)
			}
			if err := os.WriteFile(identityFile, originalIdentity, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(inventoryFile, []byte("200\n{\"attachment_count\":0}"), 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("ordinary connection and final no-expected inventory", func(t *testing.T) {
		cfg := fskitConfig{controlSock: socket, daemonPathForTest: daemon}
		ctl, err := connectCompatiblePortablefsd(cfg, "1.2.3")
		if err != nil {
			t.Fatal(err)
		}
		ctl.close()
		if out, err := command(filepath.Join(root, "final-home"), nil).CombinedOutput(); err != nil || !strings.Contains(string(out), `"liveAttaches":0`) {
			t.Fatalf("final inventory=%s error=%v", out, err)
		}
	})
	t.Run("outgoing protocols vary while ordinary pairing is exact", func(t *testing.T) {
		var identity daemonctl.Identity
		if err := json.Unmarshal(bytes.TrimPrefix(originalIdentity, []byte("200\n")), &identity); err != nil {
			t.Fatal(err)
		}
		identity.ControlProtocol = 71
		identity.PFSLocalMajor = 98
		identity.PFSLocalMinor = 37
		data, err := daemonctl.EncodeIdentity(identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(identityFile, append([]byte("200\n"), data...), 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := command(filepath.Join(root, "outgoing-home"), &expected).CombinedOutput(); err != nil {
			t.Fatalf("outgoing actual protocols: %v: %s", err, out)
		}
		cfg := fskitConfig{controlSock: socket, daemonPathForTest: daemon}
		if ctl, err := connectCompatiblePortablefsd(cfg, "1.2.3"); err == nil {
			ctl.close()
			t.Fatal("unequal ordinary pair admitted")
		}
		if err := os.WriteFile(identityFile, originalIdentity, 0600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("substituted socket execution and missing socket cannot select absence", func(t *testing.T) {
		if err := peer.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = peer.Wait()
		if err := os.Remove(socket); err != nil {
			t.Fatal(err)
		}
		for _, substituted := range []bool{false, true} {
			var substitute *exec.Cmd
			if substituted {
				substitute, _, _ = startSignedBundlePeer(t, filepath.Join(incoming, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath)), socket)
			}
			cmd := command(filepath.Join(root, "substitution-home"), &expected)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), "strict daemon attach inventory") {
				t.Fatalf("substitution=%t error=%v readiness=%s stderr=%s", substituted, err, &stdout, &stderr)
			}
			if substitute != nil {
				_ = substitute.Process.Kill()
				_ = substitute.Wait()
				if err := os.Remove(socket); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
	t.Run("staged to canonical publication and final inventory with incoming helper", func(t *testing.T) {
		appDir, linkDir := filepath.Join(root, "Applications"), filepath.Join(root, "bin")
		if err := os.MkdirAll(appDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(linkDir, 0755); err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(appDir, macOSAppName)
		prepared, err := prepareMacOSInstall(outgoing, destination, filepath.Join(linkDir, macOSCLIName))
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.cleanup()
		if err := commitMacOSInstall(prepared, destination); err != nil {
			t.Fatal(err)
		}
		daemon = filepath.Join(destination, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath))
		if _, err := authenticateDaemonRelease(daemon, "1.2.3"); err != nil {
			t.Fatal(err)
		}
		_, _, _ = startSignedBundlePeer(t, daemon, socket)
		if out, err := command(filepath.Join(root, "canonical-home"), nil).CombinedOutput(); err != nil || !strings.Contains(string(out), `"liveAttaches":0`) {
			t.Fatalf("canonical final inventory=%s error=%v", out, err)
		}
	})

}

func TestCompiledInstallSourceRequiresItsOwnEmbeddedCLI(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(app, "Contents", "Helpers", macOSCLIName)
	if err := os.WriteFile(cli, data, 0755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cli, "portablefs-test-source", app).CombinedOutput(); err != nil {
		t.Fatalf("selected nested source refused: %v: %s", err, out)
	}
	other := makeFakeMacOSApp(t, t.TempDir(), "other-copy")
	if out, err := exec.Command(cli, "portablefs-test-source", other).CombinedOutput(); err == nil || !bytes.Contains(out, []byte("installer must run the CLI nested")) {
		t.Fatalf("another source accepted: %v: %s", err, out)
	}
}
