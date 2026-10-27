//go:build darwin

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceimage"
)

func verifyWorkspaceBundleImage(app string) error {
	info := filepath.Join(app, "Contents/Library/LaunchAgents/PortableFSWorkspaceService.app/Contents/Info.plist")
	pin, err := plistValue(info, "PFSWorkspaceImageManifestSHA256")
	if err != nil {
		return err
	}
	commit, err := plistValue(info, "PFSWorkspaceBuildCommit")
	if err != nil {
		return err
	}
	version, err := plistValue(filepath.Join(app, "Contents/Info.plist"), "CFBundleShortVersionString")
	if err != nil {
		return err
	}
	_, err = workspaceimage.Verify(filepath.Join(app, "Contents/Resources/LinuxWorkspace"), pin, commit, version)
	return err
}
func (e *cmdEnv) verifyWorkspaceBundle(app string) int {
	id, err := plistValue(filepath.Join(app, "Contents/Info.plist"), "CFBundleIdentifier")
	if err == nil {
		err = validateWorkspaceBundleLayout(app, e.version, id)
	}
	if err != nil {
		return e.fail("lifecycle", err)
	}
	if err := verifyWorkspaceBundleImage(app); err != nil {
		fmt.Fprintln(e.stderr, err)
		return 1
	}
	return 0
}

func validateWorkspaceBundleLayout(app, version, appID string) error {
	service := filepath.Join(app, "Contents/Library/LaunchAgents/PortableFSWorkspaceService.app")
	info := filepath.Join(service, "Contents/Info.plist")
	for key, want := range map[string]string{"CFBundleIdentifier": appID + ".WorkspaceService", "CFBundleExecutable": "portablefs-workspace-service", "CFBundleName": "PortableFSWorkspaceService", "CFBundlePackageType": "APPL", "CFBundleShortVersionString": version, "LSMinimumSystemVersion": "26.0", "LSBackgroundOnly": "true"} {
		got, err := plistValue(info, key)
		if err != nil || got != want {
			return fmt.Errorf("workspace service %s mismatch: %q: %v", key, got, err)
		}
	}
	build, err := plistValue(filepath.Join(app, "Contents/Info.plist"), "CFBundleVersion")
	if err != nil {
		return err
	}
	serviceBuild, err := plistValue(info, "CFBundleVersion")
	if err != nil || serviceBuild != build {
		return fmt.Errorf("workspace service build mismatch: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(service, "Contents/embedded.provisionprofile")); !os.IsNotExist(err) {
		return fmt.Errorf("workspace service must not embed a profile: %v", err)
	}
	agent := filepath.Join(app, "Contents/Library/LaunchAgents", appID+".workspace.plist")
	for key, want := range map[string]string{"Label": appID + ".workspace", "BundleProgram": "Contents/Library/LaunchAgents/PortableFSWorkspaceService.app/Contents/MacOS/portablefs-workspace-service", "RunAtLoad": "true", "KeepAlive": "true"} {
		got, err := plistValue(agent, key)
		if err != nil || got != want {
			return fmt.Errorf("workspace agent %s mismatch: %q: %v", key, got, err)
		}
	}
	if out, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", agent).Output(); err != nil {
		return err
	} else {
		var fields map[string]any
		if json.Unmarshal(out, &fields) != nil || len(fields) != 4 {
			return fmt.Errorf("workspace agent has extra launch policy")
		}
	}
	return nil
}

func validateWorkspaceBundleForPublication(app, version, appID string, layout macOSInstallLayout) error {
	if err := validateWorkspaceBundleLayout(app, version, appID); err != nil {
		return err
	}
	service := filepath.Join(app, "Contents/Library/LaunchAgents/PortableFSWorkspaceService.app")
	executable := filepath.Join(service, "Contents/MacOS/portablefs-workspace-service")
	out, err := exec.Command("/usr/bin/lipo", "-archs", executable).CombinedOutput()
	if err != nil {
		return fmt.Errorf("workspace service architectures: %w", err)
	}
	architectures, err := macOSCodeArchitectures(string(out), layout.codeIdentity)
	if err != nil {
		return err
	}
	team, _, _ := strings.Cut(fskitidentity.AppGroup, ".")
	for _, arch := range architectures {
		out, err := exec.Command("/usr/bin/codesign", "-dv", "--verbose=4", "--arch", arch, service).CombinedOutput()
		if err != nil {
			return err
		}
		if err = validateMacOSCodeSignature(string(out), layout.codeIdentity, "workspace service", team, appID+".WorkspaceService"); err != nil {
			return err
		}
		entitlements, err := exactCodeEntitlementsForArchitecture(service, filepath.Dir(app), arch)
		if err != nil {
			return err
		}
		if len(entitlements) != 1 || entitlements["com.apple.security.virtualization"] != true {
			return fmt.Errorf("workspace service must hold exactly virtualization")
		}
	}
	return verifyWorkspaceBundleImage(app)
}

func (e *cmdEnv) verifyMacOSReleaseBundle(app string) int {
	id, err := sourceMacOSBundleIdentityWithLayout(app, compiledMacOSInstallLayout)
	if err == nil {
		err = validateMacOSBundleForPublicationWithLayout(app, e.version, id, compiledMacOSInstallLayout)
	}
	if err != nil {
		return e.fail("lifecycle", err)
	}
	return 0
}
