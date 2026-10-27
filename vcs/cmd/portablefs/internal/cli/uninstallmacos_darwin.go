//go:build darwin

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/accountsession"
	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"golang.org/x/sys/unix"
)

func runUninstallMacOSApp(e *cmdEnv, requestedLinkDir string) (macOSInstallResult, error) {
	layout := compiledMacOSInstallLayout
	if err := layout.validate(); err != nil {
		return macOSInstallResult{}, err
	}
	home, err := accountpath.Home()
	if err != nil {
		return macOSInstallResult{}, err
	}
	app := filepath.Join(home, "Applications", layout.appName)
	executable, err := os.Executable()
	if err != nil {
		return macOSInstallResult{}, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return macOSInstallResult{}, err
	}
	if executable != filepath.Join(app, "Contents", "Helpers", macOSCLIName) {
		return macOSInstallResult{}, fmt.Errorf("run the installed PortableFS helper to remove its app")
	}
	identifier, err := sourceMacOSBundleIdentityWithLayout(app, layout)
	if err != nil {
		return macOSInstallResult{}, err
	}
	if err := validateInstalledMacOSBundleForPublicationWithLayout(app, e.version, identifier, layout); err != nil {
		return macOSInstallResult{}, fmt.Errorf("authenticate installed app before removal: %w", err)
	}
	linkDir := requestedLinkDir
	if linkDir == "" {
		linkDir = filepath.Join(home, ".local", "bin")
	}
	if err := validateContainedPath(home, linkDir); err != nil {
		return macOSInstallResult{}, err
	}
	if pathsOverlap(filepath.Dir(app), linkDir) {
		return macOSInstallResult{}, fmt.Errorf("CLI link directory overlaps application directory")
	}
	link := filepath.Join(linkDir, macOSCLIName)
	removal, err := prepareMacOSAppRemoval(app, link)
	if err != nil {
		return macOSInstallResult{}, err
	}
	release, err := macOSServiceReleaseIdentity(app, e.version)
	if err != nil {
		return macOSInstallResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	session, err := prepareInstalledHostUpdate(ctx, app, hostctl.SocketPath(home), release, release)
	cancel()
	if err != nil {
		return macOSInstallResult{}, err
	}
	committed := false
	defer func() {
		if committed {
			_ = session.Close()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = session.Cancel(ctx)
	}()
	stateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return macOSInstallResult{}, err
	}
	account, err := accountsession.AcquireExclusive(stateDir)
	if err != nil {
		return macOSInstallResult{}, err
	}
	defer account.Close()
	guard, err := mountlifecycle.AcquireExclusive(stateDir)
	if err != nil {
		return macOSInstallResult{}, err
	}
	defer guard.Close()
	releaseWorkspace, err := excludeAbsentWorkspace(stateDir, layout)
	if err != nil {
		return macOSInstallResult{}, err
	}
	defer releaseWorkspace()
	if err := rejectPreparedMacOSRuntime(e, stateDir, session.HostProcessWitness(), filepath.Join(app, "Contents", "MacOS", layout.appExecutable), hostctl.SocketPath(home)); err != nil {
		return macOSInstallResult{}, err
	}
	if err := removal.requireUnchanged(); err != nil {
		return macOSInstallResult{}, err
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	committed = true // A lost acknowledgement never authorizes Cancel.
	err = session.Commit(ctx)
	cancel()
	if err != nil {
		return macOSInstallResult{}, fmt.Errorf("removal handoff is unconfirmed; app and data retained: %w", err)
	}
	if err := waitForPreparedHostAbsence(session.HostPID(), hostctl.SocketPath(home), 10*time.Second); err != nil {
		return macOSInstallResult{}, err
	}
	if err := hostctl.RequireLease(hostctl.LeasePath(home), session.Token(), hostctl.PhaseOldAbsent, release, release); err != nil {
		return macOSInstallResult{}, err
	}
	if err := rejectLiveMacOSRuntimeWithLayout(e, stateDir, layout); err != nil {
		return macOSInstallResult{}, err
	}
	if err := validateInstalledMacOSBundleForPublicationWithLayout(app, e.version, identifier, layout); err != nil {
		return macOSInstallResult{}, err
	}
	if err := removal.commit(); err != nil {
		return macOSInstallResult{}, fmt.Errorf("owned app removal incomplete; workspace data retained: %w", err)
	}
	if err := rejectLiveMacOSRuntimeWithLayout(e, stateDir, layout); err != nil {
		return macOSInstallResult{}, err
	}
	if err := removal.requireAbsent(); err != nil {
		return macOSInstallResult{}, err
	}
	// Only the exact live token can retire this lease, after all owned program
	// names are durably absent and while both services remain excluded.
	if err := hostctl.RetireRemovalLease(hostctl.LeasePath(home), session.Token(), release); err != nil {
		return macOSInstallResult{}, err
	}
	return macOSInstallResult{SchemaVersion: 1, AppPath: app, CLILink: link, Version: e.version}, nil
}

type macOSAppRemoval struct {
	app, link                                string
	appID, linkID, appParentID, linkParentID pathSnapshot
}

func prepareMacOSAppRemoval(app, link string) (*macOSAppRemoval, error) {
	if err := validateExistingAppDestination(app); err != nil {
		return nil, err
	}
	if err := validateExistingCLILink(link, app); err != nil {
		return nil, err
	}
	p := &macOSAppRemoval{app: app, link: link}
	for _, item := range []struct {
		path   string
		target *pathSnapshot
	}{
		{app, &p.appID}, {link, &p.linkID}, {filepath.Dir(app), &p.appParentID}, {filepath.Dir(link), &p.linkParentID},
	} {
		snapshot, err := snapshotPath(item.path)
		if err != nil {
			return nil, err
		}
		*item.target = snapshot
	}
	if !p.appID.exists {
		return nil, fmt.Errorf("installed app is absent")
	}
	return p, nil
}

func (p *macOSAppRemoval) requireUnchanged() error {
	for _, item := range []struct {
		path string
		id   pathSnapshot
	}{
		{p.app, p.appID}, {p.link, p.linkID}, {filepath.Dir(p.app), p.appParentID}, {filepath.Dir(p.link), p.linkParentID},
	} {
		if err := requireUnchangedPath(item.path, item.id); err != nil {
			return err
		}
	}
	return nil
}

func (p *macOSAppRemoval) commit() error {
	if err := p.requireUnchanged(); err != nil {
		return err
	}
	parent, err := openSnapshottedDirectory(filepath.Dir(p.app), p.appParentID)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if p.linkID.exists {
		links, err := openSnapshottedDirectory(filepath.Dir(p.link), p.linkParentID)
		if err != nil {
			return err
		}
		defer unix.Close(links)
		if err := requireUnchangedPath(p.link, p.linkID); err != nil {
			return err
		}
		if err := unix.Unlinkat(links, filepath.Base(p.link), 0); err != nil {
			return err
		}
		if err := unix.Fsync(links); err != nil {
			return err
		}
	}
	if err := removeSnapshottedTreeAt(parent, filepath.Base(p.app), p.appID, nil); err != nil {
		return err
	}
	return p.requireAbsent()
}

func (p *macOSAppRemoval) requireAbsent() error {
	for _, item := range []struct {
		path string
		id   pathSnapshot
	}{
		{filepath.Dir(p.app), p.appParentID}, {filepath.Dir(p.link), p.linkParentID},
	} {
		if err := requireUnchangedPath(item.path, item.id); err != nil {
			return err
		}
	}
	for _, path := range []string{p.app, p.link} {
		if err := requireRuntimePathAbsent(path, "removed program name"); err != nil {
			return err
		}
	}
	return nil
}

func excludeAbsentWorkspace(stateDir string, layout macOSInstallLayout) (func(), error) {
	var guards []*mountlifecycle.Guard
	release := func() {
		for i := len(guards) - 1; i >= 0; i-- {
			_ = guards[i].Close()
		}
	}
	if layout.codeIdentity != macOSInstallDeveloperIDRelease {
		return release, nil
	}
	directory := filepath.Join(stateDir, "workspace")
	for _, name := range []string{"service.lock", "owner.lock"} {
		guard, err := mountlifecycle.AcquireNamedExclusive(directory, name)
		if err != nil {
			release()
			return nil, fmt.Errorf("workspace singleton release unconfirmed: %w", err)
		}
		guards = append(guards, guard)
	}
	if err := requireWorkspaceResourcesAbsent(stateDir); err != nil {
		release()
		return nil, err
	}
	for _, name := range []string{"control.sock", "ssh.sock"} {
		if err := requireRuntimePathAbsent(filepath.Join(directory, name), "workspace endpoint"); err != nil {
			release()
			return nil, err
		}
	}
	return release, nil
}
