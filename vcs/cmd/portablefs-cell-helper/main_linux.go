//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellhelper"
	"github.com/steerlabs/portablefs/vcs/internal/cellhost"
	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "portablefs-cell-helper:", err)
		os.Exit(1)
	}
}

func run() error {
	cellID := flag.String("cell-id", "", "stable cell UUID")
	socket := flag.String("socket", "/run/portablefs-cell-helper/default.sock", "Unix socket used only by the cell agent")
	agentUID := flag.Uint("agent-uid", 0, "exact unprivileged cell-agent UID")
	agentGID := flag.Int("agent-gid", 0, "cell-agent group owning the helper socket")
	stateFile := flag.String("state-file", "/var/lib/portablefs-cell-helper/state.json", "durable helper assignment state")
	planPublicKey := flag.String("plan-public-key", "", "manager cell-plan Ed25519 public key PEM")
	cellRoot := flag.String("cell-root", "/srv/portablefs", "XFS project-quota root")
	configRoot := flag.String("config-root", "/etc/portablefs/volumes", "root-owned authority configuration root")
	stateRoot := flag.String("authority-state-root", "/var/lib/portablefs/volumes", "authority runtime state root")
	systemdRoot := flag.String("systemd-unit-root", "/etc/systemd/system", "systemd unit/drop-in root")
	sysusersRoot := flag.String("sysusers-root", "/var/lib/portablefs-cell-helper/sysusers.d", "durable root-owned systemd-sysusers configuration root")
	xfsQuota := flag.String("xfs-quota", "/usr/sbin/xfs_quota", "pinned xfs_quota executable")
	systemctl := flag.String("systemctl", "/usr/bin/systemctl", "pinned systemctl executable")
	systemdRun := flag.String("systemd-run", "/usr/bin/systemd-run", "pinned systemd-run executable")
	sysusers := flag.String("systemd-sysusers", "/usr/bin/systemd-sysusers", "pinned systemd-sysusers executable")
	planLifetime := flag.Duration("plan-max-lifetime", 15*time.Minute, "maximum accepted cell-plan lifetime")
	clockSkew := flag.Duration("clock-skew", 5*time.Second, "maximum authenticated clock disagreement")
	flag.Parse()
	if flag.NArg() != 0 || !cellplan.ValidID(*cellID) || *agentUID == 0 || *agentGID <= 0 || *planPublicKey == "" ||
		!planLifetimeValid(planLifetime, clockSkew) {
		return errors.New("cell ID, non-root agent UID/GID, plan public key, and valid lifetimes are required")
	}
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	for _, path := range []string{*socket, *stateFile, *planPublicKey, *cellRoot, *configRoot, *stateRoot, *systemdRoot, *sysusersRoot, *xfsQuota, *systemctl, *systemdRun, *sysusers} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("path must be clean and absolute: %q", path)
		}
	}
	publicKey, err := readPlanPublicKey(*planPublicKey)
	if err != nil {
		return err
	}
	host, err := cellhost.New(cellhost.Config{
		CellID: *cellID, CellRoot: *cellRoot, ConfigRoot: *configRoot, StateRoot: *stateRoot,
		SystemdUnitRoot: *systemdRoot, SysusersRoot: *sysusersRoot, XFSQuotaBinary: *xfsQuota,
		SystemctlBinary: *systemctl, SystemdRunBinary: *systemdRun, SysusersBinary: *sysusers,
	})
	if err != nil {
		return err
	}
	reconciler := &cellhelper.Reconciler{
		CellID: *cellID, PlanPublicKey: publicKey, ClockSkew: *clockSkew, PlanLifetime: *planLifetime,
		ReleaseID: version, StatePath: *stateFile, Host: host,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return (&cellhelper.Server{SocketPath: *socket, SocketGID: *agentGID, AgentUID: uint32(*agentUID), Reconciler: reconciler}).Serve(ctx)
}

func planLifetimeValid(lifetime, skew *time.Duration) bool {
	return lifetime != nil && skew != nil && *lifetime > 0 && *skew >= 0
}

func readPlanPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("plan public key must contain one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("plan public key is not Ed25519")
	}
	return key, nil
}
