// Command pfs-powerloss-fskit-driver exercises the real authority FSKit
// handler for the power-loss harness, exactly as a Mac's portablefsd does and
// with nothing else in the path.
//
// It dials the authority with the platform-neutral client, attaches and
// activates one MOUNT session with FRONTEND_PROFILE_FSKIT_EXCLUSIVE, renews it
// with KeepAlive at the daemon's cadence, and issues a deterministic sequence
// of FSKit-shaped mutations. FSKit has no fsync callback, so the authority
// makes every successful FSKit mutation reply durable before sending it. The
// driver therefore treats each success reply as a durability claim: it
// records the complete expected subtree, asks the root harness for a
// dm-log-writes mark over powerloss.MarkChannel (requests on stdout, answers
// on stdin), and sends the next mutation only after the mark is confirmed.
// Every cut taken at or after a mark must then show that step exactly.
//
// It runs as the unprivileged volume identity, like the rest of the data
// plane. It never installs a kernel mount, so the mount-absence evidence it
// presents when it detaches is true by construction.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/test/powerloss"
)

// Session bounds mirror portablefsd's v3 attach, so the authority admits this
// session through the same configuration a Mac presents.
const (
	sessionReplaySlots        uint32 = 128
	sessionMaxInFlight               = 128
	sessionMaxFrame           uint32 = 4 << 20
	sessionDialTimeout               = 10 * time.Second
	sessionCancelDrainTimeout        = 10 * time.Second
	// maxRenewalInterval is the daemon's renewal ceiling.
	maxRenewalInterval = 5 * time.Second
	// teardownBudget bounds the closing Detach.
	teardownBudget = 30 * time.Second
	// absenceComponent names who observed that no kernel mount exists.
	absenceComponent = "pfs-powerloss-fskit-driver"
)

// elementPattern constrains --prefix and --volume to one safe path element,
// the same shape a ledger accepts.
var elementPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "pfs-powerloss-fskit-driver: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	authority  string
	volumeID   string
	volume     string
	tokenFile  string
	tlsCert    string
	tlsKey     string
	tlsCA      string
	serverName string
	ledger     string
	label      string
	prefix     string
}

func parseOptions(arguments []string, progress io.Writer) (options, error) {
	flags := flag.NewFlagSet("pfs-powerloss-fskit-driver", flag.ContinueOnError)
	flags.SetOutput(progress)
	var opts options
	flags.StringVar(&opts.authority, "authority", "", "authority host:port")
	flags.StringVar(&opts.volumeID, "volume-id", "", "exact volume identity to attach")
	flags.StringVar(&opts.volume, "volume", "", "volume directory name inside the XFS cell, recorded in the ledger")
	flags.StringVar(&opts.tokenFile, "access-token-file", "", "file holding a single-use read/write volume capability")
	flags.StringVar(&opts.tlsCert, "tls-cert", "", "client TLS certificate PEM")
	flags.StringVar(&opts.tlsKey, "tls-key", "", "client TLS private key PEM")
	flags.StringVar(&opts.tlsCA, "tls-server-ca", "", "authority CA certificate PEM")
	flags.StringVar(&opts.serverName, "tls-server-name", "", "authority certificate DNS name")
	flags.StringVar(&opts.ledger, "ledger", "", "path the acknowledged-mutation ledger is written to")
	flags.StringVar(&opts.label, "label", "", "prose description of this run, echoed in every report")
	flags.StringVar(&opts.prefix, "prefix", "fskit", "directory the workload creates and owns inside the volume; it must not exist yet")
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	for name, value := range map[string]string{
		"--authority": opts.authority, "--volume-id": opts.volumeID, "--volume": opts.volume,
		"--access-token-file": opts.tokenFile, "--tls-cert": opts.tlsCert, "--tls-key": opts.tlsKey,
		"--tls-server-ca": opts.tlsCA, "--tls-server-name": opts.serverName, "--ledger": opts.ledger, "--label": opts.label,
	} {
		if value == "" {
			return options{}, fmt.Errorf("%s is required", name)
		}
	}
	if !elementPattern.MatchString(opts.prefix) || !elementPattern.MatchString(opts.volume) {
		return options{}, errors.New("--prefix and --volume must each be a single lowercase path element")
	}
	return opts, nil
}

func run(arguments []string, acks io.Reader, requests io.Writer, progress io.Writer) error {
	opts, err := parseOptions(arguments, progress)
	if err != nil {
		return err
	}
	tlsConfig, err := loadTLS(opts.tlsCert, opts.tlsKey, opts.tlsCA, opts.serverName)
	if err != nil {
		return err
	}
	token, err := os.ReadFile(opts.tokenFile)
	if err != nil {
		return fmt.Errorf("read access token: %w", err)
	}
	if token = []byte(strings.TrimSpace(string(token))); len(token) == 0 {
		return errors.New("the access token file is empty")
	}
	ctx := context.Background()
	client, err := authorityrpc.DialClient(ctx, clientConfig(opts, tlsConfig, token))
	if err != nil {
		return fmt.Errorf("attach and activate the FSKit session: %w", err)
	}
	return driveSession(ctx, client, opts, powerloss.NewMarkChannel(requests, acks), progress)
}

// clientConfig is portablefsd's FSKit attach shape: a MOUNT session with the
// exclusive-writer profile, the empty routing declaration a freshly
// provisioned volume runs, and an exact pre-kernel absence observer.
func clientConfig(opts options, tlsConfig *tls.Config, token []byte) authorityrpc.ClientConfig {
	return authorityrpc.ClientConfig{
		Purpose:                      authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
		FrontendProfile:              authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE,
		Address:                      opts.authority,
		TLS:                          tlsConfig,
		VolumeID:                     opts.volumeID,
		AccessToken:                  token,
		ReplaySlots:                  sessionReplaySlots,
		MaxFrame:                     sessionMaxFrame,
		DialTimeout:                  sessionDialTimeout,
		CancelDrainTimeout:           sessionCancelDrainTimeout,
		MaxInFlight:                  sessionMaxInFlight,
		RoutesRevision:               localroutes.RuleSet{}.Revision(),
		ObservePreKernelMountAbsence: observeNoKernelMount,
	}
}

// observeNoKernelMount is this frontend's exact absence evidence. A Mac reads
// getfsstat for its attempt's FSKit source; this driver has no kernel source
// at all, so absence holds at every instant of its life.
func observeNoKernelMount(context.Context) (*authoritypb.MountAbsenceProof, error) {
	return &authoritypb.MountAbsenceProof{
		ObservedUnixNanos: time.Now().UnixNano(),
		Observation:       []byte("no kernel mount: this session's only frontend drives the authority wire directly and never installs one"),
		Component:         absenceComponent,
	}, nil
}

// driveSession runs the workload on an activated session and always ends it
// with the authenticated Detach a clean Mac unmount sends.
func driveSession(ctx context.Context, client *authorityrpc.Client, opts options, marks *powerloss.MarkChannel, progress io.Writer) (err error) {
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), teardownBudget)
		defer cancel()
		if releaseErr := client.ReleaseBeforeMount(releaseCtx); releaseErr != nil {
			err = errors.Join(err, fmt.Errorf("detach the FSKit session: %w", releaseErr))
		}
	}()
	lease := client.SessionLease()
	interval, err := renewalInterval(lease)
	if err != nil {
		return err
	}
	// portablefsd serves nothing until it holds a usable KeepAlive proof; the
	// workload starts from the same point.
	initialCtx, cancel := context.WithTimeout(ctx, lease)
	_, err = client.KeepAlive(initialCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("initial FSKit KeepAlive: %w", err)
	}
	v, err := newAuthorityVolume(client)
	if err != nil {
		return err
	}
	workCtx, stopWork := context.WithCancel(ctx)
	defer stopWork()
	renewal := make(chan error, 1)
	go func() { renewal <- renew(workCtx, client.KeepAlive, interval, lease, stopWork) }()
	ledger := &powerloss.MutationLedger{Volume: opts.volume, Prefix: opts.prefix, Label: opts.label}
	workErr := newWorkload(v, marks, ledger, opts.ledger, progress).run(workCtx)
	if workErr == nil {
		if releaseErr := v.Release(workCtx); releaseErr != nil {
			workErr = fmt.Errorf("release the session's resources after the last acknowledged step: %w", releaseErr)
		}
	}
	stopWork()
	return errors.Join(workErr, <-renewal)
}

// renewalInterval is portablefsd's renewal cadence: at least three renewals
// per session lease, never slower than five seconds, and never slower than a
// third of the largest proof the authority may grant. It is rounded down to
// whole milliseconds, the unit the protocol advertises.
func renewalInterval(lease time.Duration) (time.Duration, error) {
	interval := min(lease/3, maxRenewalInterval, authorityrpc.MaxCacheProof/3).Truncate(time.Millisecond)
	if interval <= 0 {
		return 0, fmt.Errorf("the advertised session lease %s leaves no representable renewal interval", lease)
	}
	return interval, nil
}

// renew keeps the session inside its lease with at most one KeepAlive in
// flight, each bounded by the lease. A failed renewal stops the workload
// through stop: a session that may have expired can no longer acknowledge
// anything this ledger could rely on.
func renew(ctx context.Context, keepAlive func(context.Context) (time.Duration, error), interval, budget time.Duration, stop func()) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			callCtx, cancel := context.WithTimeout(ctx, budget)
			_, err := keepAlive(callCtx)
			cancel()
			if err != nil && ctx.Err() == nil {
				stop()
				return fmt.Errorf("renew the FSKit session: %w", err)
			}
		}
	}
}

func loadTLS(certPath, keyPath, caPath, serverName string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client TLS identity: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read authority CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the authority CA file holds no certificate")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots, Certificates: []tls.Certificate{certificate}}, nil
}
