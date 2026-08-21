// Command pfs-coherence-routes is the coherence harness's route-administration
// and route-contract tool.
//
// It exists because two things the matrix needs are not syscalls, and the
// matrix driver is deliberately syscall-only:
//
//   - installing a machine-local route declaration in the volume. The authority
//     owns .portablefs/local-dirs and refuses mount mutation of it, so a
//     declaration can only arrive through an admin ApplyRoutes call.
//   - attaching with a deliberately WRONG routing revision. A mount binary
//     adopts the volume's declaration from the refusal and retries, which is
//     the behaviour under test everywhere else; asserting the refusal itself
//     needs a client that does not adopt.
//
// Both use authorityrpc.Client directly - the same client the mount uses - so
// what is measured is the production contract and not a private reimplementation
// of it.
//
//	pfs-coherence-routes --apply-file rules.txt        # install a declaration
//	pfs-coherence-routes --check-revision-contract     # the two-attempt contract
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pfs-coherence-routes: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	address     string
	volumeID    string
	tokenFile   string
	clientCert  string
	clientKey   string
	serverCA    string
	serverName  string
	maxFrame    uint
	dialTimeout time.Duration
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("pfs-coherence-routes", flag.ExitOnError)
	var (
		o         options
		applyFile = flags.String("apply-file", "", "install this file as the volume's route declaration (needs an admin capability)")
		check     = flags.Bool("check-revision-contract", false,
			"attach with a deliberately wrong revision without adopting, then adopt and retry; print the observed contract")
	)
	flags.StringVar(&o.address, "authority", "", "authority host:port")
	flags.StringVar(&o.volumeID, "volume-id", "", "exact volume identity")
	flags.StringVar(&o.tokenFile, "access-token-file", "", "file holding one single-use capability")
	flags.StringVar(&o.clientCert, "tls-cert", "", "client certificate PEM")
	flags.StringVar(&o.clientKey, "tls-key", "", "client private key PEM")
	flags.StringVar(&o.serverCA, "tls-server-ca", "", "authority CA certificate PEM")
	flags.StringVar(&o.serverName, "tls-server-name", "", "authority certificate DNS name")
	flags.UintVar(&o.maxFrame, "max-frame-bytes", 16<<20, "hard protobuf frame bound")
	flags.DurationVar(&o.dialTimeout, "dial-timeout", 15*time.Second, "authority dial and TLS timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if o.address == "" || o.volumeID == "" || o.tokenFile == "" {
		return errors.New("--authority, --volume-id and --access-token-file are required")
	}
	switch {
	case *applyFile != "" && *check:
		return errors.New("--apply-file and --check-revision-contract are separate operations")
	case *applyFile != "":
		return applyRoutes(o, *applyFile)
	case *check:
		return checkRevisionContract(o)
	default:
		return errors.New("one of --apply-file or --check-revision-contract is required")
	}
}

func clientConfig(o options, token []byte, revision [32]byte, purpose authoritypb.SessionPurpose) (authorityrpc.ClientConfig, error) {
	certificate, err := tls.LoadX509KeyPair(o.clientCert, o.clientKey)
	if err != nil {
		return authorityrpc.ClientConfig{}, fmt.Errorf("load client identity: %w", err)
	}
	caPEM, err := os.ReadFile(o.serverCA)
	if err != nil {
		return authorityrpc.ClientConfig{}, fmt.Errorf("read authority CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return authorityrpc.ClientConfig{}, errors.New("authority CA PEM contains no certificate")
	}
	cfg := authorityrpc.ClientConfig{
		Address:  o.address,
		VolumeID: o.volumeID,
		TLS: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			RootCAs:      pool,
			ServerName:   o.serverName,
			MinVersion:   tls.VersionTLS13,
		},
		AccessToken:        token,
		Purpose:            purpose,
		ReplaySlots:        8,
		MaxFrame:           uint32(o.maxFrame),
		DialTimeout:        o.dialTimeout,
		CancelDrainTimeout: 10 * time.Second,
		MaxInFlight:        4,
		RoutesRevision:     revision,
	}
	if purpose == authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT {
		// A mount-purpose attach is what learns the volume's active routing
		// revision from the refusal that carries it, so this tool declares the
		// same frontend profile the real Linux mount declares. Anything else
		// would be refused for the wrong reason and prove nothing about routing.
		cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES
		cfg.ObservePreKernelMountAbsence = func(context.Context) (*authoritypb.MountAbsenceProof, error) {
			return administrativeAbsenceProof(), nil
		}
	}
	return cfg, nil
}

func administrativeAbsenceProof() *authoritypb.MountAbsenceProof {
	return &authoritypb.MountAbsenceProof{
		ObservedUnixNanos: time.Now().UnixNano(),
		Observation:       []byte("route administration process has no kernel mount path or FUSE connection"),
		Component:         "pfs-coherence-routes/no-kernel-mount",
	}
}

func releaseMountClient(client *authorityrpc.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	releaseErr := client.ReleaseBeforeMount(ctx)
	cancel()
	return errors.Join(releaseErr, client.Close())
}

func releaseAdminClient(client *authorityrpc.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	detachErr := client.DetachRouteAdmin(ctx)
	cancel()
	return errors.Join(detachErr, client.Close())
}

// dialOnce makes one attach attempt. The TLS configuration is cloned per
// attempt because a dial takes ownership of the one it is given, and this tool
// deliberately attaches more than once with the same capability.
func dialOnce(ctx context.Context, cfg authorityrpc.ClientConfig) (*authorityrpc.Client, error) {
	if cfg.TLS != nil {
		cfg.TLS = cfg.TLS.Clone()
	}
	return authorityrpc.DialClient(ctx, cfg)
}

func dialAdminOnce(ctx context.Context, cfg authorityrpc.ClientConfig) (*authorityrpc.Client, error) {
	if cfg.TLS != nil {
		cfg.TLS = cfg.TLS.Clone()
	}
	return authorityrpc.DialRouteAdminClient(ctx, cfg)
}

// applyRoutes installs a declaration through the admin ApplyRoutes call.
//
// The compare-and-swap expects the revision that is active NOW, which this
// process learns the only way a peer without a session can: by attaching with
// the empty rule set and reading the refusal. On a volume that has no
// declaration yet, that first attach succeeds and the expected revision is the
// empty one.
func applyRoutes(o options, path string) error {
	rulesText, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rule file: %w", err)
	}
	rules, err := localroutes.Parse(rulesText)
	if err != nil {
		return fmt.Errorf("compile %s: %w", path, err)
	}
	token, err := os.ReadFile(o.tokenFile)
	if err != nil {
		return fmt.Errorf("read capability: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg, err := clientConfig(o, token, [32]byte{}, authoritypb.SessionPurpose_SESSION_PURPOSE_ROUTE_ADMIN)
	if err != nil {
		return err
	}
	client, err := dialAdminOnce(ctx, cfg)
	if err != nil {
		return fmt.Errorf("attach route administrator: %w", err)
	}
	expected := client.RoutesRevision()

	reply, err := client.ApplyRoutes(ctx, rules.Canonical(), expected)
	if err != nil {
		return errors.Join(fmt.Errorf("apply routes: %w", err), releaseAdminClient(client))
	}
	if err := releaseAdminClient(client); err != nil {
		return fmt.Errorf("release route-administration session: %w", err)
	}
	fmt.Printf("applied_revision=%x\n", reply.GetRevision())
	fmt.Printf("applied_canonical_bytes=%d\n", len(reply.GetCanonical()))
	fmt.Printf("applied_patterns=%v\n", rules.Patterns())
	fmt.Printf("acknowledged_participants=%d\n", reply.GetAcknowledgedParticipants())
	if got := hex.EncodeToString(reply.GetRevision()); got != rules.RevisionHex() {
		return fmt.Errorf("the authority made %s active but the rules given hash to %s", got, rules.RevisionHex())
	}
	return nil
}

// checkRevisionContract is the observable half of routes_revision_mismatch.
//
// It performs the exact experiment the matrix cannot: attach with a revision
// that is deliberately not the volume's, WITHOUT adopting, and report what the
// refusal carried. Then it adopts and retries on the SAME capability and reports
// how many attach attempts that took.
//
// It prints a machine-readable summary and exits 0 whenever the experiment could
// be RUN. Whether the observations are the right ones is the matrix's judgement,
// not this tool's: a helper that decided pass and fail for itself would move the
// assertion out of the harness, where a reader can see it.
func checkRevisionContract(o options) error {
	token, err := os.ReadFile(o.tokenFile)
	if err != nil {
		return fmt.Errorf("read capability: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A revision that is definitely not the volume's: the digest of a rule set
	// nothing would ever declare. It is derived rather than hard-coded so it
	// stays a legal revision if the digest ever changes shape.
	stale, err := localroutes.Parse([]byte("pfs-deliberately-stale-revision/\n"))
	if err != nil {
		return fmt.Errorf("compile the stale rule set: %w", err)
	}
	staleRevision := stale.Revision()
	cfg, err := clientConfig(o, token, staleRevision, authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT)
	if err != nil {
		return err
	}

	attempts := 1
	client, err := dialOnce(ctx, cfg)
	if err == nil {
		_ = releaseMountClient(client)
		fmt.Printf("stale_attach_refused=false\n")
		fmt.Printf("attempts=%d\n", attempts)
		return nil
	}
	var mismatch *authorityrpc.RoutesMismatchError
	if !errors.As(err, &mismatch) {
		fmt.Printf("stale_attach_refused=true\n")
		fmt.Printf("refusal_is_routing_mismatch=false\n")
		fmt.Printf("refusal_detail=%s\n", err)
		fmt.Printf("attempts=%d\n", attempts)
		return nil
	}
	adopted, parseErr := localroutes.Parse(mismatch.Canonical)
	canonicalMatchesActive := parseErr == nil && adopted.Revision() == mismatch.Active

	fmt.Printf("stale_attach_refused=true\n")
	fmt.Printf("refusal_is_routing_mismatch=true\n")
	fmt.Printf("refusal_declared=%t\n", mismatch.Declared)
	fmt.Printf("refusal_presented=%x\n", mismatch.Presented)
	fmt.Printf("refusal_active=%x\n", mismatch.Active)
	fmt.Printf("presented_is_the_stale_one=%t\n", mismatch.Presented == staleRevision)
	fmt.Printf("refusal_canonical_bytes=%d\n", len(mismatch.Canonical))
	fmt.Printf("refusal_canonical_matches_active=%t\n", canonicalMatchesActive)
	fmt.Printf("refusal_canonical_patterns=%v\n", adopted.Patterns())
	fmt.Printf("refusal_detail=%s\n", mismatch.Error())

	if !canonicalMatchesActive {
		fmt.Printf("attempts=%d\n", attempts)
		fmt.Printf("adopt_succeeded=false\n")
		return nil
	}
	// Adopt and retry ON THE SAME CAPABILITY. That it works at all is the
	// property: a routing refusal must not spend the single-use token, or a
	// mount would need two credentials to complete a handshake it was just
	// taught how to complete.
	cfg.RoutesRevision = adopted.Revision()
	attempts++
	client, err = dialOnce(ctx, cfg)
	if err != nil {
		fmt.Printf("attempts=%d\n", attempts)
		fmt.Printf("adopt_succeeded=false\n")
		fmt.Printf("adopt_error=%s\n", err)
		return nil
	}
	releaseErr := releaseMountClient(client)
	fmt.Printf("attempts=%d\n", attempts)
	fmt.Printf("adopt_succeeded=%t\n", releaseErr == nil)
	if releaseErr != nil {
		fmt.Printf("adopt_error=%s\n", releaseErr)
	}
	fmt.Printf("adopt_revision=%x\n", adopted.Revision())
	return nil
}
