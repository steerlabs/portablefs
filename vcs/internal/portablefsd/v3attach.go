package portablefsd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// The daemon-owned authority-v3 attach mode.
//
// An authority-v3 attach serves the pfslocal operation surface from the
// standalone v3 data plane (v3dataplane.go) over one strict authorityrpc
// session, never from the legacy clientcore Volume. The two paths share
// nothing: no WAL store, no write-back engine, no delegation handoffs, no
// clientcore session. The daemon — not the FSKit extension — owns the
// mutual-TLS identity and access capability, binds the exact authority
// epoch/session and routes revision, and owns the evidence-bearing detach.
// pfslocal carries only the derived coherence contract and ordered visibility
// obligations.
//
// Failure is terminal for the attach. There is no fallback into the v2
// clientcore path, no transport-mode probing, and no session re-establishment:
// a replacement session cannot prove what the kernel cached before it, so a
// dead session leaves exactly one exit — the exact unmount.

// Dialing bounds for one v3 authority session. These mirror the Linux v3
// frontend's contract decisions (cmd/portablefs-mount-v3): the numbers a
// strict mount DECLARES (cached-name capacity, repair budget, routes revision)
// come from the attach request because the authority reasons from them, while
// these transport bounds are the daemon's own and negotiate downward against
// the authority's advertised limits.
const (
	v3AttachReplaySlots        uint32 = 128
	v3AttachMaxInFlight               = 128
	v3AttachMaxFrame           uint32 = 4 << 20
	v3AttachDialTimeout               = 10 * time.Second
	v3AttachCancelDrainTimeout        = 10 * time.Second
	// v3DetachProofBudget bounds delivery of one mount-absence proof. Strictly
	// under unmountTransactionBudget so the transaction can still publish a
	// verdict for the request that started it.
	v3DetachProofBudget = 15 * time.Second
	// v3DetachProofComponent names the local component that observed the
	// kernel-mount absence inside the proof the authority retains.
	v3DetachProofComponent = "portablefsd/getfsstat"
)

// errV3AttachDetached is the terminal cause recorded on a v3 data plane whose
// attach ended through an explicit detach rather than through a failure.
var errV3AttachDetached = errors.New("portablefsd: v3 attach detached")

// v3AttachRequest is the wire half of a v3 ensure request. The generic
// ensureAttachRequest fields keep their meaning — authority endpoint,
// data-plane transport mode and trust material, access capability, volume
// identity, mount path — and this block carries what only a strict v3
// participant declares.
type v3AttachRequest struct {
	// ClientCertPEM/ClientKeyPEM are the manager-issued mutual-TLS identity
	// this daemon presents to the authority. They never leave the daemon:
	// the FSKit extension sees only the derived pfslocal contract.
	ClientCertPEM string `json:"clientCertPem"`
	ClientKeyPEM  string `json:"clientKeyPem"`
	// CachedNameCapacity and RepairBudgetMillis are the two numbers the
	// authority sizes the visibility barrier from: how many resolutions this
	// mount's kernel may hold, and how long it may take to withdraw one.
	CachedNameCapacity uint64 `json:"cachedNameCapacity"`
	RepairBudgetMillis uint64 `json:"repairBudgetMillis"`
	// CachePolicy is the exact macOS coherence policy string the frontend and
	// authority must agree on (see v3coherence.go).
	CachePolicy string `json:"cachePolicy"`
	// RoutesRevision is the 64-hex-digit digest of the canonical machine-local
	// routing rules this mount runs. The authority refuses any mount whose
	// topology is not the volume's active one.
	RoutesRevision string                    `json:"routesRevision"`
	Enrollment     *v3MountEnrollmentRequest `json:"enrollment,omitempty"`
}

type v3MountEnrollmentRequest struct {
	ManagerURL                      string `json:"managerUrl"`
	ManagerServerName               string `json:"managerServerName"`
	ManagerCAPEM                    string `json:"managerCaPem"`
	EnrollmentID                    string `json:"enrollmentId"`
	EnrollmentCertificatePEM        string `json:"enrollmentCertificatePem"`
	EnrollmentExpiresAtMs           int64  `json:"enrollmentExpiresAtMs"`
	AuthorityGeneration             uint64 `json:"authorityGeneration"`
	InitialAuthorizationExpiresAtMs int64  `json:"initialAuthorizationExpiresAtMs"`
}

// persistedV3Attach is the durable, credential-free record of a v3 attach.
// The mutual-TLS identity is deliberately not persisted: a v3 session dies
// with the daemon process and is never re-established from disk, so the only
// thing a revived record supports is the exact unmount.
type persistedV3Attach struct {
	CachedNameCapacity uint64 `json:"cachedNameCapacity"`
	RepairBudgetMillis uint64 `json:"repairBudgetMillis"`
	CachePolicy        string `json:"cachePolicy"`
	RoutesRevision     string `json:"routesRevision"`
}

// v3AttachConfig is the validated attach-side configuration. It is immutable
// after construction; the mutable session state lives on attach.v3Data.
type v3AttachConfig struct {
	// identity is nil exactly when revived is true.
	identityMu                   sync.RWMutex
	identity                     *tls.Certificate
	cachedNameCapacity           uint64
	repairBudget                 time.Duration
	cachePolicy                  string
	routesRevision               [32]byte
	enrollmentClient             *mountenrollment.Client
	enrollmentID                 string
	enrollmentExpires            time.Time
	initialAuthorizationDeadline time.Time
	// revived marks a record loaded from disk after a daemon restart. Its
	// strict session died with the previous process, and a replacement session
	// cannot prove what the kernel cached before it, so a revived v3 attach is
	// permanently inactivatable and exists only to be exactly unmounted.
	revived bool
}

func (c *v3AttachConfig) clientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if c == nil {
		return nil, errors.New("v3 client identity is unavailable")
	}
	c.identityMu.RLock()
	defer c.identityMu.RUnlock()
	if c.identity == nil {
		return nil, errors.New("v3 client identity is unavailable")
	}
	identity := *c.identity
	identity.Certificate = cloneCertificateChain(c.identity.Certificate)
	return &identity, nil
}

// replacementCertificate validates a manager-renewed certificate against the
// private key that was generated locally for this mount. Reauthorization may
// renew a certificate for that key; changing the key would change the mTLS
// principal and requires a new mount/session.
func (c *v3AttachConfig) replacementCertificate(certificatePEM string, now time.Time) (*tls.Certificate, error) {
	if c == nil || certificatePEM == "" {
		return nil, errors.New("v3 reauthorization requires a renewed client certificate")
	}
	c.identityMu.RLock()
	defer c.identityMu.RUnlock()
	if c.identity == nil || c.identity.PrivateKey == nil {
		return nil, errors.New("v3 client identity is unavailable")
	}
	chain, leaf, err := parseCertificateChain([]byte(certificatePEM))
	if err != nil {
		return nil, err
	}
	signer, ok := c.identity.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("v3 client private key is not a signer")
	}
	want, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	got, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(want, got) {
		return nil, errors.New("renewed client certificate does not match the mount-local private key")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || !permitsClientAuth(leaf.ExtKeyUsage) {
		return nil, errors.New("renewed client certificate is not currently valid for client authentication")
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: c.identity.PrivateKey, Leaf: leaf}, nil
}

func (c *v3AttachConfig) installReplacementCertificate(identity *tls.Certificate) {
	c.identityMu.Lock()
	defer c.identityMu.Unlock()
	c.identity = identity
}

func parseCertificateChain(raw []byte) ([][]byte, *x509.Certificate, error) {
	var chain [][]byte
	rest := raw
	for len(rest) != 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, nil, errors.New("renewed client identity must contain only CERTIFICATE PEM blocks")
		}
		chain = append(chain, append([]byte(nil), block.Bytes...))
		rest = bytes.TrimSpace(remaining)
	}
	if len(chain) == 0 {
		return nil, nil, errors.New("renewed client identity contains no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, nil, err
	}
	return chain, leaf, nil
}

func permitsClientAuth(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func cloneCertificateChain(chain [][]byte) [][]byte {
	copy := make([][]byte, len(chain))
	for index := range chain {
		copy[index] = append([]byte(nil), chain[index]...)
	}
	return copy
}

func (c *v3AttachConfig) persisted() *persistedV3Attach {
	if c == nil {
		return nil
	}
	return &persistedV3Attach{
		CachedNameCapacity: c.cachedNameCapacity,
		RepairBudgetMillis: uint64(c.repairBudget / time.Millisecond),
		CachePolicy:        c.cachePolicy,
		RoutesRevision:     hex.EncodeToString(c.routesRevision[:]),
	}
}

// matches compares the declared contract, not the credential material: the
// capability and mutual-TLS identity legitimately rotate between ensure calls
// for one mount identity, while a changed barrier declaration or routing
// revision is a different mount contract and needs an explicit detach first.
func (c *v3AttachConfig) matches(other *v3AttachConfig) bool {
	return c != nil && other != nil &&
		c.cachedNameCapacity == other.cachedNameCapacity &&
		c.repairBudget == other.repairBudget &&
		c.cachePolicy == other.cachePolicy &&
		c.routesRevision == other.routesRevision &&
		c.enrollmentID == other.enrollmentID
}

func parseV3RoutesRevision(value string) ([32]byte, error) {
	var out [32]byte
	if len(value) != 64 {
		return out, errors.New("routesRevision must be exactly 64 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return out, fmt.Errorf("invalid routesRevision: %w", err)
	}
	copy(out[:], decoded)
	if hex.EncodeToString(out[:]) != value {
		return out, errors.New("routesRevision must be lowercase hexadecimal")
	}
	return out, nil
}

func validPersistedV3Attach(v3 *persistedV3Attach) error {
	if v3.CachedNameCapacity == 0 || v3.RepairBudgetMillis == 0 {
		return errors.New("v3 attach requires a positive cachedNameCapacity and repairBudgetMillis")
	}
	switch v3.CachePolicy {
	case v3CachePolicyMacOS26V1, v3CachePolicyMacOS26, v3CachePolicyFSKit:
	default:
		return fmt.Errorf("unsupported v3 cache policy %q", v3.CachePolicy)
	}
	if _, err := parseV3RoutesRevision(v3.RoutesRevision); err != nil {
		return err
	}
	return nil
}

func revivedV3AttachConfig(v3 *persistedV3Attach) (*v3AttachConfig, error) {
	if err := validPersistedV3Attach(v3); err != nil {
		return nil, err
	}
	revision, err := parseV3RoutesRevision(v3.RoutesRevision)
	if err != nil {
		return nil, err
	}
	return &v3AttachConfig{
		cachedNameCapacity: v3.CachedNameCapacity,
		repairBudget:       time.Duration(v3.RepairBudgetMillis) * time.Millisecond,
		cachePolicy:        v3.CachePolicy,
		routesRevision:     revision,
		revived:            true,
	}, nil
}

// v3ConfigForEnsure validates the v3 half of one ensure request against the
// generic half it rides on. Every refusal here is definite: there is no
// downgrade to the clientcore path and no permissive default for a field the
// authority reasons from.
func v3ConfigForEnsure(req ensureAttachRequest) (*v3AttachConfig, error) {
	v3 := req.V3
	if v3 == nil {
		return nil, nil
	}
	if req.Branch != "" {
		return nil, errors.New("a v3 attach is branchless: branch must be empty")
	}
	if req.AuthToken == "" {
		return nil, errors.New("a v3 attach requires its access capability at ensure time; the strict session is admitted exactly once")
	}
	// The clientcore-only options have no v3 meaning. Accepting them silently
	// would promise cache and graft behavior this attach cannot deliver.
	if req.Options.Prefetch || req.Options.NegativeCache || req.Options.NoNegativeCache ||
		req.Options.DiskCacheDir != "" || req.Options.DiskCacheMB != 0 ||
		len(req.Options.LocalDirs) != 0 || req.Options.VolumeLocalDirs {
		return nil, errors.New("v3 attach refuses clientcore-only options (prefetch, caches, local-dir grafts)")
	}
	// authorityrpc speaks only verified TLS 1.3 with a client identity, so the
	// plaintext transport mode cannot carry a v3 session and is refused here
	// rather than failing later inside the dial with a transport-shaped error.
	switch req.DataPlaneTransport {
	case "tls-private-ca", "tls-system-pki":
	default:
		return nil, fmt.Errorf("v3 attach requires mutually authenticated TLS; transport %q is refused", req.DataPlaneTransport)
	}
	if err := validPersistedV3Attach(&persistedV3Attach{
		CachedNameCapacity: v3.CachedNameCapacity,
		RepairBudgetMillis: v3.RepairBudgetMillis,
		CachePolicy:        v3.CachePolicy,
		RoutesRevision:     v3.RoutesRevision,
	}); err != nil {
		return nil, err
	}
	identity, err := tls.X509KeyPair([]byte(v3.ClientCertPEM), []byte(v3.ClientKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid v3 mutual-TLS identity: %w", err)
	}
	revision, err := parseV3RoutesRevision(v3.RoutesRevision)
	if err != nil {
		return nil, err
	}
	var enrollmentClient *mountenrollment.Client
	var enrollmentID string
	var enrollmentExpires time.Time
	var initialAuthorizationDeadline time.Time
	if v3.Enrollment != nil {
		enrollment := v3.Enrollment
		if req.AuthTokenExpiresAtMs != enrollment.InitialAuthorizationExpiresAtMs ||
			enrollment.InitialAuthorizationExpiresAtMs <= time.Now().UnixMilli() ||
			enrollment.EnrollmentExpiresAtMs <= enrollment.InitialAuthorizationExpiresAtMs {
			return nil, errors.New("v3 automatic enrollment requires matching, unexpired authorization lifetimes")
		}
		enrollmentClient, err = mountenrollment.NewClient(mountenrollment.Config{
			ManagerURL: enrollment.ManagerURL, ManagerServerName: enrollment.ManagerServerName,
			ManagerCAPEM: []byte(enrollment.ManagerCAPEM), EnrollmentID: enrollment.EnrollmentID,
			EnrollmentCertificatePEM: []byte(enrollment.EnrollmentCertificatePEM), ClientKeyPEM: []byte(v3.ClientKeyPEM),
			VolumeID: req.VolumeID, AuthorityGeneration: enrollment.AuthorityGeneration,
			EnrollmentExpires: time.UnixMilli(enrollment.EnrollmentExpiresAtMs),
		})
		if err != nil {
			return nil, fmt.Errorf("invalid v3 automatic mount enrollment: %w", err)
		}
		enrollmentID = enrollment.EnrollmentID
		enrollmentExpires = time.UnixMilli(enrollment.EnrollmentExpiresAtMs)
		initialAuthorizationDeadline = time.UnixMilli(enrollment.InitialAuthorizationExpiresAtMs)
	}
	return &v3AttachConfig{
		identity: &identity, cachedNameCapacity: v3.CachedNameCapacity,
		repairBudget: time.Duration(v3.RepairBudgetMillis) * time.Millisecond,
		cachePolicy:  v3.CachePolicy, routesRevision: revision,
		enrollmentClient: enrollmentClient, enrollmentID: enrollmentID, enrollmentExpires: enrollmentExpires,
		initialAuthorizationDeadline: initialAuthorizationDeadline,
	}, nil
}

// v3NamespaceRepair is how this mount's kernel makes a cached name binding
// unservable, declared per cache policy because the authority cannot observe a
// remote kernel and the two policies repair through different mechanisms:
// macOS 26 repairs synchronously through the VFS — the repair traverses the
// same namespace locks an unanswered directory mutation can hold, which is the
// CALLBACK_SERIALIZED contract — live macOS 26 FSKit also serializes disjoint
// mutation and repair callbacks through shared execution capacity. The native
// FSKit revocation API revokes kernel cache entries without re-entering the
// namespace and therefore declares INDEPENDENT.
func v3NamespaceRepair(cachePolicy string) authoritypb.NamespaceRepair {
	switch cachePolicy {
	case v3CachePolicyMacOS26V1:
		return authoritypb.NamespaceRepair_NAMESPACE_REPAIR_CALLBACK_SERIALIZED
	case v3CachePolicyMacOS26:
		return authoritypb.NamespaceRepair_NAMESPACE_REPAIR_CALLBACK_SERIALIZED_PIPELINED
	case v3CachePolicyFSKit:
		return authoritypb.NamespaceRepair_NAMESPACE_REPAIR_INDEPENDENT
	default:
		return authoritypb.NamespaceRepair_NAMESPACE_REPAIR_UNSPECIFIED
	}
}

// v3AuthoritySession is the slice of authorityrpc.Client the attach lifecycle
// itself needs beyond the data plane: leaving the barrier with evidence.
type v3AuthoritySession interface {
	DetachAfterUnmount(context.Context, *authoritypb.MountAbsenceProof) error
}

// isV3 is stable for the attach lifetime: v3Config is assigned before the
// attach is registered and never mutated afterwards.
func (a *attach) isV3() bool { return a.v3Config != nil }

func (a *attach) v3Backend() *v3DataPlane {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.v3Data
}

// fenceV3 ends the strict session. The data plane records the terminal cause,
// the bridge fails closed, and the authorityrpc client is closed, so the
// authority fences this participant on its session lease if it has not been
// told anything better. Idempotent; a nil plane (a revived record) has no
// session left to fence.
func (a *attach) fenceV3(cause error) {
	a.mu.RLock()
	d := a.v3Data
	a.mu.RUnlock()
	if d != nil {
		_ = d.fail(cause)
	}
}

// startV3 activates a fresh v3 attach: it dials the authority under the exact
// declared transport (no probing, no fallback between modes), attaches the
// branchless strict session, constructs the data plane and coherence bridge,
// and installs them on the attach. Any failure is the caller's definite error;
// nothing here retries into the clientcore path.
func (a *attach) startV3(ctx context.Context) error {
	cfg := a.v3Config
	if cfg == nil {
		return errors.New("attach carries no v3 configuration")
	}
	if cfg.revived {
		return errors.New("a v3 attach cannot be reactivated after a daemon restart: its strict authority session died with the previous process and a replacement session cannot prove what the kernel cached before it; unmount the attach")
	}
	a.mu.RLock()
	existing := a.v3Data
	a.mu.RUnlock()
	if existing != nil {
		if err := existing.terminalError(); err != nil {
			return fmt.Errorf("v3 attach is terminal: %w; unmount it before mounting again", err)
		}
		return nil
	}
	tlsCfg, err := (dataPlaneTransport{
		mode:       a.dataPlaneTransport,
		serverName: a.dataPlaneServerName,
		caPEM:      a.tlsCAPEM,
		caSHA256:   a.tlsCASHA256,
	}).tlsConfig()
	if err != nil {
		return err
	}
	if tlsCfg == nil {
		// Unreachable after v3ConfigForEnsure, kept as a structural guard: the
		// dial below must never run without endpoint verification.
		return errors.New("v3 attach requires a verified TLS transport")
	}
	tlsCfg.Certificates = nil
	tlsCfg.GetClientCertificate = cfg.clientCertificate
	a.credMu.RLock()
	token := a.token
	a.credMu.RUnlock()
	client, err := authorityrpc.DialClient(ctx, authorityrpc.ClientConfig{
		Address:                               a.authorityAddr,
		TLS:                                   tlsCfg,
		VolumeID:                              a.volumeID,
		AccessToken:                           []byte(token),
		ReplaySlots:                           v3AttachReplaySlots,
		MaxFrame:                              v3AttachMaxFrame,
		DialTimeout:                           v3AttachDialTimeout,
		CancelDrainTimeout:                    v3AttachCancelDrainTimeout,
		MaxInFlight:                           v3AttachMaxInFlight,
		CoherenceProfile:                      authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity:                    cfg.cachedNameCapacity,
		RepairBudget:                          cfg.repairBudget,
		NamespaceRepair:                       v3NamespaceRepair(cfg.cachePolicy),
		RoutesRevision:                        cfg.routesRevision,
		RequireMountEnrollmentReauthorization: cfg.enrollmentClient != nil,
	})
	if err != nil {
		return fmt.Errorf("attach v3 authority session: %w", err)
	}
	if cfg.enrollmentClient != nil && !client.InitialAuthorizationDeadline().Equal(cfg.initialAuthorizationDeadline) {
		_ = client.Close()
		return fmt.Errorf("authority installed authorization deadline %s, Manager response declared %s",
			client.InitialAuthorizationDeadline().UTC().Format(time.RFC3339Nano), cfg.initialAuthorizationDeadline.UTC().Format(time.RFC3339Nano))
	}
	// The data plane owns the client from here: every constructor failure path
	// inside newV3DataPlane records a terminal cause and closes it.
	d, err := newV3DataPlane(a.lifetime(), v3DataPlaneConfig{
		Client:         client,
		VolumeID:       a.volumeID,
		VolumeName:     a.volumeName,
		ItemGeneration: a.identityEpoch,
		PrincipalUID:   uint32(os.Getuid()),
		PrincipalGID:   uint32(os.Getgid()),
		CachePolicy:    cfg.cachePolicy,
	})
	if err != nil {
		return fmt.Errorf("construct v3 data plane: %w", err)
	}
	a.mu.Lock()
	if a.detached {
		a.mu.Unlock()
		_ = d.fail(errors.New("portablefsd: attach detached during v3 activation"))
		return errors.New("attach is detached")
	}
	a.v3Data = d
	a.v3Session = client
	a.v3Coherence = d.bridge
	if cfg.enrollmentClient != nil {
		a.authorizationDeadlineAtMs = cfg.initialAuthorizationDeadline.UnixMilli()
	}
	a.mu.Unlock()
	go a.watchV3Terminal(d)
	if cfg.enrollmentClient != nil {
		go a.runAutomaticMountRenewal(cfg, d)
	}
	return nil
}

func (a *attach) runAutomaticMountRenewal(cfg *v3AttachConfig, d *v3DataPlane) {
	renewer := &mountenrollment.Renewer{
		Source: cfg.enrollmentClient, MinimumSafetyMargin: cfg.repairBudget,
		Observe: func(status mountenrollment.RenewalStatus) {
			a.mu.Lock()
			a.authorizationDeadlineAtMs = status.AuthorizationDeadline.UnixMilli()
			if !status.LastSuccess.IsZero() {
				a.lastReauthorizationAtMs = status.LastSuccess.UnixMilli()
			}
			if !status.NextAttempt.IsZero() {
				a.nextReauthorizationAtMs = status.NextAttempt.UnixMilli()
			}
			a.reauthorizationFailures = status.ConsecutiveFailures
			a.reauthorizationError = status.LastError
			a.mu.Unlock()
		},
	}
	err := renewer.Run(a.lifetime(), d.authorizationSessionID(), cfg.initialAuthorizationDeadline,
		func(ctx context.Context, token string, sequence uint64, certificatePEM []byte) (time.Time, error) {
			replacement, err := cfg.replacementCertificate(string(certificatePEM), time.Now())
			if err != nil {
				return time.Time{}, err
			}
			deadline, err := d.reauthorize(ctx, []byte(token), sequence)
			if err != nil {
				return time.Time{}, err
			}
			cfg.installReplacementCertificate(replacement)
			return deadline, nil
		})
	if err == nil || a.isDetached() {
		return
	}
	a.setErr(fmt.Errorf("automatic mount reauthorization failed closed: %w", err))
	_ = d.fail(err)
}

// watchV3Terminal publishes the data plane's terminal verdict onto the attach
// so status and the frontend report a definite degraded state the moment the
// session dies, not at the next operation. An explicit detach is not an error.
func (a *attach) watchV3Terminal(d *v3DataPlane) {
	<-d.ctx.Done()
	err := d.terminalError()
	if err == nil || errors.Is(err, errV3AttachDetached) || a.isDetached() {
		return
	}
	a.setErr(fmt.Errorf(
		"v3 authority session is terminal: %v; every operation fails closed (ENOTCONN) and only an exact unmount resolves it", err,
	))
}

// v3RootReply is Resolve for a v3 attach: the reply — including the
// V3CoherenceContract with the exact authority epoch, session, protocol and
// cache policy — comes wholly from the v3 data plane, never from the
// clientcore item registry.
func (a *attach) v3RootReply() (pfslocal.ResolveReply, int32) {
	a.mu.RLock()
	unavailable := a.detached || a.detachPrepared || a.detachForce
	d := a.v3Data
	a.mu.RUnlock()
	if unavailable {
		return pfslocal.ResolveReply{}, darwinENXIO
	}
	if d == nil {
		// A revived record or an attach whose activation never completed: there
		// is no session whose contract could be resolved.
		return pfslocal.ResolveReply{}, darwinEIO
	}
	if err := d.terminalError(); err != nil {
		return pfslocal.ResolveReply{}, darwinENOTCONN
	}
	reply := d.resolveReply()
	if reply == nil {
		return pfslocal.ResolveReply{}, darwinEIO
	}
	return *reply, 0
}

// handleV3Attached serves one frontend request of a v3 attach. It keeps the
// connection's logical-operation ledger — reservation, exposure, and the one
// post-callback PublicationAck — because the coherence bridge's source
// COMPLETE barrier is built on exactly that acknowledgement, but it never
// enters the clientcore admission, mirror, or delegation machinery: the v3
// data plane owns its own ordering and concurrency bounds.
func (c *frontendConn) handleV3Attached(
	ctx context.Context,
	a *attach,
	requestID uint64,
	operationID uint64,
	sourcePhaseQueueable bool,
	initializeOperation bool,
	body any,
) {
	if operationID != 0 {
		defer c.finishLogicalRequest(operationID)
	}
	ctx, cancelOperation := withOperationDeadline(ctx)
	defer cancelOperation()
	gateCtx, participant, participates, publishes, err := c.beginLogicalOperation(
		ctx, a, operationID, initializeOperation, body,
	)
	if err != nil {
		_ = c.conn.Close()
		return
	}
	if participates {
		defer a.finishFrontendParticipant(participant)
	}
	if _, ok := body.(*pfslocal.SubscribeEventsRequest); ok {
		// Subscription binds the one lossless visibility consumer for this
		// mount incarnation (see frontendConn.subscribeEvents); until it is
		// bound the data plane answers EAGAIN by design.
		if err := c.subscribeEvents(a); err != nil {
			c.errorReply(requestID, darwinEIO, err.Error())
			return
		}
		c.reply(requestID, &pfslocal.SubscribeEventsReply{})
		return
	}
	d := a.v3Backend()
	var (
		reply any
		eno   int32
	)
	resources := &v3ReplyResourceCollector{d: d}
	switch body.(type) {
	case *pfslocal.CreateRequest, *pfslocal.MkdirRequest, *pfslocal.SymlinkRequest:
		resources.visible = true
	}
	dispatchCtx := context.WithValue(gateCtx, v3ReplyResourceContextKey{}, resources)
	switch {
	case d == nil:
		eno = darwinEIO
	case d.terminalError() != nil:
		eno = darwinENOTCONN
	default:
		reply, eno = d.dispatchFrontend(
			dispatchCtx, operationID, sourcePhaseQueueable, body,
		)
		if eno == darwinEIO && d.terminalError() != nil {
			// The failure that produced this errno killed the session. Report
			// the session verdict, not a per-operation I/O fault: FSKit must
			// stop retrying against a mount that can never answer again.
			eno = darwinENOTCONN
		}
	}
	if eno != 0 {
		if d != nil && (len(resources.items) != 0 || len(resources.handles) != 0) {
			cleanup, prepareErr := d.abandonCollectedReplyResources(resources)
			if cleanup != nil && prepareErr == nil {
				if cleanup.required() {
					go func() {
						if err := cleanup.finish(); err != nil {
							_ = d.fail(err)
						}
					}()
				}
			}
			if prepareErr != nil {
				_ = d.fail(prepareErr)
			}
			// Incomplete publication of a successful visible resource reply is
			// detected by the synchronous disposition above. Re-read the terminal
			// state after that transition so this callback reports the session
			// verdict rather than its earlier per-operation errno.
			if d.terminalError() != nil {
				eno = darwinENOTCONN
			}
		}
		failure := &pfslocal.ErrorReply{Errno: eno, Message: errMessage(fmt.Sprintf("%T", body), eno)}
		if publishes {
			c.replyWithPublication(requestID, operationID, failure, true)
		} else {
			c.errorReplyForOperation(requestID, operationID, eno, failure.Message)
		}
		return
	}
	resourceReply, resourceErr := resourceBearingV3Reply(reply, resources)
	if resourceErr != nil {
		provisional, prepareErr := d.prepareReplyResources(resources)
		if provisional != nil {
			cleanup, cleanupErr := d.applyReplyResourceDisposition(
				provisional, false, 0,
			)
			if cleanupErr == nil {
				go func() {
					if err := cleanup.finish(); err != nil {
						_ = d.fail(err)
					}
				}()
			} else {
				prepareErr = errors.Join(prepareErr, cleanupErr)
			}
		}
		resourceErr = errors.Join(resourceErr, prepareErr)
		_ = d.fail(resourceErr)
		_ = c.conn.Close()
		return
	}
	if resourceReply {
		provisional, err := d.prepareReplyResources(resources)
		if err != nil {
			if provisional != nil {
				if cleanup, cleanupErr := d.applyReplyResourceDisposition(
					provisional, false, 0,
				); cleanupErr == nil {
					go func() {
						if finishErr := cleanup.finish(); finishErr != nil {
							_ = d.fail(finishErr)
						}
					}()
				} else {
					err = errors.Join(err, cleanupErr)
				}
			}
			_ = d.fail(err)
			_ = c.conn.Close()
			return
		}
		cleanup, registered, err := c.registerProvisionalResourceOrAbandon(requestID, provisional)
		if !registered {
			if err != nil {
				_ = d.fail(err)
			} else if cleanup.required() {
				go func() {
					if err := cleanup.finish(); err != nil {
						_ = d.fail(err)
					}
				}()
			}
			_ = c.conn.Close()
			return
		}
	}
	c.replyWithPublication(requestID, operationID, reply, publishes)
}

// detachV3 is the evidence-bearing unmount of one v3 attach. The caller owns
// registry.mutationMu (it runs inside runUnmountTransaction) and the shared
// registry-removal tail runs after it returns nil.
//
// Order is the contract: exact kernel detach first, then the getfsstat
// absence observation, then delivery of that proof to the authority, and only
// then the local release. A proof that cannot be produced or delivered ends
// the attach FENCED — the session is closed so the authority's lease sweep
// fences this participant — never silently absent.
func (r *registry) detachV3(a *attach, force bool, ops fskitKernelOps) error {
	present, err := ops.present(a.mountPath, a.ref)
	if err != nil {
		// Nothing irreversible has happened: the mount may still be serving,
		// so this refusal leaves the attach fully alive and retryable.
		return fmt.Errorf("classify v3 FSKit detach: %w", err)
	}
	if present {
		bridge := a.v3CoherenceBridge()
		if bridge == nil {
			return errors.New("v3 FSKit detach has no live coherence bridge")
		}
		if err := bridge.beginDetach(); err != nil {
			return fmt.Errorf("begin v3 FSKit detach: %w", err)
		}
		detachErr := ops.unmountExact(a.mountPath, a.ref, force)
		if detachErr != nil && !force && errors.Is(detachErr, syscall.EBUSY) {
			// A normal v3 detach is deliberately two-phase on Darwin.
			// dounmount without MNT_FORCE first runs ubc_umount and
			// VFS_SYNC(MNT_WAIT), returning any sync error before it reaches
			// vflush. PortableFS itself retains the mount-root descriptor that
			// macOS 26 repair actuation requires, so that fully synchronized
			// pass then answers EBUSY. Only that exact errno authorizes the
			// second MNT_FORCE pass, which revokes the product-owned vnode and
			// open user references but is not trusted as a flush barrier (XNU
			// skips VFS_SYNC for forced unmounts). Any other first-pass error
			// leaves the live mount attached.
			detachErr = ops.unmountExact(a.mountPath, a.ref, true)
		}
		if detachErr != nil {
			bridge.abortDetach(detachErr)
			// The kernel mount remains (or its state is still owned by an
			// abandoned helper); the attach keeps serving and the caller
			// retries or escalates.
			return detachErr
		}
		present, err = ops.present(a.mountPath, a.ref)
		if err == nil && present {
			err = fmt.Errorf("kernel mount remains at %s after exact detach", a.mountPath)
		}
		if err != nil {
			// The detach ran but exact absence cannot be observed, so the one
			// honest statement left is session death: the authority must fence
			// this participant rather than trust an unprovable teardown.
			cause := fmt.Errorf("v3 mount-absence proof cannot be produced: %w", err)
			a.fenceV3(cause)
			return cause
		}
	}
	observed := time.Now()
	proof := &authoritypb.MountAbsenceProof{
		ObservedUnixNanos: observed.UnixNano(),
		Observation: []byte(fmt.Sprintf(
			"getfsstat(MNT_NOWAIT) reports no kernel mount at %s for attach %s at %s",
			a.mountPath, a.ref, observed.UTC().Format(time.RFC3339Nano),
		)),
		Component: v3DetachProofComponent,
	}
	a.mu.RLock()
	session := a.v3Session
	d := a.v3Data
	a.mu.RUnlock()
	if session != nil && d != nil && d.terminalError() == nil {
		proofCtx, cancel := context.WithTimeout(context.Background(), v3DetachProofBudget)
		deliverErr := session.DetachAfterUnmount(proofCtx, proof)
		cancel()
		if deliverErr != nil {
			// The proof exists but the authority did not accept it. Ending the
			// session here is what keeps the detach honest: the authority
			// fences this participant on its lease instead of carrying a
			// barrier member whose mount silently vanished.
			a.fenceV3(fmt.Errorf("deliver v3 mount-absence proof: %w", deliverErr))
			log.Printf(
				"portablefsd: attach %s: kernel mount at %s is exactly absent but the mount-absence proof could not be delivered (%v); the strict session ends fenced",
				a.ref, a.mountPath, deliverErr,
			)
		}
	}
	// Terminal either way: an already-fenced plane keeps its original cause.
	a.fenceV3(errV3AttachDetached)
	a.frontendSerial.Lock()
	a.nsMu.Lock()
	_, err = a.finishDetachWithNSLocked("", nil)
	return err
}
