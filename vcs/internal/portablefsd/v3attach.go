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
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/lantrace"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/mountlog"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

const (
	v3ReauthorizationSafetyMargin        = 15 * time.Second
	v3AttachReplaySlots           uint32 = 128
	v3AttachMaxInFlight                  = 128
	v3AttachMaxFrame              uint32 = 4 << 20
	v3AttachDialTimeout                  = 10 * time.Second
	v3AttachCancelDrainTimeout           = 10 * time.Second
	// v3DetachProofComponent names the trusted local supervisor component that
	// observed the kernel-mount absence.
	v3DetachProofComponent = "portablefsd/getfsstat"
)

// v3DetachProofBudget bounds delivery of one mount-absence proof. Strictly under unmountTransactionBudget so the
// transaction can still publish a verdict for the request that started it. A
// variable only so tests can exercise its expiry.
var v3DetachProofBudget = 15 * time.Second

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
	AuthorityGeneration             uint64 `json:"authorityGeneration"`
	InitialAuthorizationExpiresAtMs int64  `json:"initialAuthorizationExpiresAtMs"`
}

// persistedV3Attach is the durable, credential-free record of a v3 attach.
// The mutual-TLS identity is deliberately not persisted: a v3 session dies
// with the daemon process and is never re-established from disk, so the only
// thing a revived record supports is the exact unmount.
type persistedV3Attach struct {
	RoutesRevision string `json:"routesRevision"`
}

// v3AttachConfig is the validated attach-side configuration. It is immutable
// after construction; the mutable session state lives on attach.v3Data.
type v3AttachConfig struct {
	// identity is nil exactly when revived is true.
	identityMu sync.RWMutex
	identity   *tls.Certificate

	routesRevision               [32]byte
	enrollmentClient             *mountenrollment.Client
	enrollmentID                 string
	initialAuthorizationDeadline time.Time
	// preKernelMountAbsence is non-nil only in package tests running without
	// Darwin getfsstat. Production binds a fresh observer to a.mountPath and
	// a.ref in startV3, after the stable attach identity exists.
	preKernelMountAbsence authorityrpc.PreKernelMountAbsenceObserver
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
		RoutesRevision: hex.EncodeToString(c.routesRevision[:]),
	}
}

// matches compares the declared contract, not the credential material: the
// capability and mutual-TLS identity legitimately rotate between ensure calls
// for one mount identity, while a changed barrier declaration or routing
// revision is a different mount contract and needs an explicit detach first.
func (c *v3AttachConfig) matches(other *v3AttachConfig) bool {
	return c != nil && other != nil &&
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

		routesRevision: revision,
		revived:        true,
	}, nil
}

func v3ConfigForEnsure(req ensureAttachRequest) (*v3AttachConfig, error) {
	v3 := req.V3
	if v3 == nil {
		return nil, errors.New("v3 attach configuration is required")
	}
	if req.AuthToken == "" {
		return nil, errors.New("a v3 attach requires its access capability at ensure time; the strict session is admitted exactly once")
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
		RoutesRevision: v3.RoutesRevision,
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
	var initialAuthorizationDeadline time.Time
	if v3.Enrollment != nil {
		enrollment := v3.Enrollment
		if req.AuthTokenExpiresAtMs != enrollment.InitialAuthorizationExpiresAtMs ||
			enrollment.InitialAuthorizationExpiresAtMs <= time.Now().UnixMilli() {
			return nil, errors.New("v3 automatic enrollment requires a matching, unexpired initial authorization")
		}
		enrollmentClient, err = mountenrollment.NewClient(mountenrollment.Config{
			ManagerURL: enrollment.ManagerURL, ManagerServerName: enrollment.ManagerServerName,
			ManagerCAPEM: []byte(enrollment.ManagerCAPEM), EnrollmentID: enrollment.EnrollmentID,
			EnrollmentCertificatePEM: []byte(enrollment.EnrollmentCertificatePEM), ClientKeyPEM: []byte(v3.ClientKeyPEM),
			VolumeID: req.VolumeID, AuthorityGeneration: enrollment.AuthorityGeneration,
		})
		if err != nil {
			return nil, fmt.Errorf("invalid v3 automatic mount enrollment: %w", err)
		}
		enrollmentID = enrollment.EnrollmentID
		initialAuthorizationDeadline = time.UnixMilli(enrollment.InitialAuthorizationExpiresAtMs)
	}
	return &v3AttachConfig{
		identity: &identity, routesRevision: revision,
		enrollmentClient: enrollmentClient, enrollmentID: enrollmentID,
		initialAuthorizationDeadline: initialAuthorizationDeadline,
		preKernelMountAbsence:        req.observePreKernelMountAbsence,
	}, nil
}

// v3AuthoritySession is the slice of authorityrpc.Client the attach lifecycle
// itself needs beyond the data plane: an authenticated clean detach for this
// exact session.
type v3AuthoritySession interface {
	DetachAfterUnmount(context.Context, *authoritypb.MountAbsenceProof) error
}

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

func (a *attach) stopV3Serving(cause error) {
	if d := a.v3Backend(); d != nil {
		_ = d.stopServing(cause)
	}
}

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
	var renewalEvents *mountlog.Writer
	if cfg.enrollmentClient != nil {
		var err error
		renewalEvents, err = mountlog.OpenAppend(a.mountLogDir, a.mountPath, "macos-fskit", a.ref)
		if err != nil {
			return fmt.Errorf("initialize per-mount renewal event log: %w", err)
		}
	}
	renewalEventsOwned := renewalEvents != nil
	defer func() {
		if renewalEventsOwned {
			_ = renewalEvents.Close()
		}
	}()
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
	preKernelMountAbsence := cfg.preKernelMountAbsence
	if preKernelMountAbsence == nil {
		preKernelMountAbsence, err = hostPreKernelFSKitMountAbsenceObserver(a.mountPath, a.ref)
		if err != nil {
			return fmt.Errorf("bind pre-kernel FSKit mount-absence observer: %w", err)
		}
	}
	client, err := authorityrpc.DialClient(ctx, authorityrpc.ClientConfig{
		Purpose:                               authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
		FrontendProfile:                       authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE,
		Address:                               a.authorityAddr,
		TLS:                                   tlsCfg,
		VolumeID:                              a.volumeID,
		AccessToken:                           []byte(token),
		ReplaySlots:                           v3AttachReplaySlots,
		MaxFrame:                              v3AttachMaxFrame,
		DialTimeout:                           v3AttachDialTimeout,
		CancelDrainTimeout:                    v3AttachCancelDrainTimeout,
		MaxInFlight:                           v3AttachMaxInFlight,
		RoutesRevision:                        cfg.routesRevision,
		RequireMountEnrollmentReauthorization: cfg.enrollmentClient != nil,
		ObservePreKernelMountAbsence:          preKernelMountAbsence,
	})
	if err != nil {
		return fmt.Errorf("attach v3 authority session: %w", err)
	}
	if cfg.enrollmentClient != nil && !client.InitialAuthorizationDeadline().Equal(cfg.initialAuthorizationDeadline) {
		cause := fmt.Errorf("authority installed authorization deadline %s, Manager response declared %s",
			client.InitialAuthorizationDeadline().UTC().Format(time.RFC3339Nano), cfg.initialAuthorizationDeadline.UTC().Format(time.RFC3339Nano))
		return releaseV3ClientBeforeKernelMount(client, cause)
	}
	// Ownership passes to the data plane only after construction succeeds.
	// Constructor failures retire any local bridge state but leave the ACTIVE
	// client to the exact ReleaseBeforeMount transition below.
	d, err := newV3DataPlane(a.lifetime(), v3DataPlaneConfig{
		Client:         client,
		VolumeID:       a.volumeID,
		VolumeName:     a.volumeName,
		ItemGeneration: a.identityEpoch,
		PrincipalUID:   uint32(os.Getuid()),
		PrincipalGID:   uint32(os.Getgid()),
	})
	if err != nil {
		return releaseV3ClientBeforeKernelMount(client, fmt.Errorf("construct v3 data plane: %w", err))
	}
	a.mu.Lock()
	if a.detached {
		a.mu.Unlock()
		d.abandonBeforeMount(errors.New("portablefsd: attach detached during v3 activation"))
		return releaseV3ClientBeforeKernelMount(client, errors.New("attach is detached"))
	}
	a.v3Data = d
	a.v3Session = client
	a.v3Coherence = d.bridge
	var renewalDone chan struct{}
	if cfg.enrollmentClient != nil {
		a.authorizationDeadlineAtMs = cfg.initialAuthorizationDeadline.UnixMilli()
		renewalDone = make(chan struct{})
		a.renewalDone = renewalDone
	}
	a.mu.Unlock()
	go a.watchV3Terminal(d)
	if cfg.enrollmentClient != nil {
		renewalEventsOwned = false
		go a.runAutomaticMountRenewal(cfg, d, renewalEvents, renewalDone)
	}
	return nil
}

func releaseV3ClientBeforeKernelMount(client *authorityrpc.Client, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), v3AttachCancelDrainTimeout)
	defer cancel()
	return errors.Join(cause, client.ReleaseBeforeMount(ctx))
}

func (a *attach) runAutomaticMountRenewal(cfg *v3AttachConfig, d *v3DataPlane, events *mountlog.Writer, done chan struct{}) {
	defer close(done)
	defer func() {
		if err := events.Close(); err != nil {
			log.Printf("portablefsd: attach %s close renewal event log: %v", a.ref, err)
		}
	}()
	renewer := &mountenrollment.Renewer{
		Source: cfg.enrollmentClient, MinimumSafetyMargin: v3ReauthorizationSafetyMargin,
		Observe: func(event mountenrollment.RenewalEvent) {
			if err := events.WriteRenewal(event, nil); err != nil {
				log.Printf("portablefsd: attach %s write renewal event: %v", a.ref, err)
			}
			status := event.Status
			a.mu.Lock()
			a.authorizationDeadlineAtMs = status.AuthorizationDeadline.UnixMilli()
			a.lastReauthorizationAtMs = 0
			if !status.LastSuccess.IsZero() {
				a.lastReauthorizationAtMs = status.LastSuccess.UnixMilli()
			}
			a.nextReauthorizationAtMs = 0
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

func (a *attach) v3RootReply() (pfslocal.ResolveReply, int32) {
	a.mu.RLock()
	unavailable := a.detached
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

// v3LatePublishingReplyDiscardable identifies replies which cannot represent
// an applied filesystem mutation. FSKit may finish a callback (and acknowledge
// NOT_PUBLISHED) while its authority request is still in flight. A late
// read-only result or definite error can then be retired with that already
// finished callback; it must not turn ordinary cancellation into mount death.
// A successful mutation is deliberately excluded: if it crossed the authority
// boundary after the callback ended, no local publication can make that state
// exact and the attach must remain fail-closed.
func v3LatePublishingReplyDiscardable(body any, errno int32) bool {
	if errno != 0 {
		return true
	}
	switch request := body.(type) {
	case *pfslocal.LookupRequest,
		*pfslocal.EnumerateEntriesRequest,
		*pfslocal.GetAttrRequest,
		*pfslocal.ReadRequest,
		*pfslocal.ReadlinkRequest,
		*pfslocal.XattrGetRequest,
		*pfslocal.XattrListRequest:
		return true
	case *pfslocal.SetAttrRequest:
		// Equal UID/GID assignments are validated locally and the authority call
		// is a GetAttr. Non-equal assignments return a definite errno above.
		return !request.SetFlags && request.Mode == nil && request.Size == nil &&
			request.MtimeMs == nil && request.AtimeMs == nil
	case *pfslocal.WriteRequest:
		// Zero-length Write is implemented as an exact GetAttr and never sends a
		// mutation or changes append/position state.
		return len(request.Data) == 0
	default:
		return false
	}
}

// handleV3Attached serves one frontend request of a v3 attach. It keeps the
// connection's logical-operation ledger — reservation, exposure, and the one
// post-callback PublicationAck — because the coherence bridge's source
// publication lifetime is built on that acknowledgement. The data plane
// owns mutation ordering and concurrency bounds.
func (c *frontendConn) handleV3Attached(
	ctx context.Context,
	a *attach,
	requestID uint64,
	operationID uint64,
	initializeOperation bool,
	body any,
) {
	if operationID != 0 {
		defer c.finishLogicalRequest(operationID)
	}
	ctx, cancelOperation := withOperationDeadline(ctx)
	defer cancelOperation()
	publishes, err := c.beginLogicalOperation(
		ctx, a, operationID, initializeOperation, body,
	)
	if err != nil {
		_ = c.conn.Close()
		return
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
	// A reply served from the metadata cache is revalidated at the physical
	// write boundary. If that refuses it, nothing was exposed: the candidate is
	// settled and the same operation takes the coherent authority path once.
	if c.serveV3Attempt(ctx, a, d, requestID, operationID, publishes, body, false) {
		c.serveV3Attempt(ctx, a, d, requestID, operationID, publishes, body, true)
	}
}

// serveV3Attempt dispatches one request and publishes its outcome. It reports
// retry only when a cached reply's revalidation refused it before any byte was
// written.
func (c *frontendConn) serveV3Attempt(
	ctx context.Context,
	a *attach,
	d *v3DataPlane,
	requestID uint64,
	operationID uint64,
	publishes bool,
	body any,
	bypassCache bool,
) (retry bool) {
	ctx = context.WithValue(ctx, v3CallbackContextKey{}, c.origin)
	var (
		reply any
		eno   int32
	)
	exposed := false
	resources := &v3ReplyResourceCollector{d: d, bypassCache: bypassCache}
	defer resources.retirePending()
	defer func() {
		if exposed {
			traceV3Request(ctx, lantrace.PhaseReply, eno)
		}
	}()
	traceV3Request(ctx, lantrace.PhaseDispatch, 0)
	defer func() {
		if resources.cached != nil {
			trace, _ := ctx.Value(v3RequestTraceContextKey{}).(v3RequestTrace)
			resources.cached.traceFinal(trace, exposed)
		}
		if resources.cached != nil && !resources.cached.accounted {
			reason := v3CacheTerminal
			if exposed {
				reason = v3CacheHit
			}
			d.recordCacheResult(resources.cached.metric, reason)
			resources.cached.accounted = true
		}
		if d != nil && !retry {
			if !exposed {
				eno = darwinENOTCONN
			}
			d.recordLookupPolarity(body, eno)
		}
	}()
	switch body.(type) {
	case *pfslocal.CreateRequest, *pfslocal.MkdirRequest, *pfslocal.SymlinkRequest:
		resources.visible = true
	}
	dispatchCtx := context.WithValue(ctx, v3ReplyResourceContextKey{}, resources)
	dispatchCtx = context.WithValue(dispatchCtx, v3PendingAdmissionContextKey{}, ctx)
	// Once assigned, an authority request must settle on its original session
	// even if the frontend disappears. Preserve the operation's absolute bound;
	// cancellation still governs local admission and never extends this budget.
	deadline, _ := ctx.Deadline()
	dispatchCtx, cancelDispatch := context.WithDeadline(context.WithoutCancel(dispatchCtx), deadline)
	defer cancelDispatch()
	dispatchCtx = context.WithValue(
		dispatchCtx,
		v3ResponseConsumptionRevokerContextKey{},
		v3ResponseConsumptionRevoker(func(cause error) {
			c.revokeV3ResponseConsumption(a, cause)
		}),
	)
	switch {
	case d == nil:
		eno = darwinEIO
	case d.terminalError() != nil:
		eno = darwinENOTCONN
	default:
		reply, eno = d.dispatchFrontend(
			dispatchCtx, operationID, body,
		)
		if eno == darwinEIO && d.terminalError() != nil {
			// The failure that produced this errno killed the session. Report
			// the session verdict, not a per-operation I/O fault: FSKit must
			// stop retrying against a mount that can never answer again.
			eno = darwinENOTCONN
		}
	}
	traceV3Request(ctx, lantrace.PhaseOutcome, eno)
	var commit func() bool
	if resources.cached != nil {
		commit = resources.cached.revalidate
	}
	trace, _ := ctx.Value(v3RequestTraceContextKey{}).(v3RequestTrace)
	if trace.recorder != nil {
		validate := commit
		commit = func() bool {
			admitted := validate == nil || validate()
			e := lantrace.Event{Kind: lantrace.KindLocal, Phase: lantrace.PhaseExposure, LocalOp: trace.localOp}
			if !admitted {
				e.Outcome = lantrace.OutcomeCancelled
			}
			trace.emit(e)
			return admitted
		}
	}
	if eno != 0 {
		if d != nil && (len(resources.items) != 0 || len(resources.handles) != 0) {
			cleanup, prepareErr := d.abandonCollectedReplyResources(resources)
			if prepareErr != nil {
				_ = d.fail(prepareErr)
			}
			// finish always runs, even after a terminal verdict: it settles the
			// abandoned reply's pending reservation.
			if cleanup.required() {
				go func() {
					_ = cleanup.finish()
				}()
			}
			// Incomplete publication of a successful visible resource reply is
			// detected by the synchronous disposition above. Re-read the terminal
			// state after that transition so this callback reports the session
			// verdict rather than its earlier per-operation errno.
			if d.terminalError() != nil {
				eno = darwinENOTCONN
			}
		}
		if d != nil {
			if terminal := d.terminalError(); terminal != nil {
				// A retained visible result which could not be represented is not an
				// ordinary ENOTCONN reply. Revoke the pfslocal serving boundary before
				// the handler can expose any substitute frame; connection teardown
				// will retire the response under the already-recorded terminal cause.
				c.stopV3FrontendPublication(a, terminal)
				consumeV3ResponseConsumptions(resources.responseConsumptions)
				resources.responseConsumptions = nil
				return false
			}
		}
		failure := &pfslocal.ErrorReply{Errno: eno, Message: errMessage(fmt.Sprintf("%T", body), eno)}
		if !publishes {
			_, written := c.replyWithPublicationWriteStatus(requestID, operationID, failure, false)
			exposed = written
			if written {
				consumeV3ResponseConsumptions(resources.responseConsumptions)
				resources.responseConsumptions = nil
			} else if len(resources.responseConsumptions) != 0 {
				c.stopV3FrontendPublication(a, errors.New("portablefsd: retained authority error reply was not delivered"))
				consumeV3ResponseConsumptions(resources.responseConsumptions)
				resources.responseConsumptions = nil
			}
			return false
		}
		// A cached negative answer is revalidated at the write boundary like
		// any other cached reply.
		_, written, _, refused := c.replyWithPublicationCommit(
			requestID, operationID, failure, true,
			v3LatePublishingReplyDiscardable(body, eno), commit,
		)
		if refused {
			consumeV3ResponseConsumptions(resources.responseConsumptions)
			resources.responseConsumptions = nil
			retry = c.expiredV3CacheCandidate(a, resources)
			if !retry {
				eno = darwinENOTCONN
			}
			return retry
		}
		exposed = written
		return false
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
					_ = cleanup.finish()
				}()
			} else {
				prepareErr = errors.Join(prepareErr, cleanupErr)
			}
		}
		resourceErr = errors.Join(resourceErr, prepareErr)
		c.stopV3FrontendPublication(a, resourceErr)
		consumeV3ProvisionalResponses(provisional)
		consumeV3ResponseConsumptions(resources.responseConsumptions)
		resources.responseConsumptions = nil
		return false
	}
	if resourceReply {
		provisional, err := d.prepareReplyResources(resources)
		if err != nil {
			if provisional != nil {
				if cleanup, cleanupErr := d.applyReplyResourceDisposition(
					provisional, false, 0,
				); cleanupErr == nil {
					go func() {
						_ = cleanup.finish()
					}()
				} else {
					err = errors.Join(err, cleanupErr)
				}
			}
			c.stopV3FrontendPublication(a, err)
			consumeV3ProvisionalResponses(provisional)
			consumeV3ResponseConsumptions(resources.responseConsumptions)
			resources.responseConsumptions = nil
			return false
		}
		cleanup, registered, err := c.registerProvisionalResourceOrAbandon(requestID, provisional)
		if !registered {
			if err != nil {
				c.stopV3FrontendPublication(a, err)
			} else if cleanup.required() {
				go func() {
					_ = cleanup.finish()
				}()
			}
			if err == nil {
				c.stopV3FrontendPublication(a, errors.New("portablefsd: retained resource reply lost its disposition table"))
			}
			consumeV3ProvisionalResponses(provisional)
			consumeV3ResponseConsumptions(resources.responseConsumptions)
			resources.responseConsumptions = nil
			return false
		}
	}
	_, written, discarded, refused := c.replyWithPublicationCommit(
		requestID, operationID, reply, publishes,
		v3LatePublishingReplyDiscardable(body, 0), commit,
	)
	if refused {
		// The cached reply never reached the frontend, so no disposition can
		// name it: settle its provisional ownership exactly once and retry
		// coherently.
		if resourceReply && !c.settleProvisionalResource(&pfslocal.ResourceReplyDisposition{TargetRequestID: requestID}) {
			c.stopV3FrontendPublication(a, errors.New("portablefsd: refused cached reply lost its provisional ownership"))
			return false
		}
		consumeV3ResponseConsumptions(resources.responseConsumptions)
		resources.responseConsumptions = nil
		retry = c.expiredV3CacheCandidate(a, resources)
		if !retry {
			eno = darwinENOTCONN
		}
		return retry
	}
	exposed = written
	if discarded && resourceReply {
		// The callback already proved NOT_PUBLISHED, so no frontend can send a
		// ResourceReplyDisposition for this unexposed frame. Withdraw the exact
		// provisional capabilities without treating a read-only Lookup result as
		// a failed visible mutation.
		if !c.settleProvisionalResource(&pfslocal.ResourceReplyDisposition{
			TargetRequestID: requestID,
		}) {
			c.stopV3FrontendPublication(a, errors.New(
				"portablefsd: discarded late resource reply lost its provisional ownership",
			))
		}
	}
	if !resourceReply {
		if written {
			consumeV3ResponseConsumptions(resources.responseConsumptions)
			resources.responseConsumptions = nil
		} else if len(resources.responseConsumptions) != 0 {
			c.stopV3FrontendPublication(a, errors.New("portablefsd: retained authority reply was not delivered"))
			consumeV3ResponseConsumptions(resources.responseConsumptions)
			resources.responseConsumptions = nil
		}
	}
	return false
}

func (c *frontendConn) expiredV3CacheCandidate(a *attach, resources *v3ReplyResourceCollector) bool {
	if resources.cached != nil && resources.cached.expired {
		return true
	}
	c.stopV3FrontendPublication(a, errors.New("portablefsd: cached reply lost eligibility or ownership before exposure"))
	return false
}

func (c *frontendConn) revokeV3ResponseConsumption(a *attach, cause error) {
	// Serialize against every pfslocal reply write: a retained authority
	// response may still be in another handler, and fail-closed means its frame
	// must either already be physically out or become unwritable before the
	// authority's bounded force callback returns. Record the exact
	// delivery-bound cause before closing the socket, so connection teardown
	// cannot race in and replace it with context.Canceled.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if a != nil {
		a.fenceV3(cause)
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// stopV3FrontendPublication revokes reply delivery without discarding the
// authority transport needed for the supervisor's exact kernel-absence proof.
func (c *frontendConn) stopV3FrontendPublication(a *attach, cause error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if a != nil {
		a.stopV3Serving(cause)
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// detachV3 is the evidence-bearing unmount of one v3 attach. The caller owns
// registry.mutationMu (it runs inside runUnmountTransaction) and the shared
// registry-removal tail runs once local teardown completes, preserving any
// final proof-delivery or release diagnostic returned here.
//
// Order is the contract: exact kernel detach first, then the getfsstat
// absence observation, then delivery of that proof to the authority, and only
// then the local release. A proof that cannot be produced or delivered ends
// the attach FENCED — the session is closed so the authority's lease sweep
// fences this participant — never silently absent.
func (r *registry) detachV3(a *attach, force bool, ops fskitKernelOps) error {
	if a.isDetached() {
		// An earlier detach completed the teardown and returned its outcome,
		// including any release failure; only durable registry removal remains,
		// so its release transfer and proof are not repeated.
		a.frontendSerial.Lock()
		a.nsMu.Lock()
		return a.finishDetachWithNSLocked(nil)
	}
	present, err := ops.present(a.mountPath, a.ref)
	if err != nil {
		// Nothing irreversible has happened: the mount may still be serving,
		// so this refusal leaves the attach fully alive and retryable.
		return fmt.Errorf("classify v3 FSKit detach: %w", err)
	}
	if present {
		bridge := a.v3CoherenceBridge()
		if bridge == nil && (a.v3Config == nil || !a.v3Config.revived) {
			return errors.New("FSKit detach has no session owner")
		}
		if bridge != nil {
			if err := bridge.beginDetach(); err != nil {
				return fmt.Errorf("begin FSKit detach: %w", err)
			}
		}
		detachErr := ops.unmountExact(a.mountPath, a.ref, force)
		if detachErr != nil {
			if bridge != nil {
				bridge.abortDetach(detachErr)
			}
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
	var releaseErr, proofErr error
	if session != nil && d != nil {
		releaseErr = d.transferReleases()
		proofCtx, cancel := context.WithTimeout(context.Background(), v3DetachProofBudget)
		// Call refuses poisoned/closed admission. Never create a new session to
		// deliver evidence about the original incarnation.
		if !d.client.LocalAdmissionOpen() {
			proofErr = errors.New("authority session is closed or poisoned")
		} else {
			proofErr = session.DetachAfterUnmount(proofCtx, proof)
		}
		cancel()
		if proofErr != nil {
			proofErr = fmt.Errorf("deliver v3 mount-absence proof: %w", proofErr)
			a.fenceV3(proofErr)
			log.Printf("portablefsd: attach %s: exact kernel absence was not accepted: %v; session ends fenced", a.ref, proofErr)
		}
	}
	if releaseErr != nil {
		releaseErr = fmt.Errorf("v3 authority release cleanup: %w", releaseErr)
	}
	// Terminal either way: an already-fenced plane keeps its original cause.
	a.fenceV3(errV3AttachDetached)
	a.frontendSerial.Lock()
	a.nsMu.Lock()
	return a.finishDetachWithNSLocked(errors.Join(proofErr, releaseErr))
}
