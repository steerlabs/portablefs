// Package mountenrollment owns the Manager-facing half of automatic mount
// authorization. It deliberately contains no filesystem logic: one mount
// owner asks for an exact sequence, then installs the returned short-lived
// grant into its already-running authority session.
package mountenrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

const maxResponseBytes = 2 << 20

var ErrDefinitiveDenial = errors.New("mount enrollment was definitively denied")

type Config struct {
	ManagerURL               string
	ManagerServerName        string
	ManagerCAPEM             []byte
	EnrollmentID             string
	EnrollmentCertificatePEM []byte
	ClientKeyPEM             []byte
	VolumeID                 string
	AuthorityGeneration      uint64
	EnrollmentExpires        time.Time
	Timeout                  time.Duration
}

type Client struct {
	baseURL             *url.URL
	http                *http.Client
	enrollmentID        string
	volumeID            string
	authorityGeneration uint64
	enrollmentExpires   time.Time
	csrPEM              string
	keySPKI             []byte
}

func NewClient(cfg Config) (*Client, error) {
	baseURL, err := url.Parse(cfg.ManagerURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil || baseURL.Opaque != "" ||
		baseURL.RawQuery != "" || baseURL.ForceQuery || baseURL.Fragment != "" || baseURL.RawPath != "" ||
		baseURL.Path != "" && baseURL.Path != "/" {
		return nil, errors.New("mount enrollment requires an origin-only HTTPS Manager URL")
	}
	if cfg.ManagerServerName == "" || cfg.EnrollmentID == "" || cfg.VolumeID == "" || cfg.AuthorityGeneration == 0 ||
		len(cfg.ManagerCAPEM) == 0 || len(cfg.EnrollmentCertificatePEM) == 0 || len(cfg.ClientKeyPEM) == 0 ||
		cfg.EnrollmentExpires.IsZero() {
		return nil, errors.New("complete mount enrollment configuration is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.ManagerCAPEM) {
		return nil, errors.New("Manager CA bundle contains no certificates")
	}
	identity, err := tls.X509KeyPair(cfg.EnrollmentCertificatePEM, cfg.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("mount enrollment identity: %w", err)
	}
	signer, ok := identity.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("mount enrollment private key is not a signer")
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	clientAuth := false
	if err == nil {
		for _, usage := range leaf.ExtKeyUsage {
			clientAuth = clientAuth || usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny
		}
	}
	if err != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://portablefs/mount-enrollment/"+cfg.EnrollmentID ||
		!leaf.NotAfter.Equal(cfg.EnrollmentExpires) || time.Now().Before(leaf.NotBefore) || !cfg.EnrollmentExpires.After(time.Now()) || !clientAuth {
		return nil, errors.New("mount enrollment certificate does not match its declared identity or lifetime")
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cfg.EnrollmentID}}, signer)
	if err != nil {
		return nil, fmt.Errorf("create mount refresh CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if len(csrPEM) == 0 {
		return nil, errors.New("encode mount refresh CSR")
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: cfg.ManagerServerName,
		Certificates: []tls.Certificate{identity}, NextProtos: []string{"h2", "http/1.1"},
	}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: cfg.Timeout,
		IdleConnTimeout: 90 * time.Second, MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
	}
	httpClient := &http.Client{
		Transport: transport, Timeout: cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Client{
		baseURL: baseURL, http: httpClient, enrollmentID: cfg.EnrollmentID, volumeID: cfg.VolumeID,
		authorityGeneration: cfg.AuthorityGeneration, enrollmentExpires: cfg.EnrollmentExpires.UTC(),
		csrPEM: string(csrPEM), keySPKI: spki,
	}, nil
}

func (client *Client) EnrollmentExpires() time.Time { return client.enrollmentExpires }

func (client *Client) Refresh(ctx context.Context, sessionID string, sequence uint64) (controlplane.MountAuthorization, error) {
	if client == nil || sessionID == "" || sequence == 0 {
		return controlplane.MountAuthorization{}, errors.New("complete mount refresh identity is required")
	}
	request := controlplane.RefreshMountEnrollmentRequest{ClientCSRPEM: client.csrPEM, SessionID: sessionID, Sequence: sequence}
	var authorization controlplane.MountAuthorization
	if err := client.do(ctx, http.MethodPost, "reauthorizations", refreshRequestID(client.enrollmentID, sessionID, sequence), request, &authorization); err != nil {
		return controlplane.MountAuthorization{}, err
	}
	if authorization.VolumeID != client.volumeID || authorization.SessionID != sessionID || authorization.Sequence != sequence ||
		authorization.AuthorityGeneration != client.authorityGeneration || authorization.Capability == "" ||
		authorization.ClientCertificatePEM == "" || authorization.ExpiresUnix <= time.Now().Unix() ||
		authorization.CertificateExpiresUnix <= time.Now().Unix() || len(authorization.Access) == 0 {
		return controlplane.MountAuthorization{}, errors.New("Manager returned a mismatched or expired mount authorization")
	}
	if err := client.verifyReplacementCertificate(authorization.ClientCertificatePEM); err != nil {
		return controlplane.MountAuthorization{}, err
	}
	return authorization, nil
}

func (client *Client) Close(ctx context.Context, reason string) error {
	if client == nil || strings.TrimSpace(reason) != reason || reason == "" {
		return errors.New("mount enrollment close reason is required")
	}
	requestID := digestID("mount-close", client.enrollmentID, reason)
	backoff := 250 * time.Millisecond
	for {
		var response controlplane.MountEnrollment
		err := client.do(ctx, http.MethodPost, "close", requestID, controlplane.TerminateMountEnrollmentRequest{Reason: reason}, &response)
		if err == nil && (response.ID != client.enrollmentID || response.State != controlplane.MountEnrollmentClosed && response.State != controlplane.MountEnrollmentRevoked) {
			err = fmt.Errorf("%w: Manager returned a mismatched mount enrollment close result", ErrDefinitiveDenial)
		}
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrDefinitiveDenial) {
			return err
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("close mount enrollment: %w", ctx.Err())
		case <-timer.C:
		}
		if backoff < 2*time.Second {
			backoff *= 2
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
		}
	}
}

func (client *Client) do(ctx context.Context, method, operation, requestID string, body, response any) error {
	requestBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint := *client.baseURL
	endpoint.Path = path.Join("/v1/mount-enrollments", url.PathEscape(client.enrollmentID), operation)
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(requestBody))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", requestID)
	reply, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("call Manager mount enrollment: %w", err)
	}
	defer reply.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(reply.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return errors.New("Manager mount enrollment response exceeded its bound")
	}
	if reply.StatusCode < 200 || reply.StatusCode >= 300 {
		if reply.StatusCode == http.StatusBadRequest || reply.StatusCode == http.StatusUnauthorized ||
			reply.StatusCode == http.StatusForbidden || reply.StatusCode == http.StatusNotFound || reply.StatusCode == http.StatusGone {
			return fmt.Errorf("%w with HTTP %d", ErrDefinitiveDenial, reply.StatusCode)
		}
		return fmt.Errorf("Manager mount enrollment refused with HTTP %d", reply.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(response); err != nil {
		return fmt.Errorf("decode Manager mount enrollment response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("Manager mount enrollment response has trailing JSON")
	}
	return nil
}

func (client *Client) verifyReplacementCertificate(certificatePEM string) error {
	block, rest := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("Manager returned an invalid replacement certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("Manager returned an invalid replacement certificate")
	}
	for len(bytes.TrimSpace(rest)) != 0 {
		var next *pem.Block
		next, rest = pem.Decode(rest)
		if next == nil || next.Type != "CERTIFICATE" {
			return errors.New("Manager returned an invalid replacement certificate chain")
		}
	}
	got, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(got, client.keySPKI) {
		return errors.New("Manager replacement certificate changed the mount key")
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		clientAuth = clientAuth || usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny
	}
	if !clientAuth {
		return errors.New("Manager replacement certificate cannot authenticate a mount")
	}
	return nil
}

func refreshRequestID(enrollmentID, sessionID string, sequence uint64) string {
	return digestID("mount-refresh", enrollmentID, sessionID, fmt.Sprint(sequence))
}

func digestID(prefix string, values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(hash, value)
		_, _ = hash.Write([]byte{0})
	}
	return prefix + "-" + hex.EncodeToString(hash.Sum(nil))
}
