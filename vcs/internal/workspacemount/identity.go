// Package workspacemount owns data-disk identities, independently of volatile
// boot, mount, session and replay identities. No private key crosses control 8.
package workspacemount

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

var ErrIdentityUnavailable = errors.New("invalid or unavailable persistent guest identity")

const format = 8
const maxEpoch = 1<<53 - 1 // Existing Manager/product authorization contract.

type record struct {
	Format      int                `json:"format"`
	Authority   []byte             `json:"authority"`
	Volume      string             `json:"volume"`
	Incarnation []byte             `json:"incarnation"`
	Key         ed25519.PrivateKey `json:"key"`
	Epoch       uint64             `json:"epoch"`
	Provision   []byte             `json:"provision,omitempty"`
}
type guestRecord struct {
	Format int    `json:"format"`
	UUID   []byte `json:"uuid"`
}
type Store struct {
	mu        sync.Mutex
	directory string
	lock      *os.File
	guest     []byte
	mounts    map[string]*pb.MountID
	failed    error
}

// Open takes exclusive lifetime ownership. The directory is private, on the
// persistent data disk; a competing supervisor cannot rotate identity state.
func Open(directory string) (*Store, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}
	st, err := os.Lstat(directory)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, errors.New("workspace identity directory must be private")
	}
	fd, err := unix.Open(filepath.Join(directory, "owner.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open identity ownership: %w", err)
	}
	lock := os.NewFile(uintptr(fd), "identity owner")
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("identity already owned: %w", err)
	}
	s := &Store{directory: directory, lock: lock, mounts: map[string]*pb.MountID{}}
	// A crash can leave private-key bytes in an uncommitted transaction. Sweep
	// only after taking lifetime ownership; never race a live writer.
	entries, err := os.ReadDir(directory)
	if err != nil {
		lock.Close()
		return nil, ErrIdentityUnavailable
	}
	retained := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".identity-") {
			if err = os.Remove(filepath.Join(directory, entry.Name())); err != nil {
				lock.Close()
				return nil, ErrIdentityUnavailable
			}
		} else if entry.Name() != "owner.lock" && entry.Name() != "guest.json" {
			retained = true
		}
	}
	dir, err := os.Open(directory)
	if err == nil {
		err = dir.Sync()
		dir.Close()
	}
	if err != nil {
		lock.Close()
		return nil, ErrIdentityUnavailable
	}
	var g guestRecord
	if err = s.read("guest.json", &g); errors.Is(err, os.ErrNotExist) {
		// Retained volume keys/epochs must never escape their original scope.
		// Refusal survives restart because no replacement UUID is written.
		if retained {
			lock.Close()
			return nil, ErrIdentityUnavailable
		}
		g = guestRecord{format, nonce()}
		err = s.commit("guest.json", g)
	}
	if err != nil || g.Format != format || !control.ID(g.UUID) {
		lock.Close()
		return nil, ErrIdentityUnavailable
	}
	s.guest = bytes.Clone(g.UUID)
	return s, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = errors.New("identity store closed")
	return s.lock.Close()
}
func nonce() []byte {
	v := make([]byte, 16)
	if _, err := rand.Read(v); err != nil {
		panic(err)
	}
	v[6] = (v[6] & 0x0f) | 0x40
	v[8] = (v[8] & 0x3f) | 0x80
	return v
}
func volumeKey(authority []byte, volume string) string {
	sum := sha256.Sum256(append(append(bytes.Clone(authority), 0), []byte(volume)...))
	return hex.EncodeToString(sum[:])
}
func (s *Store) read(name string, v any) error {
	fd, err := unix.Open(filepath.Join(s.directory, name), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "identity state")
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1<<20 {
		return errors.New("invalid identity state mode or size")
	}
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(v); err != nil {
		return errors.New("invalid identity state")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing identity state")
	}
	return nil
}
func (s *Store) commit(name string, v any) (result error) {
	defer func() {
		if result != nil {
			s.failed = result
		}
	}()
	raw, err := json.Marshal(v)
	if err != nil {
		return errors.New("encode identity state")
	}
	f, err := os.CreateTemp(s.directory, ".identity-")
	if err != nil {
		return fmt.Errorf("create identity transaction: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Close()
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(s.directory, name))
	}
	if err == nil {
		var d *os.File
		d, err = os.Open(s.directory)
		if err == nil {
			err = d.Sync()
			d.Close()
		}
	}
	if err != nil {
		s.failed = fmt.Errorf("persist identity transaction: %w", err)
		return s.failed
	}
	return nil
}
func (s *Store) load(r *pb.IdentityRequest) (*record, string, error) {
	if s.failed != nil {
		return nil, "", s.failed
	}
	if err := control.IdentityRequest(r); err != nil {
		return nil, "", err
	}
	key := volumeKey(r.AuthorityId, r.VolumeId)
	var v record
	err := s.read(key+".json", &v)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, "", fmt.Errorf("generate guest identity: %w", e)
		}
		v = record{Format: format, Authority: bytes.Clone(r.AuthorityId), Volume: r.VolumeId, Incarnation: nonce(), Key: priv, Epoch: 1}
		err = s.commit(key+".json", v)
	}
	if err != nil {
		return nil, "", fmt.Errorf("load volume identity: %w", err)
	}
	if v.Format != format || !bytes.Equal(v.Authority, r.AuthorityId) || v.Volume != r.VolumeId || !control.ID(v.Incarnation) || len(v.Key) != ed25519.PrivateKeySize || v.Epoch == 0 || v.Epoch > maxEpoch || !bytes.Equal(ed25519.NewKeyFromSeed(v.Key[:ed25519.SeedSize]), v.Key) {
		return nil, "", errors.New("invalid persistent volume identity")
	}
	return &v, key, nil
}

// EnsureIdentity preserves the key/scope/epoch; each service lifetime chooses a
// new mount nonce. Repeated requests in that lifetime return the same MountID.
func (s *Store) EnsureIdentity(r *pb.IdentityRequest) (*pb.IdentityReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, key, err := s.load(r)
	if err != nil {
		return nil, err
	}
	m := s.mounts[key]
	if m == nil {
		m = &pb.MountID{AuthorityId: bytes.Clone(v.Authority), VolumeId: v.Volume, Incarnation: nonce()}
		s.mounts[key] = m
	}
	spki, err := x509.MarshalPKIXPublicKey(v.Key.Public())
	if err != nil {
		return nil, err
	}
	csr, err := CSR(v.Key)
	if err != nil {
		return nil, err
	}
	return &pb.IdentityReply{Mount: proto.Clone(m).(*pb.MountID), PublicKey: spki, Csr: csr, GuestUuid: bytes.Clone(s.guest), IdentityIncarnation: bytes.Clone(v.Incarnation), RenewalEpoch: v.Epoch}, nil
}
func CSR(key ed25519.PrivateKey) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "portablefs-linux-workspace"}}, key)
}
func RenewalScope(r *pb.IdentityReply) string {
	return "portablefs-linux-workspace/8/" + uuid(r.GuestUuid) + "/" + uuid(r.IdentityIncarnation)
}
func uuid(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) != 32 {
		return ""
	}
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// IssueRequest uses the existing Manager v1 contract. Product authorization is
// issued by the caller with this guest's RenewalScope and durable RenewalEpoch.
func IssueRequest(r *pb.IdentityReply, authorization string, access []string) (controlplane.IssueMountRequest, error) {
	if control.IdentityReply(r) != nil || authorization == "" {
		return controlplane.IssueMountRequest{}, errors.New("complete guest issuance identity required")
	}
	return controlplane.IssueMountRequest{VolumeID: r.Mount.VolumeId, ProductAuthorization: authorization, ClientCSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: r.Csr})), Access: append([]string(nil), access...), AutomaticReauthorization: true}, nil
}
func endpoint(value string) error {
	host, port, err := net.SplitHostPort(value)
	p, e := strconv.Atoi(port)
	if err != nil || e != nil || p < 1 || p > math.MaxUint16 || host == "" || strings.ContainsAny(host, " /\t\r\n\x00") {
		return errors.New("invalid authority endpoint")
	}
	return nil
}
func certificates(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(bytes.TrimSpace(raw)) != 0 {
		b, rest := pem.Decode(raw)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return nil, errors.New("invalid certificate material")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, errors.New("invalid certificate material")
		}
		out = append(out, c)
		raw = rest
	}
	if len(out) == 0 {
		return nil, errors.New("missing certificate material")
	}
	return out, nil
}

type certificatePending struct{ until time.Time }

func (e *certificatePending) Error() string { return "provision certificate is not yet valid" }

// The peer owns client-chain verification. These roots authenticate servers,
// and need not issue either of the guest's client identities.
func verifyServerCA(raw []byte) error {
	roots, err := certificates(raw)
	if err != nil {
		return err
	}
	for _, c := range roots {
		if !c.IsCA || !c.BasicConstraintsValid {
			return errors.New("invalid CA certificate")
		}
	}
	return nil
}
func verifyClientIdentity(raw, spki []byte, now time.Time) (*x509.Certificate, error) {
	chain, err := certificates(raw)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, spki) {
		return nil, errors.New("provision certificate changed the guest key")
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		clientAuth = clientAuth || usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny
	}
	if !clientAuth || !now.Before(leaf.NotAfter) || !leaf.NotAfter.After(leaf.NotBefore) {
		return nil, errors.New("provision certificate is not currently valid for client authentication")
	}
	if now.Before(leaf.NotBefore) {
		return nil, &certificatePending{leaf.NotBefore}
	}
	return leaf, nil
}

// AcceptProvision validates before a single durable commit. Errors never include
// request/certificate/capability bytes. A different grant requires exact prior
// cleanup through Reissue; ordinary boot does not forget that obligation.
func (s *Store) AcceptProvision(ctx context.Context, p *pb.Provision, waitClock func(context.Context) error) error {
	if waitClock == nil {
		return errors.New("provision requires the shared clock")
	}
	for {
		if err := waitClock(ctx); err != nil {
			return err
		}
		err := s.acceptProvision(ctx, p)
		var pending *certificatePending
		if !errors.As(err, &pending) {
			return err
		}
		timer := time.NewTimer(min(time.Second, max(time.Millisecond, time.Until(pending.until))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func (s *Store) acceptProvision(ctx context.Context, p *pb.Provision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := control.Provision(p); err != nil {
		return err
	}
	key := volumeKey(p.Mount.AuthorityId, p.Mount.VolumeId)
	if !proto.Equal(s.mounts[key], p.Mount) {
		return errors.New("provision does not name the guest-selected mount")
	}
	v, key, err := s.load(&pb.IdentityRequest{AuthorityId: p.Mount.AuthorityId, VolumeId: p.Mount.VolumeId})
	if err != nil {
		return err
	}
	if !proto.Equal(s.mounts[key], p.Mount) {
		return errors.New("provision does not name the guest-selected mount")
	}
	spki, _ := x509.MarshalPKIXPublicKey(v.Key.Public())
	if err = control.ProvisionForKey(p, spki); err != nil {
		return err
	}
	if err = endpoint(p.AuthorityEndpoint); err != nil {
		return err
	}
	if strings.TrimSpace(p.ServerName) != p.ServerName || strings.ContainsAny(p.ServerName, "/\x00\r\n") {
		return errors.New("invalid authority server name")
	}
	now := time.Now()
	if err = verifyServerCA(p.CaCertificate); err != nil {
		return err
	}
	if _, err = verifyClientIdentity(p.ClientCertificate, spki, now); err != nil {
		return err
	}
	if h := p.HostedEnrollment; h != nil {
		u, e := url.Parse(h.ManagerOrigin)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" {
			return errors.New("Manager must be an HTTPS origin")
		}
		if e := verifyServerCA(h.ManagerCa); e != nil {
			return e
		}
		c, e := verifyClientIdentity(h.EnrollmentCertificate, spki, now)
		if e != nil {
			return e
		}
		if len(c.URIs) != 1 || c.URIs[0].String() != "spiffe://portablefs/mount-enrollment/"+h.EnrollmentId || !time.Unix(int64(h.AuthorizationDeadlineUnix), 0).After(now) {
			return errors.New("mismatched or expired enrollment")
		}
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(p)
	if err != nil {
		return errors.New("encode provision")
	}
	if len(v.Provision) > 0 && !bytes.Equal(v.Provision, raw) {
		return errors.New("exact cleanup required before reissuance")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	v.Provision = raw
	return s.commit(key+".json", v)
}

// Reissue is called only after the root driver's exact process/kernel cleanup
// join. Keeping that proof as a required operation avoids a caller-supplied bit.
// Revocation commits the larger epoch before any new issuance can be requested.
func (s *Store) Reissue(r *pb.IdentityRequest, revoke bool, cleanup func() error) error {
	if cleanup == nil {
		return errors.New("reissuance requires exact cleanup")
	}
	if err := cleanup(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, key, err := s.load(r)
	if err != nil {
		return err
	}
	if revoke {
		if v.Epoch == maxEpoch {
			return errors.New("renewal epoch exhausted")
		}
		v.Epoch++
	}
	v.Provision = nil
	if err = s.commit(key+".json", v); err != nil {
		return err
	}
	delete(s.mounts, key)
	return nil
}

// TLSIdentity is an in-process handoff to the future root driver. Keys never
// appear in IdentityReply/Provision, logs or the Mac control stream.
func (s *Store) TLSIdentity(r *pb.IdentityRequest) (tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, _, err := s.load(r)
	if err != nil {
		return tls.Certificate{}, err
	}
	p := new(pb.Provision)
	if err = proto.Unmarshal(v.Provision, p); err != nil || len(v.Provision) == 0 {
		return tls.Certificate{}, errors.New("identity is not provisioned")
	}
	chain, err := certificates(p.ClientCertificate)
	if err != nil {
		return tls.Certificate{}, err
	}
	out := tls.Certificate{PrivateKey: v.Key, Leaf: chain[0]}
	for _, c := range chain {
		out.Certificate = append(out.Certificate, c.Raw)
	}
	return out, nil
}

// Provisioned returns an in-process launch handoff for the exact selected
// incarnation. The key is delivered only through the child's inherited pipe.
func (s *Store) Provisioned(id *pb.MountID) (*pb.Provision, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, key, err := s.load(&pb.IdentityRequest{AuthorityId: id.AuthorityId, VolumeId: id.VolumeId})
	if err != nil {
		return nil, nil, err
	}
	if !proto.Equal(s.mounts[key], id) {
		return nil, nil, errors.New("workspace identity incarnation not selected")
	}
	p := new(pb.Provision)
	if len(v.Provision) == 0 || proto.Unmarshal(v.Provision, p) != nil || !proto.Equal(p.Mount, id) {
		return nil, nil, errors.New("workspace incarnation requires fresh provisioning")
	}
	der, err := x509.MarshalPKCS8PrivateKey(v.Key)
	if err != nil {
		return nil, nil, err
	}
	return p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
