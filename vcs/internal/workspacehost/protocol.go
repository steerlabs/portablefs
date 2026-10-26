// Package workspacehost is the paired operational-v1 boundary between the
// signed Mac CLI/app and the per-account workspace VM service. It never carries
// private keys or authority/product signing credentials.
package workspacehost

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

const Version = 1
const MaxFrame = 4 << 20
const MaxDocument = 512 << 10
const SocketName = "control.sock"
const Starting = "Starting Linux Workspace…"
const Running = "Linux Workspace: Running"
const Approval = "Allow PortableFS in Background Items"
const AuthorizationRequired = "Authorization required"
const Busy = "Volume is in use. Close its terminals and editor windows, then try again."

type Request struct {
	Version   int       `json:"version"`
	Operation string    `json:"operation"`
	Document  *Document `json:"document,omitempty"`
	VolumeID  string    `json:"volumeId,omitempty"`
	Force     bool      `json:"force,omitempty"`
}
type Volume struct {
	VolumeID string `json:"volumeId"`
	Path     string `json:"path"`
	State    string `json:"state"`
	Message  string `json:"message"`
	// Typed protocol-8 evidence; retained outcomes survive replacement and Stop.
	Evidence             []byte `json:"evidence,omitempty"`
	AuthorizationRequest string `json:"authorizationRequest,omitempty"`
}
type Reply struct {
	RetainedEvidence            [][]byte `json:"retainedEvidence"`
	SomeChangesWereNotSaved     bool     `json:"someChangesWereNotSaved"`
	PreviousWriteOutcomeUnknown bool     `json:"previousWriteOutcomeUnknown"`
	Version                     int      `json:"version"`
	State                       string   `json:"state"`
	Message                     string   `json:"message"`
	DesiredRunning              bool     `json:"desiredRunning"`
	Volumes                     []Volume `json:"volumes"`
}

func DecodeRequest(raw []byte) (Request, error) {
	r, err := hostctl.DecodeBounded[Request](raw, MaxFrame)
	if err != nil {
		return r, err
	}
	return r, r.Validate()
}
func (r Request) Validate() error {
	if r.Version != Version {
		return errors.New("workspace host operational version mismatch")
	}
	switch r.Operation {
	case "start", "status":
		if r.Document != nil || r.VolumeID != "" || r.Force {
			return errors.New("unexpected workspace request field")
		}
	case "stop":
		if r.Document != nil || r.VolumeID != "" {
			return errors.New("unexpected workspace stop field")
		}
	case "mount":
		if r.Document == nil || r.VolumeID != "" || r.Force {
			return errors.New("mount requires a connection document")
		}
		return r.Document.Validate()
	case "umount":
		if r.Document != nil || !mountlifecycle.ValidVolume(r.VolumeID) {
			return errors.New("umount requires a canonical volume ID")
		}
	default:
		return errors.New("unknown workspace operation")
	}
	return nil
}
func DecodeReply(raw []byte) (Reply, error) {
	r, err := hostctl.DecodeBounded[Reply](raw, MaxFrame)
	if err != nil {
		return r, err
	}
	if r.Version != Version || r.Volumes == nil || len(r.Volumes) > 64 || len(r.Message) > 1024 {
		return r, errors.New("invalid workspace reply")
	}
	switch r.State {
	case "stopped", "starting", "running", "reconnecting", "pending", "authorization-required", "ready", "busy", "terminal", "cleanup-required", "refused":
	default:
		return r, errors.New("invalid workspace state")
	}
	if len(r.RetainedEvidence) > 128 {
		return r, errors.New("invalid retained workspace inventory")
	}
	for _, raw := range r.RetainedEvidence {
		frame, err := workspacecontrol.Decode(raw)
		if err != nil || frame.GetStatusReply() == nil {
			return r, errors.New("invalid retained workspace evidence")
		}
	}
	for _, v := range r.Volumes {
		if !mountlifecycle.ValidVolume(v.VolumeID) || v.Path != "/workspaces/"+v.VolumeID || len(v.Evidence) > workspacecontrol.MaxFrame {
			return r, errors.New("invalid workspace volume")
		}
	}
	return r, nil
}

// Document is one exact public handoff. Identity and Authorization are canonical
// protocol-8 envelopes (fixed correlation ID 1), not a second Provision codec.
// A response must echo the complete saved request and its unique mount intent.
type Document struct {
	RenewalScope  string     `json:"renewalScope,omitempty"`
	RenewalEpoch  string     `json:"renewalEpoch,omitempty"`
	Version       int        `json:"version"`
	Kind          string     `json:"kind"`
	Connection    Connection `json:"connection"`
	Intent        string     `json:"intent,omitempty"`
	Identity      []byte     `json:"identity,omitempty"`
	Authorization []byte     `json:"authorization,omitempty"`
}
type Connection struct {
	Authority      string `json:"authority"`
	VolumeID       string `json:"volumeId"`
	Endpoint       string `json:"endpoint"`
	ServerName     string `json:"serverName"`
	CACertificate  []byte `json:"caCertificate"`
	RoutesRevision []byte `json:"routesRevision"`
	Hosted         bool   `json:"hosted"`
}

func DecodeDocument(raw []byte) (Document, error) {
	d, err := hostctl.DecodeBounded[Document](raw, MaxDocument)
	if err != nil {
		return d, errors.New("invalid .pfsworkspace document")
	}
	return d, d.Validate()
}
func (c Connection) Validate() error {
	id, err := mountlifecycle.AuthorityIdentity(c.ServerName)
	if err != nil || id != c.Authority || !mountlifecycle.ValidVolume(c.VolumeID) || len(c.CACertificate) == 0 || len(c.CACertificate) > 65536 || !workspacecontrol.Digest(c.RoutesRevision) {
		return errors.New("invalid workspace connection identity")
	}
	host, port, err := net.SplitHostPort(c.Endpoint)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || n < 1 || n > 65535 || host == "" || len(c.Endpoint) > 4096 || strings.ContainsAny(host, " /\t\r\n\x00") || strings.EqualFold(host, "localhost") {
		return errors.New("invalid guest authority endpoint")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return errors.New("guest authority endpoint cannot be host loopback")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.CACertificate) {
		return errors.New("invalid authority CA")
	}
	return nil
}
func (d Document) Validate() error {
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > MaxDocument {
		return errors.New("workspace document exceeds bound")
	}
	if d.Version != Version {
		return errors.New("workspace document version mismatch")
	}
	if err := d.Connection.Validate(); err != nil {
		return err
	}
	switch d.Kind {
	case "connection":
		if d.Intent != "" || len(d.Identity) > 0 || len(d.Authorization) > 0 || d.RenewalScope != "" || d.RenewalEpoch != "" {
			return errors.New("connection document contains authorization fields")
		}
		return nil
	case "request", "authorization":
	default:
		return errors.New("invalid workspace document variant")
	}
	intent, err := hex.DecodeString(d.Intent)
	if err != nil || len(intent) != 16 || !workspacecontrol.ID(intent) || hex.EncodeToString(intent) != d.Intent {
		return errors.New("invalid mount intent")
	}
	identity, err := d.GuestIdentity()
	if err != nil {
		return err
	}
	if d.Connection.Hosted {
		if d.RenewalScope != workspacemount.RenewalScope(identity) || d.RenewalEpoch != strconv.FormatUint(identity.RenewalEpoch, 10) {
			return errors.New("workspace renewal scope or epoch mismatch")
		}
	} else if d.RenewalScope != "" || d.RenewalEpoch != "" {
		return errors.New("standalone request contains hosted scope")
	}
	authority, _ := hex.DecodeString(d.Connection.Authority)
	csr, err := x509.ParseCertificateRequest(identity.Csr)
	if err != nil || csr.CheckSignature() != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, identity.PublicKey) || !bytes.Equal(identity.Mount.AuthorityId, authority) || identity.Mount.VolumeId != d.Connection.VolumeID {
		return errors.New("authorization request identity mismatch")
	}
	if d.Kind == "request" {
		if len(d.Authorization) != 0 {
			return errors.New("request contains authorization")
		}
		return nil
	}
	provision, err := d.Provision()
	if err != nil {
		return err
	}
	if !proto.Equal(provision.Mount, identity.Mount) || !bytes.Equal(provision.PublicKey, identity.PublicKey) || provision.AuthorityEndpoint != d.Connection.Endpoint || provision.ServerName != d.Connection.ServerName || !bytes.Equal(provision.CaCertificate, d.Connection.CACertificate) || !bytes.Equal(provision.RoutesRevision, d.Connection.RoutesRevision) || (provision.HostedEnrollment != nil) != d.Connection.Hosted {
		return errors.New("authorization does not bind the saved request")
	}
	return nil
}
func (d Document) GuestIdentity() (*pb.IdentityReply, error) {
	e, err := workspacecontrol.Decode(d.Identity)
	if err != nil || e.RequestId != 1 || e.GetIdentityReply() == nil {
		return nil, errors.New("invalid public guest identity")
	}
	return e.GetIdentityReply(), nil
}
func (d Document) Provision() (*pb.Provision, error) {
	e, err := workspacecontrol.Decode(d.Authorization)
	if err != nil || e.RequestId != 1 || e.GetProvision() == nil {
		return nil, errors.New("invalid public authorization")
	}
	return e.GetProvision(), nil
}
func (d Document) MatchesRequest(request Document) bool {
	a, b := d, request
	a.Kind = "request"
	a.Authorization = nil
	b.Kind = "request"
	b.Authorization = nil
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func NewAuthorizationRequest(c Connection, intent string, identity *pb.IdentityReply) (Document, error) {
	raw, err := workspacecontrol.Encode(&pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_IdentityReply{IdentityReply: identity}})
	if err != nil {
		return Document{}, err
	}
	d := Document{Version: 1, Kind: "request", Connection: c, Intent: intent, Identity: raw}
	if c.Hosted {
		d.RenewalScope = workspacemount.RenewalScope(identity)
		d.RenewalEpoch = strconv.FormatUint(identity.RenewalEpoch, 10)
	}
	return d, d.Validate()
}

// HostedIssueRequest hands only the public CSR and product-signed grant to the
// existing Manager boundary. The caller/product owns authentication and signing;
// neither the Mac service nor the guest imports an issuer key.
func (d Document) HostedIssueRequest(authorization string, access []string) (controlplane.IssueMountRequest, error) {
	if err := d.Validate(); err != nil {
		return controlplane.IssueMountRequest{}, err
	}
	r, err := d.GuestIdentity()
	if err != nil {
		return controlplane.IssueMountRequest{}, err
	}
	return workspacemount.IssueRequest(r, authorization, access)
}
func (d Document) String() string {
	return fmt.Sprintf(".pfsworkspace %s for %s", d.Kind, d.Connection.VolumeID)
}

// Authorize wraps an issuer's existing Provision response without introducing
// another key import or issuance protocol. The complete public request is echoed.
func (d Document) Authorize(provision *pb.Provision) (Document, error) {
	if d.Kind != "request" {
		return Document{}, errors.New("authorization requires a saved public request")
	}
	if err := d.Validate(); err != nil {
		return Document{}, err
	}
	raw, err := workspacecontrol.Encode(&pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_Provision{Provision: provision}})
	if err != nil {
		return Document{}, err
	}
	d.Kind = "authorization"
	d.Authorization = raw
	return d, d.Validate()
}

// HostedAuthorization converts only the existing product-authenticated Manager
// result. The Manager origin/trust is supplied by the issuer integration, never
// inferred from an untrusted browser or copied from a Mac mount private key.
func (d Document) HostedAuthorization(grant controlplane.MountAuthorization, managerOrigin, managerName string, managerCA []byte) (Document, error) {
	identity, err := d.GuestIdentity()
	if err != nil {
		return Document{}, err
	}
	if !d.Connection.Hosted || grant.VolumeID != d.Connection.VolumeID || grant.AuthorityEndpoint != d.Connection.Endpoint || grant.AuthorityServerName != d.Connection.ServerName || grant.AuthorityCAPEM != string(d.Connection.CACertificate) || grant.EnrollmentID == "" || grant.EnrollmentCertificatePEM == "" || grant.ExpiresUnix <= 0 || grant.Sequence != 0 || grant.SessionID != "" {
		return Document{}, errors.New("Manager result does not bind the workspace connection")
	}
	p := &pb.Provision{Mount: identity.Mount, AuthorityEndpoint: grant.AuthorityEndpoint, ServerName: grant.AuthorityServerName, CaCertificate: []byte(grant.AuthorityCAPEM), ClientCertificate: []byte(grant.ClientCertificatePEM), Capability: []byte(grant.Capability), RoutesRevision: d.Connection.RoutesRevision, PublicKey: identity.PublicKey, HostedEnrollment: &pb.HostedEnrollment{ManagerOrigin: managerOrigin, ManagerServerName: managerName, ManagerCa: managerCA, EnrollmentId: grant.EnrollmentID, EnrollmentCertificate: []byte(grant.EnrollmentCertificatePEM), AuthorityGeneration: grant.AuthorityGeneration, AuthorizationDeadlineUnix: uint64(grant.ExpiresUnix)}}
	return d.Authorize(p)
}
