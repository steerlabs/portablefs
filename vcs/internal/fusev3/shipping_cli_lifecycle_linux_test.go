//go:build linux

package fusev3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
)

// This executes the released cmd/portablefs composition, including its durable
// inventory and hosted renewer. The e2e tag changes only account-home lookup;
// protocol, frontend, renewal, and exact unmount all use production code.
func TestShippingCLIEpochReplacementRequiresFreshRenewedMount(t *testing.T) {
	shippingCLILifecycle(t, "")
}

// These run the actual runMountForeground composition, including signals,
// kernel Wait, Manager cancellation, durable intent and exact teardown.
func TestShippingCLIInitialRenewalSupervision(t *testing.T) {
	for _, scenario := range []string{"denied-busy", "unavailable-term", "unavailable-int", "external-unmount"} {
		t.Run(scenario, func(t *testing.T) { shippingCLILifecycle(t, scenario) })
	}
}
func shippingCLILifecycle(t *testing.T, scenario string) {
	requireIntegrationEnvironment(t)
	home := t.TempDir()
	binary := filepath.Join(home, "portablefs")
	build := exec.Command("go", "build", "-tags", "portablefs_e2e", "-o", binary, "../../cmd/portablefs")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build shipping CLI: %v\n%s", err, out)
	}
	_, managerKey, _ := ed25519.GenerateKey(rand.Reader)
	_, productKey, _ := ed25519.GenerateKey(rand.Reader)
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1, skipMounts: true, NameCacheCapacity: 1 << 16, authorizer: func() authorityrpc.Authorizer {
		return &volumecap.Authorizer{PublicKey: managerKey.Public().(ed25519.PublicKey), ProductPublicKey: productKey.Public().(ed25519.PublicKey), ProductIssuer: "test-host", ProductAudience: "portablefs", AuthorizationDomain: "test-domain", Owner: "test-owner", CellID: "test-cell", AuthorityID: "test-authority", AuthorityGeneration: 1, MaxLifetime: time.Hour, MaxRetainedNonces: 100}
	}})
	f.cfg.listenAddress = f.listener.Addr().String()
	path := f.mountPath(0)
	write := func(name string, data []byte) string {
		t.Helper()
		target := filepath.Join(home, name)
		if err := os.WriteFile(target, data, 0600); err != nil {
			t.Fatal(err)
		}
		return target
	}
	ca := write("ca.pem", f.credentials.AuthorityCAPEM)
	cert := write("client.pem", f.credentials.ClientCertificatePEM)
	key := write("key.pem", f.credentials.ClientPrivateKeyPEM)
	leaf, err := x509.ParseCertificate(f.clientTLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	peerText := base64.RawURLEncoding.EncodeToString(peer[:])
	sign := func(enrollment, session string, sequence uint64, expires time.Time) string {
		claims := volumecap.Claims{VolumeID: integrationVolumeID, Subject: "test-workspace", Access: []string{"write"}, NotBefore: time.Now().Add(-time.Second).Unix(), Expires: expires.Unix(), PeerSPKI: peerText, Nonce: fmt.Sprintf("%s:%s:%d", enrollment, session, sequence), CellID: "test-cell", AuthorityID: "test-authority", AuthorityGeneration: 1, MountEnrollmentID: enrollment, SessionID: session, Sequence: sequence}
		if session == "" {
			token, signErr := productauth.Sign(productKey, productauth.Claims{Issuer: "test-host", Audience: "portablefs", AuthorizationDomain: "test-domain", Owner: "test-owner", Subject: claims.Subject, VolumeID: integrationVolumeID, Access: claims.Access, PeerSPKI: peerText, Nonce: enrollment, NotBefore: claims.NotBefore, Expires: expires.Unix()})
			if signErr != nil {
				panic(signErr)
			}
			claims.ProductAuthorization = string(token)
		}
		token, signErr := volumecap.Sign(managerKey, claims)
		if signErr != nil {
			panic(signErr)
		}
		return string(token)
	}
	// The Manager endpoint enforces the same immutable enrollment/session binding
	// that manager_mount_replacement_test proves against the real durable Manager.
	var mu sync.Mutex
	sessions := make(map[string]string)
	refreshEntered, refreshRelease := make(chan struct{}), make(chan struct{})
	var enteredOnce sync.Once
	manager := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 {
			http.Error(w, "missing enrollment", 401)
			return
		}
		enrollment := strings.TrimPrefix(r.TLS.PeerCertificates[0].URIs[0].String(), "spiffe://portablefs/mount-enrollment/")
		if !strings.Contains(r.URL.Path, "/"+enrollment+"/") {
			http.Error(w, "wrong enrollment", 403)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/close") {
			_ = json.NewEncoder(w).Encode(controlplane.MountEnrollment{ID: enrollment, State: controlplane.MountEnrollmentClosed})
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/reauthorizations") {
			http.NotFound(w, r)
			return
		}
		var request controlplane.RefreshMountEnrollmentRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Sequence == 0 || request.SessionID == "" {
			http.Error(w, "invalid refresh", 400)
			return
		}
		mu.Lock()
		bound := sessions[enrollment]
		if bound == "" {
			sessions[enrollment] = request.SessionID
		}
		mu.Unlock()
		if bound != "" && bound != request.SessionID {
			http.Error(w, "session changed", 409)
			return
		}
		if scenario != "" {
			enteredOnce.Do(func() { close(refreshEntered) })
			if scenario == "denied-busy" {
				select {
				case <-refreshRelease:
					http.Error(w, "enrollment denied", http.StatusForbidden)
				case <-r.Context().Done():
				}
			} else {
				<-r.Context().Done()
			}
			return
		}
		expires := time.Now().Add(time.Minute).Truncate(time.Second)
		_ = json.NewEncoder(w).Encode(controlplane.MountAuthorization{VolumeID: integrationVolumeID, Capability: sign(enrollment, request.SessionID, request.Sequence, expires), ClientCertificatePEM: string(f.credentials.ClientCertificatePEM), Access: []string{"write"}, ExpiresUnix: expires.Unix(), CertificateExpiresUnix: leaf.NotAfter.Unix(), AuthorityGeneration: 1, SessionID: request.SessionID, Sequence: request.Sequence})
	}))
	manager.TLS = f.serverTLS.Clone()
	manager.StartTLS()
	defer manager.Close()
	env := append(os.Environ(), "PORTABLEFS_E2E_ACCOUNT_HOME="+home)
	command := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	inventory := func() *shippingCLIMountRow {
		t.Helper()
		out, err := command("mounts", "--json")
		if err != nil {
			t.Fatalf("inventory: %v\n%s", err, out)
		}
		var rows struct {
			Mounts []shippingCLIMountRow `json:"mounts"`
		}
		if err := json.Unmarshal(out, &rows); err != nil {
			t.Fatalf("decode inventory: %v\n%s", err, out)
		}
		for i := range rows.Mounts {
			if rows.Mounts[i].MountPath == path {
				return &rows.Mounts[i]
			}
		}
		return nil
	}
	var running *exec.Cmd
	var done chan struct{}
	start := func(enrollment string, lifetime time.Duration) time.Time {
		t.Helper()
		uri, _ := url.Parse("spiffe://portablefs/mount-enrollment/" + enrollment)
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(len(enrollment)) + 100), Subject: pkix.Name{CommonName: enrollment}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
		der, err := x509.CreateCertificate(rand.Reader, template, f.credentials.issuer, leaf.PublicKey, f.credentials.issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		enrollmentCert := write(enrollment+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		expires := time.Now().Add(lifetime).Truncate(time.Second)
		log, err := os.Create(filepath.Join(home, enrollment+".log"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = log.Close() })
		running = exec.Command(binary, "mount", integrationVolumeID, path, "--foreground", "--addr", f.cfg.listenAddress, "--mount-token", sign(enrollment, "", 0, expires), "--data-plane-transport", "tls-private-ca", "--data-plane-server-name", "localhost", "--data-plane-ca", ca, "--client-cert", cert, "--client-key", key, "--manager-url", manager.URL, "--manager-server-name", "localhost", "--manager-ca", ca, "--mount-enrollment-id", enrollment, "--mount-enrollment-cert", enrollmentCert, "--authority-generation", "1", "--auth-expires-at-ms", strconv.FormatInt(expires.UnixMilli(), 10))
		running.Env = env
		running.Stdout = log
		running.Stderr = log
		if err := running.Start(); err != nil {
			t.Fatal(err)
		}
		done = make(chan struct{})
		completed := done
		cmd := running
		go func() { _ = cmd.Wait(); close(completed) }()
		if scenario != "" {
			return expires
		}
		waitShippingCLI(t, 10*time.Second, func() bool {
			row := inventory()
			return row != nil && row.Health == "live" && row.MountEnrollmentID == enrollment && row.LastReauthorizationAtMs > 0
		}, func() string { b, _ := os.ReadFile(log.Name()); return string(b) })
		return expires
	}
	t.Cleanup(func() {
		_, _ = command("umount", path, "--json")
		if running != nil {
			select {
			case <-done:
			default:
				_ = running.Process.Kill()
				<-done
			}
		}
		if isMounted(t, path) {
			t.Errorf("shipping CLI left its mount installed")
			_ = exec.Command("fusermount3", "-u", "-z", path).Run()
		}
	})
	if scenario != "" {
		start("startup-enrollment", 10*time.Minute)
		select {
		case <-refreshEntered:
		case <-time.After(15 * time.Second):
			t.Fatal("first renewal did not reach Manager")
		}
		var retained *os.File
		switch scenario {
		case "denied-busy":
			retained, err = os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer retained.Close()
			close(refreshRelease)
		case "unavailable-term":
			if err := running.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
		case "unavailable-int":
			if err := running.Process.Signal(syscall.SIGINT); err != nil {
				t.Fatal(err)
			}
		case "external-unmount":
			if out, err := exec.Command("fusermount3", "-u", path).CombinedOutput(); err != nil {
				t.Fatalf("external unmount: %s %v", out, err)
			}
		}
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("startup failed to supervise first renewal")
		}
		data, err := os.ReadFile(filepath.Join(home, "startup-enrollment.log"))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if strings.Contains(text, "Ctrl-C unmounts") {
			t.Fatal("published readiness before first renewal", text)
		}
		if scenario == "denied-busy" {
			if !strings.Contains(text, "initial automatic renewal failed") || !strings.Contains(text, "transactional startup FUSE unmount failed") || !isMounted(t, path) {
				t.Fatal("busy denial was not independently reported with retained mount intent", text)
			}
			retained.Close()
			if out, err := exec.Command("fusermount3", "-u", path).CombinedOutput(); err != nil {
				t.Fatalf("release busy startup mount: %s %v", out, err)
			}
		} else {
			if isMounted(t, path) || f.membership.activeCount() != 0 {
				t.Fatal("startup shutdown did not release exact mount/session", text)
			}
			if scenario == "external-unmount" && !strings.Contains(text, "kernel mount ended before initial renewal") {
				t.Fatal("external unmount not observed", text)
			}
			if scenario != "external-unmount" && !strings.Contains(text, "mount startup interrupted") {
				t.Fatal("signal took default termination path", text)
			}
		}
		return
	}
	expires := start("old-enrollment", 12*time.Second)
	old := *inventory()
	if old.AuthorizationSessionID == "" || old.MountInstanceID == "" {
		t.Fatal("shipping inventory omitted immutable session/mount instance")
	}
	assertLiveLoss := func(instance string) {
		t.Helper()
		out, err := command("mount-loss", path, "--mount-instance", instance, "--json")
		if err != nil {
			t.Fatalf("read live automatic mount loss: %v\n%s", err, out)
		}
		var snapshot struct {
			MountPath       string `json:"mountPath"`
			MountInstanceID string `json:"mountInstanceId"`
			LossSequence    string `json:"lossSequence"`
		}
		if err := json.Unmarshal(out, &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.MountPath != path || snapshot.MountInstanceID != instance || snapshot.LossSequence != "0" {
			t.Fatalf("live automatic mount snapshot: %+v", snapshot)
		}
	}
	assertLiveLoss(old.MountInstanceID)
	mustWrite(t, filepath.Join(path, "durable"), []byte("survives epoch"), 0600)
	fd, err := os.OpenFile(filepath.Join(path, "durable"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := fd.Sync(); err != nil {
		t.Fatal(err)
	}
	_ = fd.Close()
	// The initial attach grant is genuinely expired, while automatic renewal has
	// installed a later deadline into this exact session.
	if delay := time.Until(expires.Add(100 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	requireContent(t, filepath.Join(path, "durable"), []byte("survives epoch"), "beyond initial grant expiry")
	row := inventory()
	if row == nil || row.AuthorizationSessionID != old.AuthorizationSessionID || row.AuthorizationDeadlineAtMs <= expires.UnixMilli() {
		t.Fatalf("renewal changed identity or failed to extend expired grant: %+v", row)
	}
	f.stopAuthority()
	f.closeStore()
	f.start()
	waitShippingCLI(t, 20*time.Second, func() bool { row := inventory(); return row != nil && row.Health != "live" }, func() string { return fmt.Sprintf("inventory=%+v", inventory()) })
	if row := inventory(); row.AuthorizationSessionID != old.AuthorizationSessionID {
		t.Fatalf("ended instance published a replacement session: %+v", row)
	}
	if out, err := command("umount", path, "--json"); err != nil {
		t.Fatalf("withdraw old instance: %v\n%s", err, out)
	}
	if isMounted(t, path) || inventory() != nil {
		t.Fatal("old instance not observably withdrawn")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("old CLI owner still running after verified unmount")
	}
	start("replacement-enrollment", time.Minute)
	replacement := inventory()
	if replacement.AuthorizationSessionID == old.AuthorizationSessionID || replacement.MountInstanceID == old.MountInstanceID {
		t.Fatalf("replacement reused old identity: %+v", replacement)
	}
	assertLiveLoss(replacement.MountInstanceID)
	if out, err := command("mount-loss", path, "--mount-instance", old.MountInstanceID, "--json"); err == nil {
		t.Fatalf("old instance queried successor loss counter: %s", out)
	}
	mu.Lock()
	bound := sessions["replacement-enrollment"]
	oldBound := sessions["old-enrollment"]
	mu.Unlock()
	if bound != replacement.AuthorizationSessionID || oldBound != old.AuthorizationSessionID {
		t.Fatalf("renewal session bindings old=%q new=%q", oldBound, bound)
	}
	requireContent(t, filepath.Join(path, "durable"), []byte("survives epoch"), "fresh authorized replacement")
}

type shippingCLIMountRow struct {
	MountPath                 string `json:"mountPath"`
	MountInstanceID           string `json:"mountInstanceId"`
	AuthorizationSessionID    string `json:"authorizationSessionId"`
	MountEnrollmentID         string `json:"mountEnrollmentId"`
	Health                    string `json:"health"`
	LastReauthorizationAtMs   int64  `json:"lastReauthorizationAtMs"`
	AuthorizationDeadlineAtMs int64  `json:"authorizationDeadlineAtMs"`
}

func waitShippingCLI(t *testing.T, bound time.Duration, ready func() bool, detail func() string) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("shipping CLI lifecycle did not converge within %s: %s", bound, detail())
}
