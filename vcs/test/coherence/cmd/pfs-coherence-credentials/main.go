// Command pfs-coherence-credentials mints the credential set the standalone
// PortableFS authority and mount binaries require, for the cross-mount
// coherence harness.
//
// It is a separate binary from the matrix driver on purpose. The driver must
// build and run with nothing but the standard library so it can be dropped on
// any machine (including a second Mac) that has no PortableFS source tree, and
// so a compile error anywhere in the engine cannot stop the matrix from
// reporting. Only this tool links the production capability signer.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
)

// run produces the exact credential set the standalone authority and mount
// binaries require: a CA, a server identity, a client identity, the control
// plane's Ed25519 capability key, and one single-use access capability per
// mount.
//
// The capability is signed with volumecap.Sign, the same function the control
// plane uses. The harness deliberately does not reimplement the token format:
// a private copy would drift from the verifier and could let this matrix pass
// against a credential production would refuse.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pfs-coherence-credentials: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("pfs-coherence-credentials", flag.ExitOnError)
	var (
		dir      = flags.String("dir", "", "output directory for the credential set")
		volumeID = flags.String("volume-id", "", "exact volume identity")
		host     = flags.String("server-name", "authority.portablefs.test", "authority certificate DNS name")
		tokens   = flags.Int("tokens", 2, "number of single-use read/write access capabilities to mint")
		// Admin capabilities are minted separately and named differently because
		// they are a different power. "admin" implies read and write, but write
		// deliberately does not imply admin (volumecap.Authorizer): changing
		// .portablefs/local-dirs changes what every OTHER machine can see, so a
		// mount's capability must not be able to do it. Handing the mounts an
		// admin token to save a flag would make the harness prove the wrong
		// thing about the separation it is meant to exercise.
		adminTokens = flags.Int("admin-tokens", 1, "number of single-use ADMIN capabilities to mint (ApplyRoutes)")
		lifetime    = flags.Duration("lifetime", 10*time.Minute, "capability validity window")
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *dir == "" || *volumeID == "" || *tokens < 1 {
		return fmt.Errorf("--dir, --volume-id and a positive --tokens are required")
	}
	if *adminTokens < 0 {
		return fmt.Errorf("--admin-tokens must not be negative")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}

	authority, err := issue("PortableFS coherence harness CA", nil, nil, true, nil)
	if err != nil {
		return fmt.Errorf("issue CA: %w", err)
	}
	server, err := issue(*host, authority.certificate, authority.key, false, []string{*host})
	if err != nil {
		return fmt.Errorf("issue server identity: %w", err)
	}
	client, err := issue("portablefs-coherence-mount", authority.certificate, authority.key, false, nil)
	if err != nil {
		return fmt.Errorf("issue client identity: %w", err)
	}

	capabilityPublic, capabilityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(capabilityPublic)
	if err != nil {
		return err
	}

	write := func(name string, mode os.FileMode, data []byte) error {
		path := filepath.Join(*dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			return err
		}
		// WriteFile applies the umask; both binaries refuse a private file that
		// is readable by group or other, so set the mode explicitly.
		return os.Chmod(path, mode)
	}
	files := []struct {
		name string
		mode os.FileMode
		data []byte
	}{
		{"ca.pem", 0o644, encode("CERTIFICATE", authority.certDER)},
		{"server.crt", 0o644, encode("CERTIFICATE", server.certDER)},
		{"server.key", 0o600, encode("PRIVATE KEY", server.keyDER)},
		{"client.crt", 0o644, encode("CERTIFICATE", client.certDER)},
		{"client.key", 0o600, encode("PRIVATE KEY", client.keyDER)},
		{"capability-public.pem", 0o644, encode("PUBLIC KEY", publicDER)},
	}
	for _, file := range files {
		if err := write(file.name, file.mode, file.data); err != nil {
			return err
		}
	}

	// The capability is bound to the exact client key the mount presents, so a
	// stolen token is useless to any other TLS identity.
	peer := sha256.Sum256(client.certificate.RawSubjectPublicKeyInfo)
	now := time.Now()
	mint := func(subject string, access []string) ([]byte, error) {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		return volumecap.Sign(capabilityPrivate, volumecap.Claims{
			VolumeID:  *volumeID,
			Subject:   subject,
			Access:    access,
			NotBefore: now.Add(-time.Second).Unix(),
			Expires:   now.Add(*lifetime).Unix(),
			PeerSPKI:  base64.RawURLEncoding.EncodeToString(peer[:]),
			Nonce:     hex.EncodeToString(nonce[:]),
		})
	}
	for index := range *tokens {
		token, err := mint(fmt.Sprintf("coherence-mount-%d", index), []string{"read", "write"})
		if err != nil {
			return err
		}
		if err := write(fmt.Sprintf("access-%d.token", index), 0o600, token); err != nil {
			return err
		}
	}
	for index := range *adminTokens {
		token, err := mint(fmt.Sprintf("coherence-admin-%d", index), []string{"admin"})
		if err != nil {
			return err
		}
		if err := write(fmt.Sprintf("admin-%d.token", index), 0o600, token); err != nil {
			return err
		}
	}
	fmt.Printf("credentials for volume %s written to %s (%d single-use access + %d admin capabilities, server name %s)\n",
		*volumeID, *dir, *tokens, *adminTokens, *host)
	return nil
}

type identity struct {
	key         ed25519.PrivateKey
	certificate *x509.Certificate
	certDER     []byte
	keyDER      []byte
}

func issue(commonName string, parent *x509.Certificate, parentKey ed25519.PrivateKey, isCA bool, dnsNames []string) (identity, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return identity{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return identity{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              dnsNames,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	signer, signerKey := template, any(private)
	if parent != nil {
		signer, signerKey = parent, any(parentKey)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, public, signerKey)
	if err != nil {
		return identity{}, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return identity{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return identity{}, err
	}
	return identity{key: private, certificate: parsed, certDER: der, keyDER: keyDER}, nil
}

func encode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}
