// Package daemonctl defines the private daemon control and lifecycle interfaces.
// Operational control requires exact paired-release versions. Lifecycle v1 is
// frozen across future operational bumps and is only for authenticated outgoing
// release quiescence. It is not authentication by itself: callers must bind the
// socket peer and live process to the actual executable and sealed release before
// trusting identity or inventory. Lifecycle snapshots do not authorize removal;
// admission closure, process/kernel absence and singleton exclusion still apply.
package daemonctl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	IdentitySchemaVersion  = 1
	ControlProtocolVersion = 2
	ControlProtocolHeader  = "X-PortableFS-Control-Protocol"
	ControlPathPrefix      = "/v2/"
)

// Identity is schema 1, shared by operational and lifecycle identity responses.
// Protocol values describe the serving release; lifecycle validation must not
// compare them to the incoming build's compiled versions. Process binding is
// supplied by authenticated socket/process witnesses, not claimed JSON fields.
type Identity struct {
	SchemaVersion    int    `json:"schemaVersion"`
	ControlProtocol  int    `json:"controlProtocol"`
	DaemonVersion    string `json:"daemonVersion"`
	ExecutableSHA256 string `json:"executableSha256"`
	PFSLocalMajor    uint32 `json:"pfslocalMajor"`
	PFSLocalMinor    uint32 `json:"pfslocalMinor"`
}

// Validate checks schema 1's shape, independently of release authentication and
// operational version equality. Minor zero is valid; major zero is not.
func (identity Identity) Validate() error {
	if identity.SchemaVersion != IdentitySchemaVersion {
		return fmt.Errorf("identity: unsupported schema version %d", identity.SchemaVersion)
	}
	if identity.ControlProtocol <= 0 || identity.PFSLocalMajor == 0 {
		return fmt.Errorf("identity: control protocol and pfslocal major must be positive")
	}
	if len(identity.DaemonVersion) == 0 || len(identity.DaemonVersion) > 128 {
		return fmt.Errorf("identity: daemon version must contain 1 to 128 visible ASCII bytes")
	}
	for _, char := range []byte(identity.DaemonVersion) {
		if char < 0x21 || char > 0x7e {
			return fmt.Errorf("identity: daemon version must contain only visible ASCII bytes")
		}
	}
	if len(identity.ExecutableSHA256) != sha256.Size*2 {
		return fmt.Errorf("identity: executable SHA-256 must contain 64 lowercase hex digits")
	}
	for _, char := range []byte(identity.ExecutableSHA256) {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return fmt.Errorf("identity: executable SHA-256 must contain 64 lowercase hex digits")
		}
	}
	return nil
}

// EncodeIdentity returns a validated schema-1 JSON body, without a newline.
func EncodeIdentity(identity Identity) ([]byte, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(identity)
}

// DecodeIdentity requires exactly schema 1's six keys and one complete object.
// Unknown, missing, duplicate (including escaped), null and mistyped fields fail.
// A lifecycle caller must separately require HTTP 200 before using this body.
func DecodeIdentity(body []byte) (Identity, error) {
	var identity Identity
	if err := decodeLifecycleObject(body, map[string]any{
		"schemaVersion":    &identity.SchemaVersion,
		"controlProtocol":  &identity.ControlProtocol,
		"daemonVersion":    &identity.DaemonVersion,
		"executableSha256": &identity.ExecutableSHA256,
		"pfslocalMajor":    &identity.PFSLocalMajor,
		"pfslocalMinor":    &identity.PFSLocalMinor,
	}); err != nil {
		return Identity{}, fmt.Errorf("decode identity: %w", err)
	}
	if err := identity.Validate(); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func FileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func CurrentExecutableSHA256() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	sum, err := FileSHA256(path)
	if err != nil {
		return "", fmt.Errorf("hash executable %s: %w", path, err)
	}
	return sum, nil
}
