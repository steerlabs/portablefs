// Package daemonctl defines the private control-plane identity shared by the
// portablefs CLI and portablefsd. It is deliberately separate from pfslocal:
// the daemon's HTTP control API and the FSKit frontend wire evolve on
// independent compatibility axes.
package daemonctl

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const (
	IdentitySchemaVersion  = 1
	ControlProtocolVersion = 1
	ControlProtocolHeader  = "X-PortableFS-Control-Protocol"
)

type Identity struct {
	SchemaVersion    int    `json:"schemaVersion"`
	ControlProtocol  int    `json:"controlProtocol"`
	DaemonVersion    string `json:"daemonVersion"`
	ExecutableSHA256 string `json:"executableSha256"`
	PFSLocalMajor    uint32 `json:"pfslocalMajor"`
	PFSLocalMinor    uint32 `json:"pfslocalMinor"`
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
