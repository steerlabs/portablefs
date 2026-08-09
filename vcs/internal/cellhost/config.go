package cellhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

var ErrInvalid = errors.New("cellhost: invalid configuration or assignment")

type AuthorityConfig struct {
	Version                 uint32 `json:"version"`
	VolumeID                string `json:"volume_id"`
	CellID                  string `json:"cell_id"`
	AuthorizationDomain     string `json:"authorization_domain"`
	Owner                   string `json:"owner"`
	ProductIssuer           string `json:"product_issuer"`
	AuthorityID             string `json:"authority_id"`
	AuthorityGeneration     uint64 `json:"authority_generation"`
	ProjectID               uint32 `json:"project_id"`
	PriorStrictMountsFenced bool   `json:"prior_strict_mounts_fenced"`
}

func LoadAuthorityConfig(path string) (AuthorityConfig, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return AuthorityConfig{}, errors.New("cellhost: authority config path must be clean and absolute")
	}
	file, err := os.Open(path)
	if err != nil {
		return AuthorityConfig{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return AuthorityConfig{}, errors.New("cellhost: authority config must be a bounded regular file")
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var config AuthorityConfig
	if err := decoder.Decode(&config); err != nil {
		return AuthorityConfig{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return AuthorityConfig{}, errors.New("cellhost: authority config has trailing data")
	}
	if config.Version != 1 || !cellplan.ValidID(config.VolumeID) || !cellplan.ValidID(config.CellID) ||
		config.AuthorizationDomain == "" || config.Owner == "" || config.ProductIssuer == "" ||
		config.AuthorityID == "" || config.AuthorityGeneration == 0 || config.ProjectID == 0 {
		return AuthorityConfig{}, errors.New("cellhost: authority config is incomplete")
	}
	return config, nil
}

// AuthorityArguments is the only authority command shape the launcher can
// produce. All paths name fixed bind-mount targets in the service namespace;
// the signed plan supplies identities and integers, never argv or paths.
func AuthorityArguments(config AuthorityConfig) []string {
	generation := strconv.FormatUint(config.AuthorityGeneration, 10)
	arguments := []string{
		"-volume-id", config.VolumeID,
		"-root", "/srv/portablefs-volume",
		"-project-id", strconv.FormatUint(uint64(config.ProjectID), 10),
		"-tls-cert", fmt.Sprintf("/run/portablefs-volume/authority-%s.cert", generation),
		"-tls-key", fmt.Sprintf("/run/portablefs-volume/authority-%s.key", generation),
		"-client-ca", "/run/portablefs-volume/client-ca.pem",
		"-capability-public-key", "/run/portablefs-volume/capability-public.pem",
		"-product-authorization-public-key", "/run/portablefs-volume/product-public.pem",
		"-product-issuer", config.ProductIssuer,
		"-product-audience", "portablefs-manager",
		"-authorization-domain", config.AuthorizationDomain,
		"-owner", config.Owner,
		"-cell-id", config.CellID,
		"-authority-id", config.AuthorityID,
		"-authority-generation", generation,
		"-visibility-membership-file", "/var/lib/portablefs-volume/visibility.membership",
	}
	if config.PriorStrictMountsFenced {
		arguments = append(arguments, "-prior-strict-mounts-fenced")
	}
	return arguments
}
