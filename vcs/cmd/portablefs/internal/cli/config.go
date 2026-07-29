package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Profile is one saved credential set in the config file.
type Profile struct {
	APIUrl       string `json:"apiUrl"`
	APIToken     string `json:"apiToken"`
	ManagerUrl   string `json:"managerUrl"`
	ManagerToken string `json:"managerToken"`
	// DataPlaneCAPEM is the CA bundle that signs the deployment's data-plane
	// router certificate, captured from GET <apiUrl>/router-ca.pem at login.
	// Mounts dial the router with this trust anchor so TLS works without any
	// local file or env setup; PORTABLEFS_TLS_CA / VCS_TLS_CA override it.
	DataPlaneCAPEM string `json:"dataPlaneCaPem,omitempty"`
}

// Config is the on-disk shape of ~/.config/portablefs/config.json.
type Config struct {
	CurrentProfile string             `json:"currentProfile"`
	Profiles       map[string]Profile `json:"profiles"`
}

func defaultConfigPath() (string, error) {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "portablefs", "config.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory for config file: %w", err)
	}
	return filepath.Join(home, ".config", "portablefs", "config.json"), nil
}

// loadConfig reads the config file. A missing file is an empty config, not an
// error, so first-run commands work before any login.
func loadConfig(path string) (*Config, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return &Config{CurrentProfile: "default", Profiles: map[string]Profile{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect config %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refuse unsafe config %s: expected a regular non-symlink file", path)
	}
	if err := verifyConfigFilePermissions(path, info); err != nil {
		return nil, err
	}
	if err := verifyConfigDirectory(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.CurrentProfile == "" {
		cfg.CurrentProfile = "default"
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]Profile{}
	}
	return &cfg, nil
}

// saveConfig writes the config file with 0600 permissions (it holds bearer
// tokens). The parent directory is created on demand; an existing file's mode
// is reset to 0600 in case it was created loose by another tool.
func saveConfig(path string, cfg *Config) error {
	dir := filepath.Dir(path)
	if err := verifyConfigDirectory(dir, true); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".portablefs-config-*.tmp")
	if err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	tmpName := tmp.Name()
	keepTemp := true
	defer func() {
		if keepTemp {
			_ = os.Remove(tmpName)
		}
	}()
	if err := secureTemporaryConfigFile(path, tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync config %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	keepTemp = false
	return syncConfigDirectory(dir)
}

func verifyConfigDirectory(dir string, create bool) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) && create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return fmt.Errorf("inspect config directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refuse unsafe config directory %s: expected a non-symlink directory", dir)
	}
	return verifyConfigDirectoryPermissions(dir, info, create)
}

// settings is the fully resolved connection configuration for one command run.
type settings struct {
	apiURL       string
	apiToken     string
	managerURL   string
	managerToken string
	// dataPlaneCAPEM comes only from the profile (no flag/env: those already
	// exist as PORTABLEFS_TLS_CA/VCS_TLS_CA file paths and take precedence).
	dataPlaneCAPEM string
}

// resolveSettings applies the documented precedence: flags > environment >
// config file profile. Empty flag values mean "not set".
func resolveSettings(cfg *Config, profileName string, getenv func(string) string, flags settings) settings {
	if profileName == "" {
		profileName = cfg.CurrentProfile
	}
	prof := cfg.Profiles[profileName]
	pick := func(flagVal, envName, fileVal string) string {
		if flagVal != "" {
			return flagVal
		}
		if v := getenv(envName); v != "" {
			return v
		}
		return fileVal
	}
	return settings{
		apiURL:         pick(flags.apiURL, "PORTABLEFS_API_URL", prof.APIUrl),
		apiToken:       pick(flags.apiToken, "PORTABLEFS_API_TOKEN", prof.APIToken),
		managerURL:     pick(flags.managerURL, "PORTABLEFS_MANAGER_URL", prof.ManagerUrl),
		managerToken:   pick(flags.managerToken, "PORTABLEFS_MANAGER_TOKEN", prof.ManagerToken),
		dataPlaneCAPEM: prof.DataPlaneCAPEM,
	}
}

// managerEndpoint returns the URL and bearer token for manager-dependent
// commands. Hosted cloud serves the manager surface from the API origin, so an
// unset managerUrl falls back to apiUrl (and managerToken to apiToken).
func (s settings) managerEndpoint() (url, token string) {
	url, token = s.managerURL, s.managerToken
	if url == "" {
		url = s.apiURL
	}
	if token == "" {
		token = s.apiToken
	}
	return url, token
}

func (s settings) requireAPI() error {
	if s.apiURL == "" {
		return fmt.Errorf("no PortableFS server configured: run `portablefs login <url>` or set PORTABLEFS_API_URL")
	}
	if s.apiToken == "" {
		return fmt.Errorf("no PortableFS credential configured: run `portablefs login` or set PORTABLEFS_API_TOKEN")
	}
	return nil
}
