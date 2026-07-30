package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/accountsession"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

// Profile is one saved credential set in the config file.
type Profile struct {
	APIUrl       string `json:"apiUrl"`
	APIToken     string `json:"apiToken"`
	ManagerUrl   string `json:"managerUrl"`
	ManagerToken string `json:"managerToken"`
}

// Config is the on-disk shape of ~/.config/portablefs/config.json.
type Config struct {
	CurrentProfile string             `json:"currentProfile"`
	Profiles       map[string]Profile `json:"profiles"`
}

func defaultConfigPath() (string, error) {
	home, err := accountpath.Home()
	if err != nil {
		return "", fmt.Errorf("resolve account home for config file: %w", err)
	}
	return filepath.Join(home, ".config", "portablefs", "config.json"), nil
}

// loadConfig reads the config file. A missing file is an empty config, not an
// error, so first-run commands work before any login.
func loadConfig(path string) (*Config, error) {
	data, err := privatepath.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{CurrentProfile: "default", Profiles: map[string]Profile{}}, nil
	}
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
// tokens). The parent directory is created on demand. Existing files with
// unsafe type, ownership, link count, or mode are refused, never repaired.
func saveConfig(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := privatepath.WriteFileAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}

// mutateConfigExclusive is the sole saved-profile mutation boundary. Network
// authentication happens before entry; while held it excludes mount startup,
// rejects any strict residual mount/attach inventory, reloads the latest
// config, applies one mutation, and atomically publishes it.
func (e *cmdEnv) mutateConfigExclusive(update func(*Config, string) error) (string, error) {
	stateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return "", err
	}
	guard, err := accountsession.AcquireExclusive(stateDir)
	if err != nil {
		return "", fmt.Errorf("acquire account session guard: %w; unmount PortableFS volumes before changing credentials or profiles", err)
	}
	defer guard.Close()
	if _, _, err := e.strictAccountInventory(); err != nil {
		return "", err
	}
	cfg, path, err := e.loadConfig()
	if err != nil {
		return "", err
	}
	if err := update(cfg, path); err != nil {
		return "", err
	}
	if err := saveConfig(path, cfg); err != nil {
		return "", err
	}
	return path, nil
}

// settings is the fully resolved connection configuration for one command run.
type settings struct {
	apiURL       string
	apiToken     string
	managerURL   string
	managerToken string
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
		apiURL:       pick(flags.apiURL, "PORTABLEFS_API_URL", prof.APIUrl),
		apiToken:     pick(flags.apiToken, "PORTABLEFS_API_TOKEN", prof.APIToken),
		managerURL:   pick(flags.managerURL, "PORTABLEFS_MANAGER_URL", prof.ManagerUrl),
		managerToken: pick(flags.managerToken, "PORTABLEFS_MANAGER_TOKEN", prof.ManagerToken),
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
