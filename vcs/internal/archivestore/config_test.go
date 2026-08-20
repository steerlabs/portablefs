package archivestore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodConfigFile = `# root-provisioned archive configuration
PORTABLEFS_ARCHIVE_ENDPOINT=https://objects.example.internal:9000
PORTABLEFS_ARCHIVE_REGION=us-west-2
PORTABLEFS_ARCHIVE_BUCKET=portablefs-archive
PORTABLEFS_ARCHIVE_PREFIX=cells/cell-a
PORTABLEFS_ARCHIVE_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
PORTABLEFS_ARCHIVE_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
PORTABLEFS_ARCHIVE_CHECKSUM_CAPABILITY=crc64nvme-full-object
PORTABLEFS_ARCHIVE_PATH_STYLE=true
`

func writeConfigFile(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cell-archive.env")
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	return path
}

func TestLoadConfigFile(t *testing.T) {
	path := writeConfigFile(t, goodConfigFile, 0o600)
	config, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	want := Config{
		Endpoint:           "https://objects.example.internal:9000",
		Region:             "us-west-2",
		Bucket:             "portablefs-archive",
		KeyPrefix:          "cells/cell-a",
		AccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey:    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		ChecksumCapability: ChecksumCRC64NVMEFullObject,
		PathStyle:          true,
	}
	if config != want {
		t.Fatalf("config = %+v, want %+v", config, want)
	}
}

func TestLoadConfigFileOptionalKeys(t *testing.T) {
	contents := strings.ReplaceAll(goodConfigFile, "PORTABLEFS_ARCHIVE_PATH_STYLE=true\n", "") +
		"PORTABLEFS_ARCHIVE_SESSION_TOKEN=session-token-value\n"
	// Without PATH_STYLE the default is virtual-host addressing.
	config, err := LoadConfigFile(writeConfigFile(t, contents, 0o400))
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if config.PathStyle {
		t.Fatal("path style defaulted to true")
	}
	if config.SessionToken != "session-token-value" {
		t.Fatalf("session token = %q", config.SessionToken)
	}
	// An explicitly empty prefix is legal and means "bucket root".
	empty := strings.ReplaceAll(contents, "PORTABLEFS_ARCHIVE_PREFIX=cells/cell-a", "PORTABLEFS_ARCHIVE_PREFIX=")
	config, err = LoadConfigFile(writeConfigFile(t, empty, 0o600))
	if err != nil {
		t.Fatalf("LoadConfigFile with an empty prefix: %v", err)
	}
	if config.KeyPrefix != "" {
		t.Fatalf("prefix = %q, want empty", config.KeyPrefix)
	}
}

func TestLoadConfigFileRejections(t *testing.T) {
	cases := map[string]string{
		"unknown key":   goodConfigFile + "PORTABLEFS_ARCHIVE_EXTRA=1\n",
		"duplicate key": goodConfigFile + "PORTABLEFS_ARCHIVE_BUCKET=other-bucket\n",
		"missing endpoint": strings.ReplaceAll(goodConfigFile,
			"PORTABLEFS_ARCHIVE_ENDPOINT=https://objects.example.internal:9000\n", ""),
		"missing secret": strings.ReplaceAll(goodConfigFile,
			"PORTABLEFS_ARCHIVE_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY\n", ""),
		"missing capability": strings.ReplaceAll(goodConfigFile,
			"PORTABLEFS_ARCHIVE_CHECKSUM_CAPABILITY=crc64nvme-full-object\n", ""),
		"unknown capability": strings.ReplaceAll(goodConfigFile,
			"crc64nvme-full-object", "crc32c"),
		"quoted value": strings.ReplaceAll(goodConfigFile,
			"PORTABLEFS_ARCHIVE_BUCKET=portablefs-archive", `PORTABLEFS_ARCHIVE_BUCKET="portablefs-archive"`),
		"non-boolean path style": strings.ReplaceAll(goodConfigFile,
			"PORTABLEFS_ARCHIVE_PATH_STYLE=true", "PORTABLEFS_ARCHIVE_PATH_STYLE=yes"),
		"lowercase key":        goodConfigFile + "portablefs_archive_extra=1\n",
		"line without equals":  goodConfigFile + "PORTABLEFS_ARCHIVE_BUCKET\n",
		"indented line":        goodConfigFile + "  PORTABLEFS_ARCHIVE_SESSION_TOKEN=x\n",
		"trailing whitespace":  goodConfigFile + "PORTABLEFS_ARCHIVE_SESSION_TOKEN=x \n",
		"control character":    goodConfigFile + "PORTABLEFS_ARCHIVE_SESSION_TOKEN=a\tb\n",
		"plain http endpoint":  strings.ReplaceAll(goodConfigFile, "https://objects.example.internal:9000", "http://objects.example.internal:9000"),
		"endpoint with a path": strings.ReplaceAll(goodConfigFile, "https://objects.example.internal:9000", "https://objects.example.internal/s3"),
		"absolute prefix":      strings.ReplaceAll(goodConfigFile, "PORTABLEFS_ARCHIVE_PREFIX=cells/cell-a", "PORTABLEFS_ARCHIVE_PREFIX=/cells/cell-a"),
		"relative prefix":      strings.ReplaceAll(goodConfigFile, "PORTABLEFS_ARCHIVE_PREFIX=cells/cell-a", "PORTABLEFS_ARCHIVE_PREFIX=cells/../etc"),
		"bad bucket":           strings.ReplaceAll(goodConfigFile, "PORTABLEFS_ARCHIVE_BUCKET=portablefs-archive", "PORTABLEFS_ARCHIVE_BUCKET=-nope-"),
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfigFile(writeConfigFile(t, contents, 0o600)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestLoadConfigFilePermissionAndPathChecks(t *testing.T) {
	t.Run("group readable", func(t *testing.T) {
		if _, err := LoadConfigFile(writeConfigFile(t, goodConfigFile, 0o640)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected ErrInvalid for a group-readable credential file, got %v", err)
		}
	})
	t.Run("world readable", func(t *testing.T) {
		if _, err := LoadConfigFile(writeConfigFile(t, goodConfigFile, 0o604)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected ErrInvalid for a world-readable credential file, got %v", err)
		}
	})
	t.Run("relative path", func(t *testing.T) {
		if _, err := LoadConfigFile("cell-archive.env"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected ErrInvalid for a relative path, got %v", err)
		}
	})
	t.Run("unclean path", func(t *testing.T) {
		if _, err := LoadConfigFile("/etc/portablefs/../portablefs/cells/x.env"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected ErrInvalid for an unclean path, got %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "real.env")
		if err := os.WriteFile(target, []byte(goodConfigFile), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		link := filepath.Join(directory, "link.env")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if _, err := LoadConfigFile(link); err == nil {
			t.Fatal("expected O_NOFOLLOW to refuse a symlinked credential file")
		}
	})
	t.Run("directory", func(t *testing.T) {
		if _, err := LoadConfigFile(t.TempDir()); err == nil {
			t.Fatal("expected a directory to be refused")
		}
	})
	t.Run("missing", func(t *testing.T) {
		if _, err := LoadConfigFile(filepath.Join(t.TempDir(), "absent.env")); err == nil {
			t.Fatal("expected a missing file to be refused")
		}
	})
	t.Run("oversized", func(t *testing.T) {
		padding := strings.Repeat("# padding padding padding padding padding padding\n", 2000)
		if _, err := LoadConfigFile(writeConfigFile(t, goodConfigFile+padding, 0o600)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected ErrInvalid for an oversized file, got %v", err)
		}
	})
}

func TestConfigValidation(t *testing.T) {
	base := func() Config {
		return Config{
			Endpoint:           "https://objects.example.internal",
			Region:             "us-west-2",
			Bucket:             "portablefs-archive",
			AccessKeyID:        "AKIA",
			SecretAccessKey:    "secret",
			ChecksumCapability: ChecksumNone,
			PathStyle:          true,
		}
	}
	baseline := base()
	if err := baseline.validate(); err != nil {
		t.Fatalf("base config rejected: %v", err)
	}
	t.Run("loopback http is admitted", func(t *testing.T) {
		config := base()
		config.Endpoint = "http://127.0.0.1:9000"
		if err := config.validate(); err != nil {
			t.Fatalf("loopback http rejected: %v", err)
		}
		config.Endpoint = "http://localhost:9000"
		if err := config.validate(); err != nil {
			t.Fatalf("localhost http rejected: %v", err)
		}
	})
	mutations := map[string]func(*Config){
		"non-loopback http":         func(c *Config) { c.Endpoint = "http://objects.example.internal" },
		"unknown scheme":            func(c *Config) { c.Endpoint = "s3://objects.example.internal" },
		"endpoint with query":       func(c *Config) { c.Endpoint = "https://objects.example.internal?x=1" },
		"endpoint with credentials": func(c *Config) { c.Endpoint = "https://user:pass@objects.example.internal" },
		"empty region":              func(c *Config) { c.Region = "" },
		"uppercase region":          func(c *Config) { c.Region = "US-WEST-2" },
		"short bucket":              func(c *Config) { c.Bucket = "ab" },
		"ip bucket":                 func(c *Config) { c.Bucket = "192.168.0.1" },
		"double dot bucket":         func(c *Config) { c.Bucket = "a..b" },
		"dotted virtual host":       func(c *Config) { c.Bucket = "a.b.c"; c.PathStyle = false },
		"ip endpoint virtual host":  func(c *Config) { c.Endpoint = "https://10.0.0.1"; c.PathStyle = false },
		"no access key":             func(c *Config) { c.AccessKeyID = "" },
		"no secret":                 func(c *Config) { c.SecretAccessKey = "" },
		"space in secret":           func(c *Config) { c.SecretAccessKey = "a b" },
		"bad capability":            func(c *Config) { c.ChecksumCapability = "crc32" },
		"too many attempts":         func(c *Config) { c.MaxAttempts = 11 },
		"negative attempts":         func(c *Config) { c.MaxAttempts = -1 },
		"inverted retry delays":     func(c *Config) { c.RetryBaseDelay = time.Minute; c.RetryMaxDelay = time.Second },
		"negative timeout":          func(c *Config) { c.Timeouts.Dial = -time.Second },
		"prefix with a slash":       func(c *Config) { c.KeyPrefix = "a//b" },
		"prefix with a space":       func(c *Config) { c.KeyPrefix = "a b" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			config := base()
			mutate(&config)
			if err := config.validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
			if _, err := New(config); !errors.Is(err, ErrInvalid) {
				t.Fatalf("New accepted an invalid config: %v", err)
			}
		})
	}
}

func TestConfigDefaultsAndRedaction(t *testing.T) {
	client, err := New(Config{
		Endpoint:           "http://127.0.0.1:9000",
		Region:             "us-west-2",
		Bucket:             "portablefs-archive",
		AccessKeyID:        "AKIA",
		SecretAccessKey:    "secret",
		SessionToken:       "token",
		ChecksumCapability: ChecksumCRC64NVMEFullObject,
		PathStyle:          true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	config := client.Config()
	if config.MaxAttempts != DefaultMaxAttempts || config.RetryBaseDelay != DefaultRetryBaseDelay ||
		config.RetryMaxDelay != DefaultRetryMaxDelay || config.Timeouts.Request != DefaultRequestTimeout ||
		config.Timeouts.Dial != DefaultDialTimeout || config.Timeouts.ResponseHeader != DefaultResponseHeaderTimeout ||
		config.Timeouts.TLSHandshake != DefaultTLSHandshakeTimeout || config.Timeouts.IdleConnection != DefaultIdleConnectionTimeout {
		t.Fatalf("defaults were not applied: %+v", config)
	}
	if config.AccessKeyID != "[redacted]" || config.SecretAccessKey != "[redacted]" || config.SessionToken != "[redacted]" {
		t.Fatalf("Config() leaked credentials: %+v", config)
	}
	if !client.ChecksumsEnabled() {
		t.Fatal("checksums should be enabled")
	}
}
