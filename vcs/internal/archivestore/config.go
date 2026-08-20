package archivestore

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ChecksumCapability declares what the configured store can prove about object
// integrity without a download. It is deployment configuration, never a runtime
// probe: a store that silently stops honouring the declaration must fail
// verification loudly rather than be downgraded behind the operator's back.
type ChecksumCapability string

const (
	// ChecksumCRC64NVMEFullObject requires FULL_OBJECT CRC64NVME uploads and a
	// checksum-bearing HeadObject.
	ChecksumCRC64NVMEFullObject ChecksumCapability = "crc64nvme-full-object"
	// ChecksumNone declares a store with no comparable object checksum;
	// verification then covers presence and size only.
	ChecksumNone ChecksumCapability = "none"
)

// Timeouts bound every phase of a request. Zero means the documented default.
type Timeouts struct {
	// Dial bounds TCP connection establishment.
	Dial time.Duration
	// TLSHandshake bounds the TLS handshake.
	TLSHandshake time.Duration
	// ResponseHeader bounds the wait for response headers after the request
	// body has been written. It is the only bound that applies to a streaming
	// ranged GET, whose body lifetime belongs to the caller's context.
	ResponseHeader time.Duration
	// Request bounds a complete buffered operation, body included. It is not
	// applied to GetObjectRange.
	Request time.Duration
	// IdleConnection bounds how long a pooled connection is kept.
	IdleConnection time.Duration
}

// Config is the complete archive-store configuration. It is root-provisioned
// cell configuration (hosted-cell-deployment.md); no field is ever selected by
// a signed plan or by any network input.
type Config struct {
	// Endpoint is the store's origin: scheme and host only, no path, query, or
	// fragment. Plain http is accepted only for loopback hosts, which is what
	// the fake-server and MinIO test paths use.
	Endpoint string
	// Region is the SigV4 region. MinIO deployments conventionally use
	// "us-east-1".
	Region string
	// Bucket is the target bucket.
	Bucket string
	// KeyPrefix is the root-pinned prefix under which every key is derived. It
	// may be empty, and never has a leading or trailing slash.
	KeyPrefix string

	AccessKeyID     string
	SecretAccessKey string
	// SessionToken is optional; when set it is sent and signed as
	// x-amz-security-token.
	SessionToken string

	ChecksumCapability ChecksumCapability
	// PathStyle addresses the bucket as a path element rather than a virtual
	// host. True for MinIO and for any IP-literal endpoint.
	PathStyle bool

	// MaxAttempts bounds total attempts per operation, retries included.
	// Zero means DefaultMaxAttempts; the accepted range is 1..10.
	MaxAttempts int
	// RetryBaseDelay is the first backoff step. Zero means
	// DefaultRetryBaseDelay; the delay doubles per attempt, is capped at
	// RetryMaxDelay, and is fully jittered.
	RetryBaseDelay time.Duration
	// RetryMaxDelay caps one backoff step. Zero means DefaultRetryMaxDelay.
	RetryMaxDelay time.Duration

	Timeouts Timeouts
}

// Defaults applied to a zero-valued knob.
const (
	DefaultMaxAttempts           = 4
	DefaultRetryBaseDelay        = 100 * time.Millisecond
	DefaultRetryMaxDelay         = 5 * time.Second
	DefaultDialTimeout           = 10 * time.Second
	DefaultTLSHandshakeTimeout   = 10 * time.Second
	DefaultResponseHeaderTimeout = 60 * time.Second
	DefaultRequestTimeout        = 120 * time.Second
	DefaultIdleConnectionTimeout = 90 * time.Second

	maxKeyPrefixBytes  = 256
	maxConfigFileBytes = 64 << 10
	// maxRetryAfterDelay bounds an attacker- or misconfiguration-supplied
	// Retry-After: an unbounded honoured hint is a denial of service.
	maxRetryAfterDelay = 30 * time.Second
)

// Environment keys of the root-provisioned archive configuration file
// (/etc/portablefs/cells/<cell-uuid>-archive.env, root 0600).
const (
	envEndpoint           = "PORTABLEFS_ARCHIVE_ENDPOINT"
	envRegion             = "PORTABLEFS_ARCHIVE_REGION"
	envBucket             = "PORTABLEFS_ARCHIVE_BUCKET"
	envPrefix             = "PORTABLEFS_ARCHIVE_PREFIX"
	envAccessKeyID        = "PORTABLEFS_ARCHIVE_ACCESS_KEY_ID"
	envSecretAccessKey    = "PORTABLEFS_ARCHIVE_SECRET_ACCESS_KEY"
	envSessionToken       = "PORTABLEFS_ARCHIVE_SESSION_TOKEN"
	envChecksumCapability = "PORTABLEFS_ARCHIVE_CHECKSUM_CAPABILITY"
	envPathStyle          = "PORTABLEFS_ARCHIVE_PATH_STYLE"
)

// LoadConfigFile reads a root-provisioned key=value configuration file.
//
// The file must be a regular file owned by root or by the effective user,
// unreadable by group and other, no larger than 64 KiB, and reached without
// traversing a symlink at the final component. Unknown keys, duplicate keys,
// quoted values, and control characters are all refused: this file carries
// credentials, so anything not exactly understood is a configuration error
// rather than something to interpret generously.
//
// Retry and timeout knobs are deliberately not loadable; they are code
// defaults or programmatic overrides, keeping the credential file minimal.
func LoadConfigFile(path string) (Config, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Config{}, fmt.Errorf("%w: config path must be clean and absolute", ErrInvalid)
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Config{}, fmt.Errorf("open archive config: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return Config{}, errors.New("archivestore: open archive config returned no file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat archive config: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		(stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || info.Size() > maxConfigFileBytes {
		return Config{}, fmt.Errorf("%w: archive config must be a private regular file owned by root or the effective user", ErrInvalid)
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read archive config: %w", err)
	}
	if len(payload) > maxConfigFileBytes {
		return Config{}, fmt.Errorf("%w: archive config exceeds %d bytes", ErrInvalid, maxConfigFileBytes)
	}
	return parseConfigFile(string(payload))
}

func parseConfigFile(contents string) (Config, error) {
	values := make(map[string]string, 9)
	for number, line := range strings.Split(contents, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.TrimSpace(line) != line {
			return Config{}, fmt.Errorf("%w: archive config line %d has surrounding whitespace", ErrInvalid, number+1)
		}
		name, value, found := strings.Cut(line, "=")
		if !found || !validEnvName(name) {
			return Config{}, fmt.Errorf("%w: archive config line %d is not KEY=VALUE", ErrInvalid, number+1)
		}
		if !knownEnvKey(name) {
			return Config{}, fmt.Errorf("%w: archive config has unknown key %q", ErrInvalid, name)
		}
		if _, duplicate := values[name]; duplicate {
			return Config{}, fmt.Errorf("%w: archive config repeats key %q", ErrInvalid, name)
		}
		if !validEnvValue(value) {
			return Config{}, fmt.Errorf("%w: archive config value for %q is quoted or contains control characters", ErrInvalid, name)
		}
		values[name] = value
	}
	for _, required := range []string{envEndpoint, envRegion, envBucket, envAccessKeyID, envSecretAccessKey, envChecksumCapability} {
		if values[required] == "" {
			return Config{}, fmt.Errorf("%w: archive config is missing %s", ErrInvalid, required)
		}
	}
	config := Config{
		Endpoint:           values[envEndpoint],
		Region:             values[envRegion],
		Bucket:             values[envBucket],
		KeyPrefix:          values[envPrefix],
		AccessKeyID:        values[envAccessKeyID],
		SecretAccessKey:    values[envSecretAccessKey],
		SessionToken:       values[envSessionToken],
		ChecksumCapability: ChecksumCapability(values[envChecksumCapability]),
	}
	switch pathStyle, present := values[envPathStyle]; {
	case !present, pathStyle == "false":
		config.PathStyle = false
	case pathStyle == "true":
		config.PathStyle = true
	default:
		return Config{}, fmt.Errorf("%w: %s must be exactly \"true\" or \"false\"", ErrInvalid, envPathStyle)
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func knownEnvKey(name string) bool {
	switch name {
	case envEndpoint, envRegion, envBucket, envPrefix, envAccessKeyID,
		envSecretAccessKey, envSessionToken, envChecksumCapability, envPathStyle:
		return true
	default:
		return false
	}
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func validEnvValue(value string) bool {
	if strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

// validate applies every configuration rule and fills in no defaults; New
// normalizes afterwards. Validation is total: a Config that passes here can
// address every operation this package performs.
func (c *Config) validate() error {
	endpoint, err := url.Parse(c.Endpoint)
	if err != nil {
		return fmt.Errorf("%w: endpoint is not a URL", ErrInvalid)
	}
	if endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") {
		return fmt.Errorf("%w: endpoint must be scheme://host[:port] with no path, query, or fragment", ErrInvalid)
	}
	switch endpoint.Scheme {
	case "https":
	case "http":
		// Plain http would carry the SigV4 credential scope and the archive
		// bytes in the clear; it is admitted only for loopback, which covers
		// the fake-server suite and a local MinIO.
		if !loopbackHost(endpoint.Hostname()) {
			return fmt.Errorf("%w: http endpoints are accepted only for loopback hosts", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: endpoint scheme must be https or http", ErrInvalid)
	}
	if !validRegion(c.Region) {
		return fmt.Errorf("%w: region must be 1..64 characters of [a-z0-9-]", ErrInvalid)
	}
	if !validBucket(c.Bucket) {
		return fmt.Errorf("%w: bucket name is not a valid S3 bucket name", ErrInvalid)
	}
	if !c.PathStyle && strings.Contains(c.Bucket, ".") {
		// A dotted bucket in virtual-host style needs a multi-label wildcard
		// certificate; refuse rather than fail the handshake at upload time.
		return fmt.Errorf("%w: virtual-host addressing requires a bucket name without dots", ErrInvalid)
	}
	if !c.PathStyle && net.ParseIP(endpoint.Hostname()) != nil {
		return fmt.Errorf("%w: an IP-literal endpoint requires path-style addressing", ErrInvalid)
	}
	if err := validateKeyPrefix(c.KeyPrefix); err != nil {
		return err
	}
	if !validCredentialText(c.AccessKeyID, 128) || !validCredentialText(c.SecretAccessKey, 256) {
		return fmt.Errorf("%w: access key ID and secret access key must be non-empty printable ASCII", ErrInvalid)
	}
	if c.SessionToken != "" && !validCredentialText(c.SessionToken, 4096) {
		return fmt.Errorf("%w: session token must be printable ASCII", ErrInvalid)
	}
	switch c.ChecksumCapability {
	case ChecksumCRC64NVMEFullObject, ChecksumNone:
	default:
		return fmt.Errorf("%w: checksum capability must be %q or %q", ErrInvalid, ChecksumCRC64NVMEFullObject, ChecksumNone)
	}
	if c.MaxAttempts < 0 || c.MaxAttempts > 10 {
		return fmt.Errorf("%w: max attempts must be within 1..10", ErrInvalid)
	}
	if c.RetryBaseDelay < 0 || c.RetryMaxDelay < 0 || (c.RetryBaseDelay > 0 && c.RetryMaxDelay > 0 && c.RetryBaseDelay > c.RetryMaxDelay) {
		return fmt.Errorf("%w: retry delays must be non-negative and ordered", ErrInvalid)
	}
	timeouts := []time.Duration{c.Timeouts.Dial, c.Timeouts.TLSHandshake, c.Timeouts.ResponseHeader, c.Timeouts.Request, c.Timeouts.IdleConnection}
	for _, timeout := range timeouts {
		if timeout < 0 {
			return fmt.Errorf("%w: timeouts must be non-negative", ErrInvalid)
		}
	}
	return nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func validRegion(region string) bool {
	if region == "" || len(region) > 64 {
		return false
	}
	for i := 0; i < len(region); i++ {
		c := region[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validBucket(bucket string) bool {
	if len(bucket) < 3 || len(bucket) > 63 {
		return false
	}
	if strings.Contains(bucket, "..") || net.ParseIP(bucket) != nil {
		return false
	}
	for i := 0; i < len(bucket); i++ {
		c := bucket[i]
		alphanumeric := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alphanumeric && c != '-' && c != '.' {
			return false
		}
		if (i == 0 || i == len(bucket)-1) && !alphanumeric {
			return false
		}
	}
	return true
}

// validateKeyPrefix accepts the empty prefix and otherwise requires a clean,
// relative, slash-separated path of conservative segments. No leading or
// trailing slash, no empty segment, no "." or "..": the prefix is pinned by
// root configuration and must derive exactly one key per identity tuple.
func validateKeyPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if len(prefix) > maxKeyPrefixBytes {
		return fmt.Errorf("%w: key prefix exceeds %d bytes", ErrInvalid, maxKeyPrefixBytes)
	}
	if strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") {
		return fmt.Errorf("%w: key prefix must not begin or end with a slash", ErrInvalid)
	}
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("%w: key prefix has an empty or relative segment", ErrInvalid)
		}
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return fmt.Errorf("%w: key prefix segment %q has a disallowed character", ErrInvalid, segment)
			}
		}
	}
	return nil
}

func validCredentialText(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func (c *Config) withDefaults() Config {
	normalized := *c
	if normalized.MaxAttempts == 0 {
		normalized.MaxAttempts = DefaultMaxAttempts
	}
	if normalized.RetryBaseDelay == 0 {
		normalized.RetryBaseDelay = DefaultRetryBaseDelay
	}
	if normalized.RetryMaxDelay == 0 {
		normalized.RetryMaxDelay = DefaultRetryMaxDelay
	}
	if normalized.RetryMaxDelay < normalized.RetryBaseDelay {
		normalized.RetryMaxDelay = normalized.RetryBaseDelay
	}
	if normalized.Timeouts.Dial == 0 {
		normalized.Timeouts.Dial = DefaultDialTimeout
	}
	if normalized.Timeouts.TLSHandshake == 0 {
		normalized.Timeouts.TLSHandshake = DefaultTLSHandshakeTimeout
	}
	if normalized.Timeouts.ResponseHeader == 0 {
		normalized.Timeouts.ResponseHeader = DefaultResponseHeaderTimeout
	}
	if normalized.Timeouts.Request == 0 {
		normalized.Timeouts.Request = DefaultRequestTimeout
	}
	if normalized.Timeouts.IdleConnection == 0 {
		normalized.Timeouts.IdleConnection = DefaultIdleConnectionTimeout
	}
	return normalized
}
