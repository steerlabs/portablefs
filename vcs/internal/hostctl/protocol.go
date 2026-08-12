// Package hostctl defines the private, account-local update protocol between
// the macOS installer CLI and the exact installed PortableFS host app.
package hostctl

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

const (
	SchemaVersion = 1
	MaxFrameBytes = 4096
	SocketName    = "update.sock"
	LeaseName     = "activation.json"
	LeaseLifetime = 5 * time.Minute
)

const (
	PhasePreparingOld     = "preparing-old"
	PhaseOldAbsent        = "old-absent"
	PhaseTargetReady      = "target-ready"
	PhaseTargetActive     = "target-active"
	PhaseRollbackAbsent   = "rollback-absent"
	PhaseRollbackReady    = "rollback-ready"
	PhaseRollbackActive   = "rollback-active"
	PhaseTargetComplete   = "target-complete"
	PhaseRollbackComplete = "rollback-complete"
)

type ReleaseIdentity struct {
	CodeDirectoryHash string `json:"codeDirectoryHash"`
	ExecutableSHA256  string `json:"executableSHA256"`
	DaemonVersion     string `json:"daemonVersion"`
	IdentitySchema    int    `json:"identitySchema"`
	ControlProtocol   int    `json:"controlProtocol"`
	PFSLocalMajor     uint32 `json:"pfslocalMajor"`
	PFSLocalMinor     uint32 `json:"pfslocalMinor"`
}

type PrepareRequest struct {
	SchemaVersion int             `json:"schemaVersion"`
	Operation     string          `json:"operation"`
	TargetRelease ReleaseIdentity `json:"targetRelease"`
}

type PreparedReply struct {
	SchemaVersion int             `json:"schemaVersion"`
	State         string          `json:"state"`
	Token         string          `json:"token"`
	HostPID       int             `json:"hostPid"`
	OldRelease    ReleaseIdentity `json:"oldRelease"`
	TargetRelease ReleaseIdentity `json:"targetRelease"`
}

type FinishRequest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Operation     string `json:"operation"`
	Token         string `json:"token"`
}

type FinishReply struct {
	SchemaVersion int    `json:"schemaVersion"`
	State         string `json:"state"`
	Token         string `json:"token"`
}

type ActivationRequest struct {
	SchemaVersion int             `json:"schemaVersion"`
	Operation     string          `json:"operation"`
	Token         string          `json:"token"`
	Release       ReleaseIdentity `json:"release"`
}

type ActivationReply struct {
	SchemaVersion int             `json:"schemaVersion"`
	State         string          `json:"state"`
	Token         string          `json:"token"`
	HostPID       int             `json:"hostPid"`
	Release       ReleaseIdentity `json:"release"`
	Error         string          `json:"error,omitempty"`
}

// ActivationResumeRequest reconnects the in-memory token holder to one exact
// durable active phase after the original accept acknowledgement was lost.
// Both release sides are carried so an active lease from another transaction
// can never be resumed by matching only the currently running binary.
type ActivationResumeRequest struct {
	SchemaVersion int             `json:"schemaVersion"`
	Operation     string          `json:"operation"`
	Token         string          `json:"token"`
	Release       ReleaseIdentity `json:"release"`
	OldRelease    ReleaseIdentity `json:"oldRelease"`
	TargetRelease ReleaseIdentity `json:"targetRelease"`
}

type ActivationResumeReply struct {
	SchemaVersion int             `json:"schemaVersion"`
	State         string          `json:"state"`
	Token         string          `json:"token"`
	HostPID       int             `json:"hostPid"`
	Release       ReleaseIdentity `json:"release"`
}

type ActivationDecision struct {
	SchemaVersion int    `json:"schemaVersion"`
	Operation     string `json:"operation"`
	Token         string `json:"token"`
}

type ActivationDecisionReply struct {
	SchemaVersion int    `json:"schemaVersion"`
	State         string `json:"state"`
	Token         string `json:"token"`
}

type CompletionRequest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Operation     string `json:"operation"`
	Token         string `json:"token"`
}

type CompletionReply struct {
	SchemaVersion int    `json:"schemaVersion"`
	State         string `json:"state"`
	Token         string `json:"token"`
}

// ActivationLease is the exact durable handoff between three distinct host
// processes: the old release, the target release, and (only on rollback) the
// restored old release. TokenSHA256 is the only token material persisted.
type ActivationLease struct {
	SchemaVersion   int             `json:"schemaVersion"`
	Phase           string          `json:"phase"`
	TokenSHA256     string          `json:"tokenSHA256"`
	OldRelease      ReleaseIdentity `json:"oldRelease"`
	TargetRelease   ReleaseIdentity `json:"targetRelease"`
	CreatedAtUnixMS int64           `json:"createdAtUnixMs"`
	DeadlineUnixMS  int64           `json:"deadlineUnixMs"`
}

func SocketPath(accountHome string) string {
	return filepath.Join(accountHome, ".local", "state", "portablefs", "host", SocketName)
}

func LeasePath(accountHome string) string {
	return filepath.Join(accountHome, ".local", "state", "portablefs", "host", LeaseName)
}

func NewPrepareRequest(target ReleaseIdentity) (PrepareRequest, error) {
	if err := ValidateReleaseIdentity(target); err != nil {
		return PrepareRequest{}, fmt.Errorf("invalid target release: %w", err)
	}
	return PrepareRequest{
		SchemaVersion: SchemaVersion,
		Operation:     "prepare-update",
		TargetRelease: target,
	}, nil
}

func NewFinishRequest(operation, token string) (FinishRequest, error) {
	if operation != "commit-exit" && operation != "cancel" {
		return FinishRequest{}, fmt.Errorf("unsupported host update operation %q", operation)
	}
	if !ValidToken(token) {
		return FinishRequest{}, fmt.Errorf("invalid host update token")
	}
	return FinishRequest{SchemaVersion: SchemaVersion, Operation: operation, Token: token}, nil
}

func ValidToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(token)
	return err == nil && len(decoded) == 32 && token == string(bytes.ToLower([]byte(token)))
}

func TokenSHA256(token string) (string, error) {
	if !ValidToken(token) {
		return "", fmt.Errorf("invalid host update token")
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), nil
}

func TokenMatchesSHA256(token, expected string) bool {
	actual, err := TokenSHA256(token)
	if err != nil || !validLowerHex(expected, sha256.Size*2) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func ValidateReleaseIdentity(identity ReleaseIdentity) error {
	if !validLowerHex(identity.CodeDirectoryHash, 40) {
		return fmt.Errorf("code directory hash is not exact lowercase 20-byte hex")
	}
	if !validLowerHex(identity.ExecutableSHA256, sha256.Size*2) {
		return fmt.Errorf("executable SHA-256 is not exact lowercase 32-byte hex")
	}
	if len(identity.DaemonVersion) == 0 || len(identity.DaemonVersion) > 128 ||
		strings.IndexFunc(identity.DaemonVersion, func(r rune) bool {
			return r < 0x21 || r > 0x7e
		}) >= 0 {
		return fmt.Errorf("daemon version is not bounded printable ASCII")
	}
	if identity.IdentitySchema <= 0 || identity.ControlProtocol <= 0 ||
		identity.PFSLocalMajor == 0 {
		return fmt.Errorf("release protocol identity is incomplete")
	}
	return nil
}

func validLowerHex(value string, exactLength int) bool {
	if len(value) != exactLength || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == exactLength/2
}

func DecodeExact[T any](frame []byte) (T, error) {
	var value T
	if len(frame) == 0 || len(frame) > MaxFrameBytes {
		return value, fmt.Errorf("host update frame size is outside 1..%d bytes", MaxFrameBytes)
	}
	if err := validateUniqueJSON(frame); err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return value, fmt.Errorf("host update frame contains malformed trailing bytes: %w", err)
		}
		return value, fmt.Errorf("host update frame contains trailing JSON")
	}
	return value, nil
}

func validateUniqueJSON(frame []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	if err := validateUniqueJSONValue(decoder, 0); err != nil {
		return fmt.Errorf("invalid exact host update JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid exact host update JSON: trailing JSON value")
		}
		return fmt.Errorf("invalid exact host update JSON trailing bytes: %w", err)
	}
	return nil
}

func validateUniqueJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("JSON nesting exceeds 32")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			rawKey, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := rawKey.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			keys[key] = struct{}{}
			if err := validateUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("object is not exactly terminated")
		}
	case '[':
		for decoder.More() {
			if err := validateUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("array is not exactly terminated")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func ValidatePrepared(
	reply PreparedReply,
	peerPID int,
	expectedOld ReleaseIdentity,
	expectedTarget ReleaseIdentity,
) error {
	if reply.SchemaVersion != SchemaVersion || reply.State != "prepared" ||
		!ValidToken(reply.Token) || reply.HostPID <= 0 || reply.HostPID != peerPID ||
		reply.OldRelease != expectedOld || reply.TargetRelease != expectedTarget {
		return fmt.Errorf("invalid host prepared reply")
	}
	if err := ValidateReleaseIdentity(reply.OldRelease); err != nil {
		return fmt.Errorf("invalid old release in prepared reply: %w", err)
	}
	if err := ValidateReleaseIdentity(reply.TargetRelease); err != nil {
		return fmt.Errorf("invalid target release in prepared reply: %w", err)
	}
	return nil
}

func ValidateFinish(reply FinishReply, state, token string) error {
	if reply.SchemaVersion != SchemaVersion || reply.State != state || reply.Token != token {
		return fmt.Errorf("invalid host %s reply", state)
	}
	return nil
}

func NewActivationRequest(
	operation, token string,
	release ReleaseIdentity,
) (ActivationRequest, error) {
	if operation != "activate-target" && operation != "activate-rollback" {
		return ActivationRequest{}, fmt.Errorf("unsupported activation operation %q", operation)
	}
	if !ValidToken(token) {
		return ActivationRequest{}, fmt.Errorf("invalid host update token")
	}
	if err := ValidateReleaseIdentity(release); err != nil {
		return ActivationRequest{}, err
	}
	return ActivationRequest{
		SchemaVersion: SchemaVersion,
		Operation:     operation,
		Token:         token,
		Release:       release,
	}, nil
}

func ValidateActivationReply(
	reply ActivationReply,
	operation, token string,
	peerPID int,
	expected ReleaseIdentity,
) (ready bool, err error) {
	wantReady := "target-ready"
	wantFenced := "target-fenced"
	if operation == "activate-rollback" {
		wantReady = "rollback-ready"
		wantFenced = "rollback-fenced"
	}
	if reply.SchemaVersion != SchemaVersion || reply.Token != token ||
		reply.HostPID != peerPID || reply.Release != expected {
		return false, fmt.Errorf("invalid host activation reply")
	}
	switch reply.State {
	case wantReady:
		if reply.Error != "" {
			return false, fmt.Errorf("ready host activation reply carried an error")
		}
		return true, nil
	case wantFenced:
		if reply.Error == "" || len(reply.Error) > 512 {
			return false, fmt.Errorf("fenced host activation reply has invalid error detail")
		}
		return false, nil
	default:
		return false, fmt.Errorf("invalid host activation state %q", reply.State)
	}
}

func NewActivationResumeRequest(
	operation, token string,
	release, oldRelease, targetRelease ReleaseIdentity,
) (ActivationResumeRequest, error) {
	if operation != "resume-target" && operation != "resume-rollback" {
		return ActivationResumeRequest{}, fmt.Errorf("unsupported activation resume operation %q", operation)
	}
	if !ValidToken(token) {
		return ActivationResumeRequest{}, fmt.Errorf("invalid host update token")
	}
	for name, identity := range map[string]ReleaseIdentity{
		"active": release,
		"old":    oldRelease,
		"target": targetRelease,
	} {
		if err := ValidateReleaseIdentity(identity); err != nil {
			return ActivationResumeRequest{}, fmt.Errorf("invalid %s release: %w", name, err)
		}
	}
	want := targetRelease
	if operation == "resume-rollback" {
		want = oldRelease
	}
	if release != want {
		return ActivationResumeRequest{}, fmt.Errorf("activation resume release does not match operation")
	}
	return ActivationResumeRequest{
		SchemaVersion: SchemaVersion,
		Operation:     operation,
		Token:         token,
		Release:       release,
		OldRelease:    oldRelease,
		TargetRelease: targetRelease,
	}, nil
}

func ValidateActivationResumeReply(
	reply ActivationResumeReply,
	operation, token string,
	peerPID int,
	expected ReleaseIdentity,
) error {
	wantState := PhaseTargetActive
	if operation == "resume-rollback" {
		wantState = PhaseRollbackActive
	}
	if reply.SchemaVersion != SchemaVersion || reply.State != wantState ||
		reply.Token != token || reply.HostPID <= 0 || reply.HostPID != peerPID ||
		reply.Release != expected {
		return fmt.Errorf("invalid host activation resume reply")
	}
	if err := ValidateReleaseIdentity(reply.Release); err != nil {
		return fmt.Errorf("invalid release in activation resume reply: %w", err)
	}
	return nil
}

func NewActivationDecision(operation, token string) (ActivationDecision, error) {
	switch operation {
	case "accept-target", "fence-target", "accept-rollback", "fence-rollback":
	default:
		return ActivationDecision{}, fmt.Errorf("unsupported activation decision %q", operation)
	}
	if !ValidToken(token) {
		return ActivationDecision{}, fmt.Errorf("invalid host update token")
	}
	return ActivationDecision{SchemaVersion: SchemaVersion, Operation: operation, Token: token}, nil
}

func ValidateActivationDecisionReply(
	reply ActivationDecisionReply,
	wantState, token string,
) error {
	if reply.SchemaVersion != SchemaVersion || reply.State != wantState || reply.Token != token {
		return fmt.Errorf("invalid host activation decision reply")
	}
	return nil
}

func NewCompletionRequest(operation, token string) (CompletionRequest, error) {
	if operation != "complete-target" && operation != "complete-rollback" {
		return CompletionRequest{}, fmt.Errorf("unsupported activation completion %q", operation)
	}
	if !ValidToken(token) {
		return CompletionRequest{}, fmt.Errorf("invalid host update token")
	}
	return CompletionRequest{SchemaVersion: SchemaVersion, Operation: operation, Token: token}, nil
}

func ValidateCompletionReply(reply CompletionReply, token string) error {
	if reply.SchemaVersion != SchemaVersion || reply.State != "complete" || reply.Token != token {
		return fmt.Errorf("invalid host activation completion reply")
	}
	return nil
}

func ValidateActivationLease(lease ActivationLease, now time.Time) error {
	if lease.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported activation lease schema %d", lease.SchemaVersion)
	}
	switch lease.Phase {
	case PhasePreparingOld, PhaseOldAbsent, PhaseTargetReady, PhaseTargetActive,
		PhaseRollbackAbsent, PhaseRollbackReady, PhaseRollbackActive,
		PhaseTargetComplete, PhaseRollbackComplete:
	default:
		return fmt.Errorf("invalid activation lease phase %q", lease.Phase)
	}
	if !validLowerHex(lease.TokenSHA256, sha256.Size*2) {
		return fmt.Errorf("invalid activation lease token hash")
	}
	if err := ValidateReleaseIdentity(lease.OldRelease); err != nil {
		return fmt.Errorf("invalid activation lease old release: %w", err)
	}
	if err := ValidateReleaseIdentity(lease.TargetRelease); err != nil {
		return fmt.Errorf("invalid activation lease target release: %w", err)
	}
	created := time.UnixMilli(lease.CreatedAtUnixMS)
	deadline := time.UnixMilli(lease.DeadlineUnixMS)
	if lease.CreatedAtUnixMS <= 0 || lease.DeadlineUnixMS <= 0 ||
		!deadline.After(created) || deadline.Sub(created) != LeaseLifetime {
		return fmt.Errorf("activation lease timestamp is invalid or expired")
	}
	if now.Before(created.Add(-time.Minute)) {
		return fmt.Errorf("activation lease timestamp is invalid or expired")
	}
	if lease.Phase != PhaseTargetComplete && lease.Phase != PhaseRollbackComplete &&
		!now.Before(deadline) {
		return fmt.Errorf("activation lease timestamp is invalid or expired")
	}
	return nil
}
