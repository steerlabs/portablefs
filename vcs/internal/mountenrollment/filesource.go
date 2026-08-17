package mountenrollment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	"golang.org/x/sys/unix"
)

// maxCredentialFileBytes is the capability bound the authority itself enforces.
// Reading further would only produce a token the authority refuses.
const maxCredentialFileBytes = 8192

// FileGrantSource is the GrantSource for a mount whose credentials are rotated
// in place, in the same file the mount was started with, by whatever external
// credential manager owns them. It is the standalone counterpart of the
// Manager-facing Client: same one-method contract, same monotonic sequence,
// and no second credential path — the mount re-reads the exact file it already
// depends on.
//
// A reauthorization capability is bound to this session and to one exact
// sequence, so an unrotated file is not a grant this source can present: it
// returns the credential manager's failure to install the next sequence as an
// ordinary retryable error. That is the whole fail-closed story. The Renewer
// retries until its safe cutoff and then ends the mount while the installed
// authorization is still valid, which is what a mount whose credentials nobody
// rotates must do.
//
// Every refusal here is retryable on purpose. A rotation that arrives late is
// indistinguishable from one that never arrives until the cutoff decides, and
// no local inspection of an unsigned token is evidence strong enough to end a
// live mount earlier than that.
type FileGrantSource struct {
	path     string
	volumeID string
	now      func() time.Time

	mu sync.Mutex
	// access is the ceiling this source will present, which is the access the
	// authority currently has recorded for the session: the attach capability's
	// access, narrowed by every grant since. The authority fences a session that
	// is offered broadened access, so a mount must never offer it.
	access []string
	// pinned is the grant already presented for pinnedSequence. The authority
	// treats a repeat of one sequence as an idempotent retry only when the token
	// is byte-identical and fences a changed one, so a retry after a lost
	// response must present exactly what the first attempt did — the same
	// durability the Manager's idempotency key gives the hosted path.
	pinned         controlplane.MountAuthorization
	pinnedSequence uint64
}

// NewFileGrantSource binds a source to the capability file the mount was
// started with. The attach capability the mount already read supplies the
// volume and the initial access ceiling: those come from the credential this
// session was actually admitted on, never from a flag that could disagree with
// it.
func NewFileGrantSource(path string, attachCapability []byte, now func() time.Time) (*FileGrantSource, error) {
	if path == "" || len(attachCapability) == 0 {
		return nil, errors.New("a capability file path and the attach capability are required")
	}
	claims, err := volumecap.Inspect(attachCapability)
	if err != nil {
		return nil, fmt.Errorf("inspect attach capability: %w", err)
	}
	if claims.VolumeID == "" || !usableAccess(claims.Access) {
		return nil, errors.New("attach capability declares no volume or no usable access")
	}
	if claims.SessionID != "" || claims.Sequence != 0 {
		return nil, errors.New("an attach capability must not be session bound")
	}
	if now == nil {
		now = time.Now
	}
	return &FileGrantSource{
		path: path, volumeID: claims.VolumeID, now: now,
		access: append([]string(nil), claims.Access...),
	}, nil
}

// Refresh returns the grant the credential manager installed for this exact
// session and sequence. The deadline it reports is the capability's own stated
// expiry, which is the deadline the authority installs from the same bytes; the
// Renewer compares the two and refuses any disagreement.
func (source *FileGrantSource) Refresh(_ context.Context, sessionID string, sequence uint64) (controlplane.MountAuthorization, error) {
	if source == nil || sessionID == "" || sequence == 0 {
		return controlplane.MountAuthorization{}, errors.New("complete mount refresh identity is required")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if sequence == source.pinnedSequence {
		return source.pinned, nil
	}
	if sequence != source.pinnedSequence+1 {
		return controlplane.MountAuthorization{}, fmt.Errorf("rotated capability sequence %d does not follow %d", sequence, source.pinnedSequence)
	}
	token, err := readCapabilityFile(source.path)
	if err != nil {
		return controlplane.MountAuthorization{}, fmt.Errorf("read rotated capability %s: %w", source.path, err)
	}
	claims, err := volumecap.Inspect(token)
	if err != nil {
		return controlplane.MountAuthorization{}, fmt.Errorf("inspect rotated capability %s: %w", source.path, err)
	}
	if claims.VolumeID != source.volumeID {
		return controlplane.MountAuthorization{}, fmt.Errorf("rotated capability names volume %q, this mount serves %q", claims.VolumeID, source.volumeID)
	}
	if claims.SessionID != sessionID || claims.Sequence != sequence {
		return controlplane.MountAuthorization{}, fmt.Errorf(
			"rotated capability is bound to session %q sequence %d; this mount needs session %q sequence %d",
			claims.SessionID, claims.Sequence, sessionID, sequence)
	}
	if !productauth.Allows(source.access, claims.Access) {
		return controlplane.MountAuthorization{}, fmt.Errorf(
			"rotated capability broadens access from %s to %s; the authority fences a session that is offered more than it holds",
			strings.Join(source.access, "+"), strings.Join(claims.Access, "+"))
	}
	if claims.Expires <= source.now().Unix() {
		return controlplane.MountAuthorization{}, errors.New("rotated capability has already expired")
	}
	source.pinned = controlplane.MountAuthorization{
		VolumeID: source.volumeID, Capability: string(token), Access: append([]string(nil), claims.Access...),
		ExpiresUnix: claims.Expires, SessionID: sessionID, Sequence: sequence,
	}
	source.pinnedSequence = sequence
	source.access = append([]string(nil), claims.Access...)
	return source.pinned, nil
}

// usableAccess reports whether an access set is one the authority's lattice
// recognises. productauth.Allows is that lattice, and a set allows itself
// exactly when it is non-empty and every permission in it is a real one.
func usableAccess(access []string) bool { return productauth.Allows(access, access) }

// readCapabilityFile reads one credential with the same discipline the mount
// applies at startup: a real file, unreadable by group and other, opened
// without following a symlink, and bounded.
func readCapabilityFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("capability file could not be adopted")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("credential must be a regular file unreadable by group and other users")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxCredentialFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxCredentialFileBytes {
		return nil, errors.New("credential exceeds the capability bound")
	}
	token := []byte(strings.TrimSpace(string(raw)))
	if len(token) == 0 {
		return nil, errors.New("credential file is empty")
	}
	return token, nil
}
