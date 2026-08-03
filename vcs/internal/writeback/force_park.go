package writeback

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	recordwal "github.com/steerlabs/portablefs/vcs/internal/wal"
	"golang.org/x/sys/unix"
)

const forceParkProofName = "force-park.json"

// ForceParkResult is the durable local proof produced for one exact abandoned
// mount transaction. JobIDs is sorted by WAL epoch. ZeroTail is true only when
// the exact store had no unclosed stream to park.
type ForceParkResult struct {
	ProofID  string
	JobIDs   []string
	ZeroTail bool
}

type forceParkProof struct {
	Version    int                 `json:"version"`
	ProofID    string              `json:"proofId"`
	VolumeID   string              `json:"volumeId"`
	Branch     string              `json:"branch"`
	MountID    string              `json:"mountId"`
	Jobs       []forceParkProofJob `json:"jobs,omitempty"`
	ZeroTail   bool                `json:"zeroTail,omitempty"`
	PreparedAt int64               `json:"preparedAtMs"`
}

type forceParkProofJob struct {
	WALEpoch uint64 `json:"walEpoch"`
	JobID    string `json:"jobId"`
}

type abandonedStream struct {
	dir            string
	epoch          uint64
	scan           *streamScan
	job            RecoveryJob
	missingJob     bool
	clean          bool
	alreadyForced  bool
	appliedThrough uint64
	// tailRecords/tailBytes are the acknowledged records this stream still owes
	// the authority, counted PER LANE — the same set laneTailFrames selects and
	// the same set the next attach's replay drains and reconciles against. See
	// RecoveryJob.PendingBasis for why the basis has to be the lane's and not the
	// global prefix's.
	tailRecords uint64
	tailBytes   uint64
}

func clearForceParkProof(dir string) error {
	path := filepath.Join(dir, forceParkProofName)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("writeback: remove consumed force-park proof: %w", err)
	}
	if err := fsyncDir(dir); err != nil {
		return fmt.Errorf("writeback: sync consumed force-park proof removal: %w", err)
	}
	return nil
}

// ForceParkAbandonedStore turns the local write-back store of a proven-dead
// owner into a durable recovery boundary without contacting the authority.
//
// The caller supplies an exact transaction proof identity (FUSE
// MountInstanceID or FSKit AttachRef). The function opens an already-existing
// store, takes engine.lock nonblockingly, and validates every stream and
// recovery registry before changing any byte. A live owner, foreign identity,
// malformed registry, or corrupt WAL is a refusal and is preserved.
func ForceParkAbandonedStore(
	stateDir string,
	volumeID string,
	branch string,
	proofID string,
	reason string,
) (ForceParkResult, error) {
	result := ForceParkResult{ProofID: proofID}
	if stateDir == "" || volumeID == "" || proofID == "" {
		return result, fmt.Errorf("writeback: state directory, volume identity, and force proof identity are required")
	}
	if len(proofID) > 1024 {
		return result, fmt.Errorf("writeback: force proof identity is too long")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "explicit forced unmount after exact owner death"
	}
	if len(reason) > 4096 {
		return result, fmt.Errorf("writeback: force-park reason is too long")
	}
	storeDir, lock, err := lockExistingStoreDir(stateDir)
	if err != nil {
		return result, err
	}
	defer func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
		_ = storeDir.Close()
	}()

	mountID, mountIDText, err := readExistingMountID(stateDir)
	if err != nil {
		return result, err
	}
	epochFloor, err := readExistingEpochFloor(stateDir)
	if err != nil {
		return result, err
	}
	priorProof, err := validatePriorForceParkProof(stateDir, proofID, volumeID, branch, mountIDText)
	if err != nil {
		return result, err
	}

	streams, err := validateAbandonedStreams(stateDir, volumeID, branch, mountID, epochFloor)
	if err != nil {
		return result, err
	}

	// Validation above is store-wide and read-only. Only now may a legitimate
	// torn final append be repaired and synchronized.
	for i := range streams {
		if streams[i].scan.truncated {
			repaired, err := scanStream(streams[i].dir)
			if err != nil {
				return result, fmt.Errorf("writeback: repair torn stream %s: %w", filepath.Base(streams[i].dir), err)
			}
			streams[i].scan = repaired
		}
	}

	var proofJobs []forceParkProofJob
	for i := range streams {
		stream := &streams[i]
		if stream.clean {
			continue
		}
		if stream.missingJob {
			if err := cleanProvablyEmptyStream(stream); err != nil {
				return result, fmt.Errorf("writeback: clean empty pre-registry stream %s: %w", filepath.Base(stream.dir), err)
			}
			continue
		}
		jobID, err := forceParkStream(stream, reason)
		if err != nil {
			return result, fmt.Errorf("writeback: force-park %s: %w", filepath.Base(stream.dir), err)
		}
		proofJobs = append(proofJobs, forceParkProofJob{WALEpoch: stream.epoch, JobID: jobID})
	}
	sort.Slice(proofJobs, func(i, j int) bool { return proofJobs[i].WALEpoch < proofJobs[j].WALEpoch })
	result.ZeroTail = len(proofJobs) == 0
	for _, job := range proofJobs {
		result.JobIDs = append(result.JobIDs, job.JobID)
	}
	preparedAt := time.Now().UnixMilli()
	if priorProof != nil {
		preparedAt = priorProof.PreparedAt
	}
	proof := forceParkProof{
		Version:    1,
		ProofID:    proofID,
		VolumeID:   volumeID,
		Branch:     branch,
		MountID:    mountIDText,
		Jobs:       proofJobs,
		ZeroTail:   result.ZeroTail,
		PreparedAt: preparedAt,
	}
	body, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return result, err
	}
	if err := writeFileAtomicDurable(filepath.Join(stateDir, forceParkProofName), append(body, '\n'), 0o600); err != nil {
		return result, fmt.Errorf("writeback: persist force-park proof: %w", err)
	}
	return result, nil
}

func lockExistingStoreDir(dir string) (*os.File, *os.File, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("writeback: inspect abandoned store %s: %w", dir, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("writeback: abandoned store %s is not a directory", dir)
	}
	namedDir, ok := info.Sys().(*syscall.Stat_t)
	if !ok || namedDir.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o022 != 0 {
		return nil, nil, fmt.Errorf("writeback: abandoned store %s is not a private current-user directory", dir)
	}
	parent, err := os.Open(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("writeback: pin abandoned store %s: %w", dir, err)
	}
	parentInfo, err := parent.Stat()
	if err != nil {
		_ = parent.Close()
		return nil, nil, fmt.Errorf("writeback: inspect pinned abandoned store %s: %w", dir, err)
	}
	pinnedDir, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || pinnedDir.Dev != namedDir.Dev || pinnedDir.Ino != namedDir.Ino {
		_ = parent.Close()
		return nil, nil, fmt.Errorf("writeback: abandoned store %s changed while it was pinned", dir)
	}

	var namedLock unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), "engine.lock", &namedLock, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		_ = parent.Close()
		return nil, nil, fmt.Errorf("writeback: inspect existing store lock %s: %w", filepath.Join(dir, "engine.lock"), err)
	}
	fd, err := unix.Openat(int(parent.Fd()), "engine.lock", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		_ = parent.Close()
		return nil, nil, fmt.Errorf("writeback: open existing store lock %s: %w", filepath.Join(dir, "engine.lock"), err)
	}
	lock := os.NewFile(uintptr(fd), filepath.Join(dir, "engine.lock"))
	if lock == nil {
		_ = unix.Close(fd)
		_ = parent.Close()
		return nil, nil, fmt.Errorf("writeback: open existing store lock %s: invalid descriptor", filepath.Join(dir, "engine.lock"))
	}
	var openedLock unix.Stat_t
	if err := unix.Fstat(fd, &openedLock); err != nil ||
		openedLock.Dev != namedLock.Dev || openedLock.Ino != namedLock.Ino ||
		openedLock.Mode&unix.S_IFMT != unix.S_IFREG ||
		openedLock.Uid != uint32(os.Geteuid()) || openedLock.Nlink != 1 ||
		openedLock.Mode&0o777 != 0o600 {
		_ = lock.Close()
		_ = parent.Close()
		return nil, nil, fmt.Errorf("writeback: existing store lock %s is not the exact sole current-user 0600 regular file", filepath.Join(dir, "engine.lock"))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		_ = parent.Close()
		return nil, nil, fmt.Errorf("writeback: store %s is owned by another engine: %w", dir, err)
	}
	var recheckedLock unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), "engine.lock", &recheckedLock, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		recheckedLock.Dev != openedLock.Dev || recheckedLock.Ino != openedLock.Ino {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = lock.Close()
		_ = parent.Close()
		return nil, nil, fmt.Errorf("writeback: existing store lock %s changed while it was pinned", filepath.Join(dir, "engine.lock"))
	}
	return parent, lock, nil
}

func readExistingMountID(dir string) ([16]byte, string, error) {
	var id [16]byte
	path := filepath.Join(dir, "mount-id")
	if err := validatePrivateCurrentUserRegular(path); err != nil {
		return id, "", fmt.Errorf("writeback: inspect abandoned store mount identity: %w", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return id, "", fmt.Errorf("writeback: read abandoned store mount identity: %w", err)
	}
	text := strings.TrimSpace(string(body))
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != len(id) || text != strings.ToLower(text) {
		return id, "", fmt.Errorf("%w: malformed mount identity %s", ErrCorrupt, path)
	}
	copy(id[:], raw)
	return id, text, nil
}

func readExistingEpochFloor(dir string) (uint64, error) {
	path := filepath.Join(dir, "wal-epoch")
	if err := validatePrivateCurrentUserRegular(path); err != nil {
		return 0, fmt.Errorf("writeback: inspect abandoned store WAL epoch: %w", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("writeback: read abandoned store WAL epoch: %w", err)
	}
	epoch, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil || epoch == 0 {
		return 0, fmt.Errorf("%w: malformed WAL epoch high-water mark %s", ErrCorrupt, path)
	}
	return epoch, nil
}

func validatePriorForceParkProof(dir, proofID, volumeID, branch, mountID string) (*forceParkProof, error) {
	path := filepath.Join(dir, forceParkProofName)
	if err := validatePrivateCurrentUserRegular(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("writeback: inspect prior force-park proof: %w", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("writeback: read prior force-park proof: %w", err)
	}
	var proof forceParkProof
	if err := decodeStrictJSON(body, &proof); err != nil {
		return nil, fmt.Errorf("%w: malformed prior force-park proof: %v", ErrCorrupt, err)
	}
	if proof.Version != 1 || proof.ProofID != proofID ||
		proof.VolumeID != volumeID || proof.Branch != branch || proof.MountID != mountID ||
		proof.ZeroTail != (len(proof.Jobs) == 0) {
		return nil, fmt.Errorf("writeback: prior force-park proof belongs to a different exact mount transaction")
	}
	var priorEpoch uint64
	for _, job := range proof.Jobs {
		if job.WALEpoch == 0 || job.WALEpoch <= priorEpoch || !validPublicJobID(job.JobID) {
			return nil, fmt.Errorf("%w: prior force-park proof has an invalid job registry", ErrCorrupt)
		}
		priorEpoch = job.WALEpoch
	}
	return &proof, nil
}

func validateAbandonedStreams(
	dir string,
	volumeID string,
	branch string,
	mountID [16]byte,
	epochFloor uint64,
) ([]abandonedStream, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("writeback: inventory abandoned store: %w", err)
	}
	var streamDirs []string
	seenEpochs := map[uint64]string{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "stream-") {
			continue
		}
		epoch, ok := streamEpochFromDir(entry.Name())
		if !ok || !entry.IsDir() || epoch == 0 {
			return nil, fmt.Errorf("%w: malformed stream registry entry %s", ErrCorrupt, entry.Name())
		}
		if prior := seenEpochs[epoch]; prior != "" {
			return nil, fmt.Errorf("%w: duplicate stream epoch %d in %s and %s", ErrCorrupt, epoch, prior, entry.Name())
		}
		seenEpochs[epoch] = entry.Name()
		streamDirs = append(streamDirs, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(streamDirs)
	streams := make([]abandonedStream, 0, len(streamDirs))
	for _, streamDir := range streamDirs {
		epoch, _ := streamEpochFromDir(filepath.Base(streamDir))
		if epoch > epochFloor {
			return nil, fmt.Errorf("%w: stream epoch %d exceeds durable high-water mark %d", ErrCorrupt, epoch, epochFloor)
		}
		if err := validatePrivateCurrentUserDir(streamDir); err != nil {
			return nil, fmt.Errorf("writeback: validate stream directory %s: %w", filepath.Base(streamDir), err)
		}
		if err := validateAbandonedStreamFiles(streamDir); err != nil {
			return nil, fmt.Errorf("writeback: validate stream files %s: %w", filepath.Base(streamDir), err)
		}
		scan, err := scanStreamReadOnly(streamDir)
		if err != nil {
			return nil, fmt.Errorf("writeback: validate stream %s: %w", filepath.Base(streamDir), err)
		}
		if scan.header.MountID != mountID || scan.header.VolumeID != volumeID ||
			scan.header.Branch != branch || scan.header.WALEpoch != epoch {
			return nil, fmt.Errorf("%w: stream %s does not match exact store identity", ErrCorrupt, filepath.Base(streamDir))
		}
		job, err := loadJobStrict(streamDir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && missingJobStreamIsProvablyEmptyOrClean(streamDir, scan) {
				streams = append(streams, abandonedStream{
					dir:        streamDir,
					epoch:      epoch,
					scan:       scan,
					missingJob: true,
					clean:      len(scan.frames) == 1,
				})
				continue
			}
			return nil, fmt.Errorf("writeback: validate recovery registry %s: %w", filepath.Base(streamDir), err)
		}
		if err := validateJobIdentity(job, scan, mountID, volumeID, branch, epoch); err != nil {
			return nil, fmt.Errorf("writeback: validate recovery registry %s: %w", filepath.Base(streamDir), err)
		}
		stream, err := analyzeAbandonedStream(streamDir, epoch, scan, job)
		if err != nil {
			return nil, fmt.Errorf("writeback: validate stream semantics %s: %w", filepath.Base(streamDir), err)
		}
		streams = append(streams, stream)
	}
	return streams, nil
}

func missingJobStreamIsProvablyEmptyOrClean(dir string, scan *streamScan) bool {
	segments, err := filepath.Glob(filepath.Join(dir, "wb-*.pfw"))
	if err != nil || len(segments) != 1 || scan == nil ||
		scan.header.Ordinal != 1 || scan.header.FirstFrame != 1 ||
		scan.header.FirstSeq != 1 || scan.lastSeq != 0 {
		return false
	}
	if len(scan.frames) == 0 {
		return true
	}
	if len(scan.frames) != 1 || scan.frames[0].typ != frameClose {
		return false
	}
	var close closeFrame
	return json.Unmarshal(scan.frames[0].payload, &close) == nil &&
		close.Through == 0 && close.JobID == ""
}

func cleanProvablyEmptyStream(stream *abandonedStream) error {
	activePath, frameNo, end, err := abandonedStreamTail(stream)
	if err != nil {
		return err
	}
	active, err := os.OpenFile(activePath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer active.Close()
	if err := active.Sync(); err != nil {
		return fmt.Errorf("sync empty WAL: %w", err)
	}
	payload, err := encodeControlPayload(closeFrame{Through: 0})
	if err != nil {
		return err
	}
	body := encodeFrame(nil, frameClose, StreamLaneLegacy, frameNo+1, 0, payload)
	n, err := active.WriteAt(body, end)
	if err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	if err != nil {
		if n > 0 {
			_ = active.Truncate(end)
		}
		return fmt.Errorf("append clean-close frame: %w", err)
	}
	if err := active.Sync(); err != nil {
		return fmt.Errorf("sync clean-close frame: %w", err)
	}
	return fsyncDir(stream.dir)
}

func loadJobStrict(streamDir string) (RecoveryJob, error) {
	var job RecoveryJob
	path := filepath.Join(streamDir, "job.json")
	if err := validatePrivateCurrentUserRegular(path); err != nil {
		return job, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return job, err
	}
	if err := decodeStrictJSON(body, &job); err != nil {
		return job, fmt.Errorf("%w: malformed job.json: %v", ErrCorrupt, err)
	}
	return job, nil
}

func validateAbandonedStreamFiles(streamDir string) error {
	entries, err := os.ReadDir(streamDir)
	if err != nil {
		return err
	}
	segmentCount := 0
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == "job.json":
			// The exact job file is validated by loadJobStrict. Keeping the
			// check there preserves os.ErrNotExist for the narrow pre-registry
			// crash shape.
		case strings.HasPrefix(name, "wb-"):
			ordinal, ok := segmentOrdinalFromName(name)
			if !ok || name != filepath.Base(segmentPath(streamDir, ordinal)) {
				return fmt.Errorf("%w: malformed segment registry entry %s", ErrCorrupt, name)
			}
			if err := validatePrivateCurrentUserRegular(filepath.Join(streamDir, name)); err != nil {
				return fmt.Errorf("%w: unsafe segment registry entry %s: %v", ErrCorrupt, name, err)
			}
			segmentCount++
		default:
			// Other known recovery files are deliberately handled by their
			// owners. They cannot be mistaken for WAL segments or job state.
		}
	}
	if segmentCount == 0 {
		return fmt.Errorf("%w: stream has no segments", ErrCorrupt)
	}
	return nil
}

func segmentOrdinalFromName(name string) (uint64, bool) {
	const (
		prefix = "wb-"
		suffix = ".pfw"
	)
	if len(name) < len(prefix)+8+len(suffix) ||
		!strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return 0, false
	}
	ordinal, err := strconv.ParseUint(name[len(prefix):len(name)-len(suffix)], 10, 64)
	if err != nil || ordinal == 0 {
		return 0, false
	}
	return ordinal, true
}

func validatePrivateCurrentUserDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is not a private current-user directory", path)
	}
	return nil
}

func validatePrivateCurrentUserRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 ||
		info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%s is not an exact sole current-user 0600 regular file", path)
	}
	return nil
}

func decodeStrictJSON(body []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return fmt.Errorf("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func validateJobIdentity(
	job RecoveryJob,
	scan *streamScan,
	mountID [16]byte,
	volumeID string,
	branch string,
	epoch uint64,
) error {
	if job.Version != 1 || !validPublicJobID(job.JobID) ||
		job.VolumeID != volumeID || job.Branch != branch ||
		job.MountID != hex.EncodeToString(mountID[:]) ||
		job.WALEpoch != epoch || job.WritebackID != streamID(mountID, epoch) {
		return fmt.Errorf("%w: job does not match exact stream identity", ErrCorrupt)
	}
	switch job.State {
	case JobActive, JobForced, JobReplaying, JobParked:
	case JobConflict, JobCorrupt:
		// TYPED, so the daemon and the CLI can name the exact command that
		// performs the resolution for the mount in hand. Until round 21b this
		// was a bare string naming a procedure that did not exist, and it closed
		// the umount/--force/--discard-record cycle with no exit at all. See
		// resolve_recovery.go.
		return fmt.Errorf(
			"%w: job %s is terminally %s (%s)",
			ErrRecoveryResolutionRequired, job.JobID, job.State, job.LastError,
		)
	default:
		return fmt.Errorf("%w: job has unknown state %q", ErrCorrupt, job.State)
	}
	if job.AdmittedThrough > scan.lastSeq || job.AppliedThrough > scan.lastSeq {
		return fmt.Errorf("%w: job watermark exceeds local WAL tail", ErrCorrupt)
	}
	return nil
}

func analyzeAbandonedStream(
	dir string,
	epoch uint64,
	scan *streamScan,
	job RecoveryJob,
) (abandonedStream, error) {
	stream := abandonedStream{dir: dir, epoch: epoch, scan: scan, job: job}
	live, mutations, marks, _, err := decodeStreamFrames(scan.frames)
	if err != nil {
		return stream, err
	}
	_ = live
	for _, mutation := range mutations {
		if _, err := recordwal.DecodePFR1(mutation.payload); err != nil {
			return stream, fmt.Errorf("%w: mutation %d payload is invalid: %v", ErrCorrupt, mutation.seq, err)
		}
	}
	applied := job.AppliedThrough
	cert, err := highestAppliedCertificate(marks, scan.lastSeq)
	if err != nil {
		return stream, err
	}
	for _, mark := range marks {
		if _, err := digestAt(scan, marks, mark.Through); err != nil {
			return stream, err
		}
		decoded, err := mark.mark()
		if err != nil {
			return stream, err
		}
		for lane := range decoded.lanes {
			if lane == int(StreamLaneLegacy) {
				continue
			}
			if _, err := laneDigestAt(scan, marks, StreamLane(lane), decoded.lanes[lane].through); err != nil {
				return stream, err
			}
		}
	}
	applied = max(applied, cert.global)
	if scan.firstSeq > 0 && applied < scan.firstSeq-1 {
		return stream, fmt.Errorf("%w: applied watermark predates the reclaimed WAL prefix", ErrCorrupt)
	}
	stream.appliedThrough = applied
	stream.tailRecords, stream.tailBytes = laneTailStats(mutations, cert)

	for i, fr := range scan.frames {
		if fr.typ != frameClose && fr.typ != frameForcedClose {
			continue
		}
		var close closeFrame
		if err := json.Unmarshal(fr.payload, &close); err != nil || close.Through > scan.lastSeq {
			return stream, fmt.Errorf("%w: malformed terminal close frame %d", ErrCorrupt, fr.frameNo)
		}
		if fr.typ == frameClose {
			if i != len(scan.frames)-1 {
				return stream, fmt.Errorf("%w: stream contains frames after clean close", ErrCorrupt)
			}
			if close.Through != scan.lastSeq {
				return stream, fmt.Errorf("%w: clean-close frame does not cover the exact WAL tail", ErrCorrupt)
			}
			stream.clean = true
			return stream, nil
		}
		if close.JobID != job.JobID || !validPublicJobID(close.JobID) ||
			close.Through > job.AppliedThrough || job.AdmittedThrough != scan.lastSeq {
			return stream, fmt.Errorf("%w: forced-close frame and job registry disagree", ErrCorrupt)
		}
		if i != len(scan.frames)-1 {
			// Recovery may append only its APPLIED+RELEASE finalization
			// controls after the original forced-close marker. No later
			// mutation or delegation installation is a valid writer shape.
			for _, later := range scan.frames[i+1:] {
				if later.typ != frameApplied && later.typ != frameRelease && later.typ != frameForcedClose {
					return stream, fmt.Errorf("%w: invalid frame after historical forced close", ErrCorrupt)
				}
			}
			continue
		}
		// A matching final marker means force-park is already durable.
		// A replaying job can retain an older final marker after advancing
		// recovery progress; forceParkStream appends a fresh marker for the
		// new applied watermark.
		if job.State == JobForced && close.Through == job.AppliedThrough {
			stream.alreadyForced = true
		}
	}
	return stream, nil
}

func forceParkStream(stream *abandonedStream, reason string) (string, error) {
	// First force every pre-existing WAL byte (including a repaired torn EOF)
	// to storage. The job registry is not allowed to claim a durable park
	// before that barrier succeeds.
	activePath, frameNo, end, err := abandonedStreamTail(stream)
	if err != nil {
		return "", err
	}
	active, err := os.OpenFile(activePath, os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	if err := active.Sync(); err != nil {
		_ = active.Close()
		return "", fmt.Errorf("sync existing WAL: %w", err)
	}
	if stream.alreadyForced {
		if err := active.Close(); err != nil {
			return "", fmt.Errorf("close forced WAL: %w", err)
		}
		if err := fsyncDir(stream.dir); err != nil {
			return "", fmt.Errorf("sync stream directory: %w", err)
		}
		return stream.job.JobID, nil
	}

	// PER LANE, deliberately, and this is the offline path's half of the fix.
	//
	// Counting `fr.seq > appliedThrough` counted against the GLOBAL applied
	// prefix, which one wedged lane pins at its own first unshipped record while
	// every other lane keeps applying above it. Every already-applied record
	// above that pin was therefore parked as "pending", and the next attach —
	// which selects its tail per lane — correctly drained far fewer. The two
	// numbers were about different sets, so their disagreement could not be read
	// as anything, and a park promising 34 records whose replay shipped 2 was
	// indistinguishable from a park that had actually lost 32.
	job := newJobState(stream.dir, stream.job)
	job.update(func(j *RecoveryJob) {
		j.State = JobForced
		j.AdmittedThrough = stream.scan.lastSeq
		j.AppliedThrough = stream.appliedThrough
		j.PendingRecords = stream.tailRecords
		j.PendingBytes = stream.tailBytes
		j.PendingBasis = pendingBasisLane
		j.LastError = reason
	})
	if err := job.persist(); err != nil {
		_ = active.Close()
		return "", fmt.Errorf("persist forced recovery job: %w", err)
	}
	jobID := job.snapshot().JobID
	if !stream.alreadyForced {
		payload, err := encodeControlPayload(closeFrame{
			Through: stream.appliedThrough,
			JobID:   jobID,
			Reason:  reason,
		})
		if err != nil {
			_ = active.Close()
			return jobID, err
		}
		frameBody := encodeFrame(nil, frameForcedClose, StreamLaneLegacy, frameNo+1, 0, payload)
		n, err := active.WriteAt(frameBody, end)
		if err == nil && n != len(frameBody) {
			err = io.ErrShortWrite
		}
		if err != nil {
			if n > 0 {
				_ = active.Truncate(end)
			}
			_ = active.Close()
			return jobID, fmt.Errorf("append forced-close frame: %w", err)
		}
		if err := active.Sync(); err != nil {
			_ = active.Close()
			return jobID, fmt.Errorf("sync forced-close frame: %w", err)
		}
	}
	if err := active.Close(); err != nil {
		return jobID, fmt.Errorf("close forced WAL: %w", err)
	}
	if err := fsyncDir(stream.dir); err != nil {
		return jobID, fmt.Errorf("sync stream directory: %w", err)
	}
	return jobID, nil
}

func abandonedStreamTail(stream *abandonedStream) (path string, frameNo uint64, end int64, err error) {
	names, err := filepath.Glob(filepath.Join(stream.dir, "wb-*.pfw"))
	if err != nil || len(names) == 0 {
		if err == nil {
			err = fmt.Errorf("%w: stream has no segment", ErrCorrupt)
		}
		return "", 0, 0, err
	}
	sort.Strings(names)
	path = names[len(names)-1]
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, 0, err
	}
	end = info.Size()
	headerBody := make([]byte, segmentHeaderSize)
	f, err := os.Open(path)
	if err != nil {
		return "", 0, 0, err
	}
	_, readErr := io.ReadFull(f, headerBody)
	closeErr := f.Close()
	if readErr != nil {
		return "", 0, 0, readErr
	}
	if closeErr != nil {
		return "", 0, 0, closeErr
	}
	header, err := decodeSegmentHeader(headerBody)
	if err != nil {
		return "", 0, 0, err
	}
	frameNo = header.FirstFrame - 1
	if len(stream.scan.frames) > 0 {
		frameNo = stream.scan.frames[len(stream.scan.frames)-1].frameNo
	}
	return path, frameNo, end, nil
}

func validPublicJobID(value string) bool {
	if len(value) != 35 || !strings.HasPrefix(value, "job") {
		return false
	}
	for _, r := range value[3:] {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
