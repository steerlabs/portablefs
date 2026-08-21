package restoremode

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type QuiesceMembership interface {
	SetQuiescing(nonce string, writeProof func() error) error
}

type QuiesceConfig struct {
	ConfigRoot     string
	StateRoot      string
	VolumeID       string
	AuthorityEpoch uint64
	WireEpoch      volumeserver.Epoch
	Membership     QuiesceMembership
	PollInterval   time.Duration
	Now            func() time.Time
}

type quiesceRequest struct {
	Nonce         string `json:"nonce"`
	RequestedUnix int64  `json:"requested_unix"`
}

type quiesceProof struct {
	VolumeID            string `json:"volume_id"`
	AuthorityEpoch      uint64 `json:"authority_epoch"`
	WireSessionEpochHex string `json:"wire_session_epoch_hex"`
	Nonce               string `json:"nonce"`
	MembershipEmpty     bool   `json:"membership_empty"`
	WrittenUnix         int64  `json:"written_unix"`
}

type QuiesceWatcher struct {
	cfg         QuiesceConfig
	mu          sync.Mutex
	activeNonce string
	cancel      context.CancelFunc
	done        chan struct{}
}

func NewQuiesceWatcher(parent context.Context, cfg QuiesceConfig) (*QuiesceWatcher, error) {
	if cfg.ConfigRoot == "" || cfg.StateRoot == "" || cfg.VolumeID == "" || cfg.Membership == nil ||
		!filepath.IsAbs(cfg.ConfigRoot) || !filepath.IsAbs(cfg.StateRoot) {
		return nil, errors.New("restoremode: quiesce watcher requires absolute roots, volume identity, and durable membership")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.PollInterval <= 0 {
		return nil, errors.New("restoremode: quiesce poll interval must be positive")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ctx, cancel := context.WithCancel(parent)
	w := &QuiesceWatcher{cfg: cfg, cancel: cancel, done: make(chan struct{})}
	if err := w.Check(); err != nil {
		cancel()
		return nil, err
	}
	go w.loop(ctx)
	return w, nil
}

func (w *QuiesceWatcher) loop(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = w.Check()
		}
	}
}

// Check is called both by the coarse watcher and immediately before strict
// attach admission. A valid request closes admission inside SetQuiescing;
// malformed or unreadable request state fails the attach closed.
func (w *QuiesceWatcher) Check() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	requestPath := filepath.Join(w.cfg.ConfigRoot, QuiesceRequest)
	var request quiesceRequest
	err := readStrictJSON(requestPath, &request)
	if errors.Is(err, os.ErrNotExist) {
		if w.activeNonce != "" {
			if err := w.cfg.Membership.SetQuiescing("", nil); err != nil {
				return err
			}
			w.activeNonce = ""
			_ = os.Remove(filepath.Join(w.cfg.StateRoot, QuiesceProof))
		}
		return nil
	}
	if err != nil || len(request.Nonce) != 64 || request.RequestedUnix <= 0 {
		return fmt.Errorf("%w: invalid quiesce request", volumeserver.ErrQuiescing)
	}
	if raw, decodeErr := hex.DecodeString(request.Nonce); decodeErr != nil || len(raw) != 32 {
		return fmt.Errorf("%w: invalid quiesce nonce", volumeserver.ErrQuiescing)
	}
	proof := func() error {
		return writeAtomicJSON(filepath.Join(w.cfg.StateRoot, QuiesceProof), quiesceProof{
			VolumeID: w.cfg.VolumeID, AuthorityEpoch: w.cfg.AuthorityEpoch,
			WireSessionEpochHex: hex.EncodeToString(w.cfg.WireEpoch[:]), Nonce: request.Nonce,
			MembershipEmpty: true, WrittenUnix: w.cfg.Now().Unix(),
		})
	}
	if err := w.cfg.Membership.SetQuiescing(request.Nonce, proof); err != nil {
		return err
	}
	w.activeNonce = request.Nonce
	return nil
}

func (w *QuiesceWatcher) Close() error {
	if w == nil {
		return nil
	}
	w.cancel()
	<-w.done
	return nil
}
