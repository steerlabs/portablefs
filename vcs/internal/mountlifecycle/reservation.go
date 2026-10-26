package mountlifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

const TransitionLock = "mount-transition.lock"
const ReservationFile = "volume-reservations.json"
const MacVolumeConflict = "This volume is mounted on your Mac. Unmount it there before using it in Linux."
const LinuxVolumeConflict = "This volume is in Linux. Remove it from Linux before mounting it on your Mac."

// AuthorityIdentity names the canonical authenticated TLS server identity,
// never its dial address. Protocol-8 hosted placement uses that same name as
// AuthorityID. Trust roots authenticate the name; their order/rotation cannot
// create a second local reservation namespace.
func AuthorityIdentity(serverName string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(serverName, "."))
	if name == "" || len(name) > 253 || strings.ContainsAny(name, " /\\\t\r\n\x00") {
		return "", errors.New("invalid authority server name")
	}
	if ip := net.ParseIP(name); ip != nil {
		name = ip.String()
	}
	sum := sha256.Sum256([]byte("portablefs-authority-identity/8\x00" + name))
	return hex.EncodeToString(sum[:]), nil
}

type Reservation struct {
	Authority string `json:"authority"`
	Volume    string `json:"volume"`
	Frontend  string `json:"frontend"`
	Owner     string `json:"owner"`
}
type reservationState struct {
	Version      int           `json:"version"`
	Reservations []Reservation `json:"reservations"`
}

func validReservation(r Reservation) bool {
	raw, err := hex.DecodeString(r.Authority)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == r.Authority && strings.Trim(r.Authority, "0") != "" && ValidVolume(r.Volume) && (r.Frontend == "fskit" || r.Frontend == "workspace") && len(r.Owner) > 0 && len(r.Owner) <= 128 && !strings.ContainsAny(r.Owner, "\x00\r\n")
}
func ValidVolume(v string) bool {
	return len(v) > 0 && len(v) <= 128 && v != "." && v != ".." && strings.IndexFunc(v, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-')
	}) < 0
}

// Transition owns the shared, never-replaced per-account lock. Reservations
// persist before attach and outlive processes. Only the exact resource owner
// may release one after its independently authenticated cleanup has joined.
type Transition struct {
	guard    *Guard
	stateDir string
	state    reservationState
}

func BeginTransition(stateDir string) (*Transition, error) {
	guard, err := AcquireNamedExclusive(stateDir, TransitionLock)
	if err != nil {
		return nil, err
	}
	t := &Transition{guard: guard, stateDir: stateDir, state: reservationState{Version: 1, Reservations: []Reservation{}}}
	raw, err := privatepath.ReadFileIfExists(filepath.Join(stateDir, ReservationFile))
	if err == nil && raw != nil {
		if len(raw) > 1<<20 {
			err = errors.New("reservation inventory exceeds bound")
		} else {
			t.state, err = hostctl.DecodeBounded[reservationState](raw, 1<<20)
		}
	}
	if err == nil && (t.state.Version != 1 || t.state.Reservations == nil || len(t.state.Reservations) > 128) {
		err = errors.New("invalid reservation inventory")
	}
	seen := map[string]bool{}
	for _, r := range t.state.Reservations {
		key := r.Authority + "/" + r.Volume
		if !validReservation(r) || seen[key] {
			err = errors.New("invalid reservation inventory")
		}
		seen[key] = true
	}
	if err != nil {
		guard.Close()
		return nil, fmt.Errorf("read volume reservations: %w", err)
	}
	return t, nil
}
func (t *Transition) Close() error { return t.guard.Close() }
func (t *Transition) Inventory() []Reservation {
	return append([]Reservation(nil), t.state.Reservations...)
}
func (t *Transition) Reserve(r Reservation) error {
	if !validReservation(r) {
		return errors.New("invalid volume reservation")
	}
	for _, old := range t.state.Reservations {
		if old.Authority == r.Authority && old.Volume == r.Volume || old.Frontend == "workspace" && r.Frontend == "workspace" && old.Volume == r.Volume {
			if old == r {
				return nil
			}
			if old.Frontend != r.Frontend {
				if r.Frontend == "workspace" {
					return errors.New(MacVolumeConflict)
				}
				return errors.New(LinuxVolumeConflict)
			}
			return errors.New("volume has retained ownership; Cleanup required")
		}
	}
	if len(t.state.Reservations) >= 128 {
		return errors.New("volume reservation capacity reached")
	}
	t.state.Reservations = append(t.state.Reservations, r)
	return t.persist()
}
func (t *Transition) Release(r Reservation) error {
	if !validReservation(r) {
		return errors.New("invalid volume reservation")
	}
	for i, old := range t.state.Reservations {
		if old == r {
			t.state.Reservations = append(t.state.Reservations[:i], t.state.Reservations[i+1:]...)
			return t.persist()
		}
		if old.Authority == r.Authority && old.Volume == r.Volume {
			return errors.New("reservation owner mismatch")
		}
	}
	return nil
}
func (t *Transition) persist() error {
	sort.Slice(t.state.Reservations, func(i, j int) bool {
		a, b := t.state.Reservations[i], t.state.Reservations[j]
		return a.Authority+"/"+a.Volume < b.Authority+"/"+b.Volume
	})
	raw, err := json.Marshal(t.state)
	if err != nil {
		return err
	}
	return privatepath.WriteFileAtomic(filepath.Join(t.stateDir, ReservationFile), raw)
}
