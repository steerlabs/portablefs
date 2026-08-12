//go:build darwin

package portablefsd

import (
	"path/filepath"
	"testing"
)

func TestApplyDarwinSocketRootsSeparatesFrontendAndControl(t *testing.T) {
	frontendRoot := filepath.Join(t.TempDir(), "group", "portablefsd")
	stateRoot := filepath.Join(t.TempDir(), "state", "portablefsd")
	cfg := Config{}
	if err := applyDarwinSocketRoots(&cfg, frontendRoot, stateRoot); err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.FrontendSocket, filepath.Join(frontendRoot, "pfs.sock"); got != want {
		t.Fatalf("frontend socket = %q, want %q", got, want)
	}
	if got, want := cfg.ControlSocket, filepath.Join(stateRoot, "control.sock"); got != want {
		t.Fatalf("control socket = %q, want %q", got, want)
	}
}

func TestApplyDarwinSocketRootsRefusesOverrides(t *testing.T) {
	frontendRoot := filepath.Join(t.TempDir(), "group", "portablefsd")
	stateRoot := filepath.Join(t.TempDir(), "state", "portablefsd")
	for _, cfg := range []Config{
		{FrontendSocket: filepath.Join(t.TempDir(), "pfs.sock")},
		{ControlSocket: filepath.Join(t.TempDir(), "control.sock")},
		{FrontendSocket: filepath.Join(frontendRoot, "other.sock")},
		{ControlSocket: filepath.Join(stateRoot, "other.sock")},
	} {
		cfg := cfg
		if err := applyDarwinSocketRoots(&cfg, frontendRoot, stateRoot); err == nil {
			t.Fatalf("config %+v was accepted", cfg)
		}
	}
}
