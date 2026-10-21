//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceguest"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
)

const state = "/run/portablefs-workspace"

type release struct {
	AppVersion     string `json:"app_version"`
	Commit         string `json:"commit"`
	ImageDigest    string `json:"image_digest"`
	AuthorityMajor uint32 `json:"authority_major"`
}
type bootSeed struct {
	BootID           string `json:"boot_id"`
	HostServiceID    string `json:"host_service_id"`
	AuthorizedKey    string `json:"authorized_key"`
	FormatAuthorized string `json:"format_authorized"`
}

func readJSON(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 8192))
	d.DisallowUnknownFields()
	if err = d.Decode(value); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
func bootstrap() (result error) {
	console, err := os.OpenFile("/dev/hvc1", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	defer console.Close()
	defer func() {
		if result != nil {
			_ = json.NewEncoder(console).Encode(map[string]string{"event": "boot-failed", "reason": result.Error()})
		}
	}()
	// Raw console: canonical tty processing and echo would corrupt the seed.
	term := &unix.Termios{Cflag: unix.B115200 | unix.CS8 | unix.CREAD | unix.CLOCAL}
	term.Cc[unix.VMIN] = 1
	if err = unix.IoctlSetTermios(int(console.Fd()), unix.TCSETS, term); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	if _, err = console.Write([]byte("{\"event\":\"seed-ready\"}\n")); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	scanner := bufio.NewScanner(io.LimitReader(console, 8192))
	if !scanner.Scan() {
		return fmt.Errorf("missing boot seed")
	}
	var seed bootSeed
	d := json.NewDecoder(strings.NewReader(scanner.Text()))
	d.DisallowUnknownFields()
	if err = d.Decode(&seed); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	boot, err := hex.DecodeString(seed.BootID)
	if err != nil || !control.ID(boot) {
		return fmt.Errorf("invalid boot ID")
	}
	host, err := hex.DecodeString(seed.HostServiceID)
	if err != nil || !control.ID(host) {
		return fmt.Errorf("invalid host ID")
	}
	parts := strings.Fields(seed.AuthorizedKey)
	if len(parts) < 2 || parts[0] != "ssh-ed25519" || strings.ContainsAny(seed.AuthorizedKey, "\r\n") {
		return fmt.Errorf("invalid client public key")
	}
	if err = os.MkdirAll(state, 0755); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	if err = os.WriteFile(state+"/authorized_keys", []byte(seed.AuthorizedKey+"\n"), 0644); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	if err = os.WriteFile(state+"/boot.json", raw, 0600); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	if seed.FormatAuthorized != "8" && seed.FormatAuthorized != "" {
		return fmt.Errorf("invalid format authorization")
	}
	data := exec.Command("/usr/local/libexec/portablefs-workspace-data")
	data.Env = append(os.Environ(), "PFS_FORMAT_AUTHORIZED="+seed.FormatAuthorized)
	data.Stdout, data.Stderr = os.Stderr, os.Stderr
	if err = data.Run(); err != nil {
		return fmt.Errorf("initialize workspace data: %w", err)
	}
	key, err := os.ReadFile("/data/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	return json.NewEncoder(console).Encode(map[string]string{"event": "seeded", "host_key": strings.TrimSpace(string(key)), "boot_id": seed.BootID, "format_complete": "8"})
}
func serve() error {
	var r release
	if err := readJSON("/usr/lib/portablefs-workspace/release.json", &r); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	digest, err := hex.DecodeString(r.ImageDigest)
	if err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	version := &pb.Release{AppVersion: r.AppVersion, Commit: r.Commit, ImageDigest: digest, AuthorityMajor: r.AuthorityMajor}
	if err = control.Release(version); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	var seed bootSeed
	if err = readJSON(state+"/boot.json", &seed); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	boot, _ := hex.DecodeString(seed.BootID)
	host, _ := hex.DecodeString(seed.HostServiceID)
	guest := make([]byte, 16)
	if _, err = rand.Read(guest); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	witness, err := os.OpenFile(state+"/control-started", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("refuse supervisor restart within a boot: %w", err)
	}
	witness.Close()
	expected := &pb.Hello{Release: version, BootId: boot, HostServiceId: host, GuestServiceId: guest}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: 1023}); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	if err = unix.Listen(fd, 1); err != nil {
		return fmt.Errorf("guest workspace: %w", err)
	}
	console, err := os.OpenFile("/dev/hvc1", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open readiness console: %w", err)
	}
	err = json.NewEncoder(console).Encode(map[string]string{"event": "control-ready"})
	console.Close()
	if err != nil {
		return fmt.Errorf("announce control readiness: %w", err)
	}
	for {
		client, peer, err := unix.Accept4(fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		if err != nil {
			return fmt.Errorf("guest workspace: %w", err)
		}
		address, ok := peer.(*unix.SockaddrVM)
		if !ok || address.CID != unix.VMADDR_CID_HOST {
			unix.Close(client)
			continue
		}
		stream := os.NewFile(uintptr(client), "workspace-vsock")
		if stream == nil {
			unix.Close(client)
			return fmt.Errorf("invalid vsock descriptor")
		}
		supervisor, err := workspaceguest.New(boot, host, guest, true)
		if err != nil {
			stream.Close()
			return fmt.Errorf("guest workspace: %w", err)
		}
		paired := false
		if err = stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			stream.Close()
			return fmt.Errorf("guest workspace: %w", err)
		}
		err = workspaceguest.Serve(context.Background(), stream, expected, supervisor, func() { paired = true; _ = stream.SetDeadline(time.Time{}) })
		stream.Close()
		if paired {
			return fmt.Errorf("paired control channel ended; cold boot required: %w", err)
		}
	}
}
func run(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: portablefs-workspaced bootstrap|serve|probe-fuse")
	}
	switch args[0] {
	case "bootstrap":
		return bootstrap()
	case "serve":
		return serve()
	case "probe-fuse":
		return probeFuse()
	}
	return fmt.Errorf("unknown guest operation")
}
