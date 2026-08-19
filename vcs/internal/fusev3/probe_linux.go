//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"os"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// KernelProbe is what one real, throwaway FUSE mount proved about this host
// and this exact client binary.
//
// Everything in it comes from the kernel's own INIT request, so it is evidence
// rather than configuration: a client whose mount options the kernel refuses,
// or whose negotiated protocol cannot carry the coherence contract, cannot
// produce a KernelProbe at all.
type KernelProbe struct {
	// InitFlags is the capability set the kernel offered in INIT.
	InitFlags uint64 `json:"initFlags"`
	// MaxWrite is the write bound the probe negotiated, in bytes. It is the
	// shipped authority's default so the probe exercises the same
	// large-request path a real mount will.
	MaxWrite uint32 `json:"maxWrite"`
	// ProtocolMajor/ProtocolMinor is the kernel FUSE protocol that completed
	// INIT.
	ProtocolMajor uint32 `json:"protocolMajor"`
	ProtocolMinor uint32 `json:"protocolMinor"`
}

// probeMaxIO mirrors portablefs-authority's -max-read-bytes/-max-write-bytes
// defaults. Probing at the deployed bound is the point: a 4 KiB probe would
// pass on a kernel that cannot carry the request size a real mount negotiates.
const probeMaxIO = 1 << 20

// ProbeKernelFUSE installs one real FUSE mount on a private, empty temporary
// directory, completes the kernel INIT handshake against this binary's own
// mount options, verifies the same kernel guarantees a live mount requires,
// and unmounts.
//
// It exists because every cheaper check — the /dev/fuse node existing, the
// device opening, CAP_SYS_ADMIN being held, a helper being installed — is
// satisfied by a client that can never complete FUSE INIT. That is exactly the
// failure that reaches production silently: the mount command starts, attaches
// to an authority, installs a kernel mount, and only then discovers that the
// interface it asked for is not one this kernel will speak.
//
// It proves nothing about the authority, the wire protocol, or coherence. No
// authority is contacted and no file is served; the mounted filesystem answers
// nothing. Only INIT, the negotiated capability set, and the mount/unmount
// lifecycle are exercised.
func ProbeKernelFUSE() (KernelProbe, error) {
	options := mountOptions(Config{
		MountInstanceID: "fuse-probe",
		MaxBackground:   minMaxInFlight,
	}, probeMaxIO, probeMaxIO)
	// The probe must not be able to pass by asking for a weaker interface than
	// a live mount asks for.
	if err := verifyMountDecisions(options); err != nil {
		return KernelProbe{}, err
	}

	mountpoint, err := os.MkdirTemp("", "portablefs-fuse-probe-")
	if err != nil {
		return KernelProbe{}, fmt.Errorf("fusev3: create FUSE probe mountpoint: %w", err)
	}
	defer os.Remove(mountpoint)

	server, err := fuse.NewServer(probeFileSystem{fuse.NewDefaultRawFileSystem()}, mountpoint, options)
	if err != nil {
		return KernelProbe{}, fmt.Errorf("fusev3: install FUSE probe mount: %w", err)
	}
	served := make(chan struct{})
	go func() {
		server.Serve()
		close(served)
	}()

	probe, probeErr := completeProbeInit(server)
	unmountErr := server.Unmount()
	<-served
	if probeErr != nil {
		return KernelProbe{}, probeErr
	}
	if unmountErr != nil {
		return KernelProbe{}, fmt.Errorf("fusev3: remove FUSE probe mount: %w", unmountErr)
	}
	return probe, nil
}

func completeProbeInit(server *fuse.Server) (KernelProbe, error) {
	if err := server.WaitMount(); err != nil {
		return KernelProbe{}, fmt.Errorf("fusev3: complete FUSE probe INIT: %w", err)
	}
	settings := server.KernelSettings()
	if settings == nil {
		return KernelProbe{}, errors.New("fusev3: FUSE probe completed without kernel INIT settings")
	}
	if err := verifyKernelGuarantees(settings, probeMaxIO); err != nil {
		return KernelProbe{}, err
	}
	return KernelProbe{
		InitFlags:     settings.Flags64(),
		MaxWrite:      probeMaxIO,
		ProtocolMajor: settings.Major,
		ProtocolMinor: settings.Minor,
	}, nil
}

// probeFileSystem is the smallest filesystem a kernel will finish mounting: an
// empty read-only root. It answers nothing else, because the probe's subject is
// the mount interface, not the filesystem behind it.
type probeFileSystem struct{ fuse.RawFileSystem }

func (probeFileSystem) GetAttr(_ <-chan struct{}, in *fuse.GetAttrIn, out *fuse.AttrOut) fuse.Status {
	if in.NodeId != fuse.FUSE_ROOT_ID {
		return fuse.ENOENT
	}
	out.Attr = fuse.Attr{Ino: fuse.FUSE_ROOT_ID, Mode: fuse.S_IFDIR | 0o555, Nlink: 2}
	return fuse.OK
}

func (probeFileSystem) Lookup(<-chan struct{}, *fuse.InHeader, string, *fuse.EntryOut) fuse.Status {
	return fuse.ENOENT
}

func (probeFileSystem) Access(<-chan struct{}, *fuse.AccessIn) fuse.Status { return fuse.OK }

func (probeFileSystem) StatFs(_ <-chan struct{}, _ *fuse.InHeader, out *fuse.StatfsOut) fuse.Status {
	out.Bsize = 4096
	out.NameLen = 255
	return fuse.OK
}
