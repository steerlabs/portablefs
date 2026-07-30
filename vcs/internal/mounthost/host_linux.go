//go:build linux

package mounthost

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// capSysAdmin is CAP_SYS_ADMIN's bit position in the capability bitmask
// (linux/capability.h). mount(2) requires it in the user namespace that owns
// the target mount namespace.
const capSysAdmin = 21

func check(t Transport) Facts {
	if t != FUSE {
		return unsupported("linux")
	}
	return classifyLinux(observeLinux())
}

func observeLinux() linuxObservation {
	o := linuxObservation{
		capability: capSysAdminState(),
		container:  inContainer(),
	}
	o.device, o.deviceErr = probeFuseDevice()
	o.helper, _ = FUSEHelper()
	return o
}

// probeFuseDevice opens /dev/fuse and immediately closes it. Opening is the
// only honest test: the device node existing says nothing about whether a
// device cgroup or LSM policy will permit this process to use it.
func probeFuseDevice() (deviceState, error) {
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
		return deviceUsable, nil
	}
	if os.IsNotExist(err) {
		return deviceMissing, err
	}
	switch err {
	case unix.ENODEV, unix.ENXIO:
		return deviceUnavailable, err
	case unix.EACCES, unix.EPERM:
		return deviceDenied, err
	default:
		return deviceUnknown, err
	}
}

// capSysAdminState reports effective CAP_SYS_ADMIN by reading the capability
// bitmask the kernel publishes for this thread. /proc/self/status is used
// rather than capget(2) because it is the same source `capsh --print` reads
// and needs no versioned struct handling; an unreadable /proc is reported as
// unknown and feeds the same single deterministic mechanism selection as all
// other observations.
func capSysAdminState() capabilityState {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return capabilityUnknown
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		rest, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			return capabilityUnknown
		}
		if mask&(1<<capSysAdmin) != 0 {
			return capabilityPresent
		}
		return capabilityAbsent
	}
	return capabilityUnknown
}

// inContainer reports the two runtime markers that exist by construction:
// Docker's /.dockerenv and the OCI /run/.containerenv Podman writes. It is
// deliberately not a brand detector — the guidance a blocked host needs names
// the missing primitive, not the runtime that omitted it.
func inContainer() bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	return false
}
