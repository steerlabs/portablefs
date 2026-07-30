package mounthost

import (
	"fmt"
)

// deviceState is what /dev/fuse permitted this process.
type deviceState string

const (
	deviceUsable      deviceState = "usable"
	deviceMissing     deviceState = "missing"
	deviceDenied      deviceState = "denied"
	deviceUnavailable deviceState = "unavailable"
	deviceUnknown     deviceState = "unknown"
)

type capabilityState string

const (
	capabilityPresent capabilityState = "present"
	capabilityAbsent  capabilityState = "absent"
	capabilityUnknown capabilityState = "unknown"
)

// linuxObservation is the raw, uninterpreted reading of the host. Splitting
// it from classifyLinux keeps the decision table exhaustively testable
// without a container per case.
type linuxObservation struct {
	device    deviceState
	deviceErr error
	helper    string
	// privileged reports effective CAP_SYS_ADMIN. It is evidence, never a
	// promise: seccomp, an LSM, device policy, or namespace ownership may
	// still reject mount(2).
	capability capabilityState
	container  bool
}

// classifyLinux turns an observation into the strongest honest verdict. A
// capability or helper is only evidence: seccomp, an LSM, namespace
// ownership, helper policy, and the mount point can still reject the real
// operation.
func classifyLinux(o linuxObservation) Facts {
	f := Facts{Transport: FUSE}
	f.Details = append(f.Details, detail("device", string(o.device)))
	if o.helper != "" {
		f.Details = append(f.Details, detail("helper", o.helper))
	} else {
		f.Details = append(f.Details, detail("helper", "none on PATH or under /bin"))
	}
	f.Details = append(f.Details, detail("cap_sys_admin", string(o.capability)))
	if o.container {
		f.Details = append(f.Details, detail("container", "true"))
	}

	switch o.device {
	case deviceMissing:
		f.State = Blocked
		f.Issue = IssueFUSEDeviceMissing
		f.Summary = "/dev/fuse does not exist: the kernel FUSE module is not loaded, or the current environment was created without the device"
		return f
	case deviceUnavailable:
		f.State = Blocked
		f.Issue = IssueFUSEDeviceUnavailable
		f.Summary = fmt.Sprintf("/dev/fuse exists but the kernel device is unavailable (%v)", o.deviceErr)
		return f
	case deviceDenied:
		if o.helper != "" {
			f.State = Unverified
			f.MountMechanism = "helper"
			f.HelperPath = o.helper
			f.Summary = fmt.Sprintf("/dev/fuse is not openable by this process (%v), but %s is available to attempt the privileged open and mount", o.deviceErr, o.helper)
			return f
		}
		f.State = Blocked
		f.Issue = IssueFUSEDeviceDenied
		f.Summary = fmt.Sprintf("/dev/fuse exists but this process cannot open it (%v), and no fusermount helper is available to try on its behalf", o.deviceErr)
		return f
	case deviceUnknown:
		switch {
		case o.capability == capabilityPresent:
			f.State = Unverified
			f.MountMechanism = "direct"
			f.Summary = fmt.Sprintf("/dev/fuse could not be probed (%v); CAP_SYS_ADMIN selects one strict direct mount attempt", o.deviceErr)
		case o.helper != "":
			f.State = Unverified
			f.MountMechanism = "helper"
			f.HelperPath = o.helper
			f.Summary = fmt.Sprintf("/dev/fuse could not be probed (%v); %s selects one strict helper mount attempt", o.deviceErr, o.helper)
		case o.capability == capabilityUnknown:
			f.State = Unverified
			f.MountMechanism = "direct"
			f.Summary = fmt.Sprintf("/dev/fuse and CAP_SYS_ADMIN could not be conclusively probed (%v); one strict direct mount attempt is authoritative", o.deviceErr)
		default:
			f.State = Blocked
			f.Issue = IssueFUSEMountUnavailable
			f.Summary = fmt.Sprintf("/dev/fuse could not be probed (%v), and this process has neither CAP_SYS_ADMIN nor a trusted fusermount helper", o.deviceErr)
		}
		return f
	case deviceUsable:
		// Continue to deterministic mechanism selection below.
	default:
		f.State = Blocked
		f.Issue = IssueFUSEDeviceUnavailable
		f.Summary = fmt.Sprintf("unrecognized /dev/fuse probe state %q", o.device)
		return f
	}

	switch {
	case o.capability == capabilityPresent:
		f.State = Unverified
		f.MountMechanism = "direct"
		f.Summary = "/dev/fuse is openable and this process holds CAP_SYS_ADMIN, but only a mount attempt can verify host policy"
	case o.helper != "":
		f.State = Unverified
		f.MountMechanism = "helper"
		f.HelperPath = o.helper
		f.Summary = "/dev/fuse is openable and " + o.helper + " is available, but only a mount attempt can verify helper policy"
	case o.capability == capabilityUnknown:
		f.State = Unverified
		f.MountMechanism = "direct"
		f.Summary = "/dev/fuse is openable but CAP_SYS_ADMIN could not be read; one strict direct mount attempt is authoritative"
	default:
		f.State = Blocked
		f.Issue = IssueFUSEMountUnavailable
		f.Summary = "/dev/fuse is openable, but this process has neither CAP_SYS_ADMIN for mount(2) nor fusermount3/fusermount on PATH or under /bin"
	}
	return f
}
