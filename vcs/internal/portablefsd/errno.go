package portablefsd

import "github.com/steerlabs/portablefs/vcs/internal/fsproto"

const (
	darwinEPERM  int32 = 1
	darwinENOENT int32 = 2
	// darwinEIO is the EIO-class answer for a far end that stopped answering:
	// the local store is intact, the authority is not applying. It is
	// deliberately distinct from darwinENOSPC (28), which promises the operation
	// can never fit locally. writeback.ErrUplinkStalled maps HERE, so an
	// application under a dead uplink retries or reports an I/O error instead of
	// deleting files to fix a network problem. See creditErrno in ops.go.
	darwinEIO          int32 = 5
	darwinEINTR        int32 = 4
	darwinENXIO        int32 = 6
	darwinE2BIG        int32 = 7
	darwinEBADF        int32 = 9
	darwinEACCES       int32 = 13
	darwinEAGAIN       int32 = 35
	darwinEBUSY        int32 = 16
	darwinEEXIST       int32 = 17
	darwinEXDEV        int32 = 18
	darwinENOTDIR      int32 = 20
	darwinEISDIR       int32 = 21
	darwinEINVAL       int32 = 22
	darwinENOSPC       int32 = 28
	darwinERANGE       int32 = 34
	darwinENAMETOOLONG int32 = 63
	darwinENOTEMPTY    int32 = 66
	darwinESTALE       int32 = 70
	darwinENOTSUP      int32 = 45
	darwinENOATTR      int32 = 93 // "attribute not found" — the wire's Linux ENODATA
)

func toDarwinErr(st int32) int32 {
	switch st {
	case fsproto.OK:
		return 0
	case fsproto.EPERM:
		return darwinEPERM
	case fsproto.ENOENT:
		return darwinENOENT
	case fsproto.EIO:
		return darwinEIO
	case fsproto.EEXIST:
		return darwinEEXIST
	case fsproto.ENOTDIR:
		return darwinENOTDIR
	case fsproto.EISDIR:
		return darwinEISDIR
	case fsproto.EINVAL:
		return darwinEINVAL
	case fsproto.ENAMETOOLONG:
		return darwinENAMETOOLONG
	case fsproto.EBUSY:
		return darwinEBUSY
	case fsproto.EAGAIN:
		return darwinEAGAIN
	case fsproto.ESTALE:
		return darwinESTALE
	case fsproto.ENOTEMPTY:
		return darwinENOTEMPTY
	case fsproto.ENOSPC:
		return darwinENOSPC
	case fsproto.ENODATA:
		return darwinENOATTR
	case fsproto.E2BIG:
		return darwinE2BIG
	case fsproto.ERANGE:
		return darwinERANGE
	case fsproto.EOPNOTSUPP:
		return darwinENOTSUP
	default:
		if st == 0 {
			return 0
		}
		return darwinEIO
	}
}
