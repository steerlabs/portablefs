package portablefsd

import "fmt"

const (
	darwinEPERM  int32 = 1
	darwinENOENT int32 = 2
	// darwinEIO is the EIO-class answer for a far end that stopped answering:
	// the local store is intact, the authority is not applying. It is
	// deliberately distinct from darwinENOSPC (28), which promises the operation
	// can never fit locally.
	darwinEIO          int32 = 5
	darwinEINTR        int32 = 4
	darwinENXIO        int32 = 6
	darwinE2BIG        int32 = 7
	darwinEBADF        int32 = 9
	darwinENOMEM       int32 = 12
	darwinEACCES       int32 = 13
	darwinEAGAIN       int32 = 35
	// ECANCELED is deliberately named separately from EINTR/EAGAIN. On macOS
	// 26 those retry-class results can be replayed by the VFS after FSKit has
	// already returned them to userspace, which destroys a definite-preapply
	// guarantee. Policy v2 uses ECANCELED for that boundary and verifies the
	// kernel behavior with the live FSKit/XFS rig.
	darwinECANCELED    int32 = 89
	darwinEBUSY        int32 = 16
	darwinEEXIST       int32 = 17
	darwinEXDEV        int32 = 18
	darwinENODEV       int32 = 19
	darwinENOTDIR      int32 = 20
	darwinEISDIR       int32 = 21
	darwinEINVAL       int32 = 22
	darwinENFILE       int32 = 23
	darwinEMFILE       int32 = 24
	darwinENOTTY       int32 = 25
	darwinETXTBSY      int32 = 26
	darwinEFBIG        int32 = 27
	darwinENOSPC       int32 = 28
	darwinESPIPE       int32 = 29
	darwinEROFS        int32 = 30
	darwinEMLINK       int32 = 31
	darwinEPIPE        int32 = 32
	darwinERANGE       int32 = 34
	darwinENAMETOOLONG int32 = 63
	darwinENOTEMPTY    int32 = 66
	darwinELOOP        int32 = 62
	darwinEDQUOT       int32 = 69
	darwinESTALE       int32 = 70
	// darwinENOTCONN is the terminal-session answer for an authority-v3 attach:
	// the strict session is dead and no retry against this attach can revive it,
	// so FSKit is told the daemon-side endpoint is gone rather than that one
	// operation suffered an I/O fault. Only an exact unmount resolves it.
	darwinENOTCONN  int32 = 57
	darwinEOVERFLOW int32 = 84
	darwinENOTSUP   int32 = 45
	darwinETIMEDOUT int32 = 60
	darwinENOSYS    int32 = 78
	darwinENOATTR   int32 = 93 // "attribute not found" — the wire's Linux ENODATA
)

// errMessage renders one operation's refusal for the pfslocal error reply. The
// frontend surfaces the errno; the text names which operation produced it.
func errMessage(op string, eno int32) string {
	return fmt.Sprintf("%s failed: errno %d", op, eno)
}
