# Workspace VM absence

Same-boot recovery uses a kernel-held execution reference, independent of the
service process. Process exit, a released service singleton and vanished
control or SSH endpoints still prove no VM absence.

## Execution reference

The owner acquires `flock(LOCK_EX | LOCK_NB)` on a fresh open description of
the existing `owner.lock` in the validated workspace state directory before
constructing the VM. WorkspaceState validates and adopts that same reference;
it does not take a second lock. Private desired-state format 3 records its
device/inode with the execution
identity before VZ Start. A successor never substitutes a recreated inode for a
same-boot execution. Unequal desired-state formats refuse; no historical decoder
or conversion exists. Authority and paired workspace control remain protocol 8.

The same file handle becomes the writing handle of a dedicated, output-only
`VZFileHandleSerialPortAttachment`. The immutable VM configuration retains this
third serial device; the ordinary bounded diagnostic console and bootstrap console
retain their existing paths. The guest workspace user does not use this device.
The removal/update boundary already fences the canonical owner lock; extending
its reference into VZ also fences the old VM after service death.

Darwin's [flock contract](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/flock.2.html)
associates duplicated descriptors with one lock. Descriptor transfer retains the
same open description. The owner closes its reference without `LOCK_UN`: an
explicit unlock would also release the VM worker's shared lock. Kernel release
occurs only after the last reference closes. A successor opens the pinned file
anew and tries an exclusive, nonblocking lock. Busy or any inspection/lock error
retains the execution witness and refuses startup.

## VZ lifetime qualification

Apple documents the attachment's [file handles](https://developer.apple.com/documentation/virtualization/vzfilehandleserialportattachment),
but that API alone does not establish the necessary cross-process lifetime. The
native witness tests must prove all of the following on the qualified VZ runtime:

- `lsof` finds the dedicated inode on the actual
  `com.apple.Virtualization.VirtualMachine` worker.
- Closing the owner's original handle leaves the lock busy while the guest runs,
  including after Linux userspace boot and VZ pause/resume. This rejects client
  I/O proxying and independently reopened, non-lock-carrying worker descriptions.
- Holding that exact worker stopped, then killing its service owner with SIGKILL,
  leaves the lock busy and refuses a successor. Releasing the worker permits its
  exit and the fresh lock acquisition. An orderly VZ stop also releases the worker
  reference. PID disappearance is an observation in this test, never production
  admission authority.
- The real SMAppService successor cold-boots, requests fresh mount authorization,
  reconciles the old guest inventories and observes an independently completed
  peer mutation. Guest boot identity changes, persistent SSH identity remains,
  and previous unknown or lost outcomes remain retained through later cleanup.

The standalone primary-console and dedicated-device experiments retain the
worker's exact descriptor observations and the independent lock probes. Product
qualification requires the service cases in the exact native inventory as well;
the external lifecycle report binds their host/image/source evidence. A successful
sample on one OS build does not qualify other supported VZ runtimes by implication.

## Successor admission

The absence check returns the acquired reference to the same startup owner. That
owner retains it through durable execution publication and passes its handle to
VZ, closing the gap between absence proof and successor construction. It never
reuses an already-held description as a fresh absence proof. Descriptor references
in flight through XPC also retain the lock; loss of the client alone cannot release
them. State and reservation locks continue to serialize all user transitions.

Acquisition proves old execution absence, not prior write durability. The host
atomically retains the prior execution's unknown outcome before clearing its
execution identity and installing a new boot identity. The fresh Linux
kernel then uses the existing cold reconciliation and loss-retention rules; no old
RAM, child process, descriptor or session is adopted. Removal and unattended update
still refuse unacknowledged unknown or lost outcomes. Only exact Dismiss
acknowledges a retained notice; it never proves write durability. A different host kernel boot proves the old
execution absent independently, without upgrading its write outcome.

## Why process and disk scans remain insufficient

`proc_listpidspath` is not this witness. Apple's
[implementation](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/proc_listpidspath.c)
enumerates processes and inspects their descriptors and memory in separate calls;
inspection failures are omitted. A successful empty result is not an atomic,
complete VM-lifetime query. Nor does a disk-image pathname prove that every live
old VM retains an inspectable reference throughout execution.

[Apple DTS](https://developer.apple.com/forums/thread/850709) describes expected
cleanup of a crashed client's VM, without a guaranteed completion deadline or a
successor termination handle. Worker relationships remain
[implementation details](https://developer.apple.com/forums/thread/848542). This
construction does not turn those expectations into authority: its witness is the
deliberately shared kernel lock, with the attachment's descriptor lifetime proven
by the native controls above.
