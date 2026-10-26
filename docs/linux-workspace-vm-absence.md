# Workspace VM absence

The service clears its durable execution witness only after its exact VZ owner
confirms termination, or after a different kernel boot-session UUID proves the
old execution cannot survive. A service PID exit, released singleton, closed
control socket or vanished SSH endpoint supplies no VM-termination authority.
Same-boot recovery after an unconfirmed owner crash remains refused. This is
an availability limitation, not a completed automatic crash-recovery feature.

## Disk-file process queries

`proc_listpidspath` does not supply an exact negative VM witness. Apple's
[implementation](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/proc_listpidspath.c)
first enumerates PIDs, then inspects each process's directories, vnode file
descriptions and memory regions in separate calls. In both search phases a
process inspection result other than a match is omitted, including an error.
A successful empty result therefore does not prove that every live process was
inspectable. Making the caller root does not make this scan atomic or change
that error-handling contract. It also does not identify an exact VZ execution.

Even a complete open-file inventory would need another invariant: every live
old VM must retain an inventory-visible reference to the exact pinned image
inode throughout execution. Apple's
[disk-image attachment contract](https://developer.apple.com/documentation/virtualization/vzdiskimagestoragedeviceattachment)
describes the storage backing, but provides no such process-reference lifetime
or crash-teardown ordering guarantee. Observing a file open during a finite
workload cannot establish that invariant. A guest can execute from RAM while
not performing disk I/O. Absence of a disk reference is not itself absence of
vCPU execution.

No global exact-VM termination query, successor-owned termination handle, or
platform-enforced lifetime binding has been established for this construction.
The product therefore does not turn a process/file scan into permission to
clear execution state, release reservations or start a successor. Native
SIGKILL qualification retains the execution witness and refuses the successor;
it does not claim the old VM survived, or infer its termination from silence.

An earlier recovery mechanism requires both a documented lifetime invariant
and an executable test which holds the old VM alive after owner death, proves
presence throughout that interval, independently confirms termination, then
proves absence and successful successor admission. Until both exist, the
refusal remains. This audit does not prove that no future platform mechanism
can provide that boundary.
