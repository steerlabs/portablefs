# The Windows Mount Gate

Status: **unsupported, fail closed**

PortableFS does not currently build or mount on Windows. There is no Windows
release artifact, client installer, or driver install path. This is not just a
packaging or UI gap: the available signed user-mode filesystem runtimes do not
expose the exact kernel primitives needed to preserve the v3 multi-writer
contract. The pure platform selector records the fail-closed answer, and any
future Windows client build must reach it before attach. There is no driver
dependency, fallback transport, or local cache to install.

## The two hard blockers

A Windows frontend must prove both properties at the same time:

1. Every Windows byte-range lock and unlock, including shared versus exclusive,
   blocking versus fail-immediately, owner/key, and unlock-all behavior, is
   decided by the one XFS authority. A lock that exists only in one Windows
   kernel does not exclude a Linux, macOS, or second Windows writer.
2. Ordinary reads and writes have no machine-local data truth, and file-backed
   mappings are refused. Any metadata caching must participate in the same
   synchronous PREPARE/COMPLETE visibility barrier as the other strict mounts.
   An asynchronous notification is not a coherence acknowledgement.

Neither evaluated runtime meets both requirements.

### WinFsp

[WinFsp 2026 Beta4](https://github.com/winfsp/winfsp/releases/tag/v2.2B4)
can disable the Cache Manager for an opened file through its `DisableCache`
response. That makes it the stronger data-I/O candidate. But its
[`IRP_MJ_LOCK_CONTROL` path](https://github.com/winfsp/winfsp/blob/v2.2B4/src/sys/lockctl.c)
always calls the kernel-local `FspFileNodeProcessLockIrp`, which delegates to
`FsRtlProcessFileLock`. The
[`FSP_FSCTL_VOLUME_PARAMS` flags](https://github.com/winfsp/winfsp/blob/v2.2B4/inc/winfsp/fsctl.h)
contain no lock-forwarding or fail-all-locks mode, and the
[native filesystem interface](https://github.com/winfsp/winfsp/blob/v2.2B4/inc/winfsp/winfsp.h)
has no lock callback. A Windows lock can therefore succeed without the
PortableFS authority ever seeing it.

WinFsp is GPLv3. Its
[license exception](https://github.com/winfsp/winfsp/blob/v2.2B4/License.txt)
permits FLOSS to link the platform DLL and redistribute the unmodified official
installer when its attribution and no-proprietary-mixing conditions are met;
its official Go binding is MIT. Those terms can be evaluated if the missing
primitive is added upstream, but licensing does not repair the semantic gap.

### Dokany

[Dokany 2.3.1](https://github.com/dokan-dev/dokany/releases/tag/v2.3.1.1000)
has a `DOKAN_OPTION_FILELOCK_USER_MODE` option and public `LockFile` and
`UnlockFile` callbacks. Its current callback, however, receives only a path,
offset, length, and generic request context. The
[user-mode dispatch](https://github.com/dokan-dev/dokany/blob/v2.3.1.1000/dokan/lock.c)
does not pass the kernel lock key and the public API does not expose
shared/exclusive or wait/fail-immediately intent. Unlock failure is reported to
the kernel as success, while unlock-all and unlock-by-key are not forwarded.
That cannot be mapped exactly to the authority's lock operation.

Dokany also exposes no mount option that forces all opens to bypass the Cache
Manager or disables oplocks. Its
[documented operations](https://dokan-dev.github.io/dokany-doc/html/struct_d_o_k_a_n___o_p_e_r_a_t_i_o_n_s.html)
explicitly support paging I/O from memory-mapped files, and the driver uses
Cache Manager flush and purge paths. It therefore has no supported synchronous
cache barrier on which PortableFS can base strict cross-machine visibility.

Dokany's driver, DLL, and installer are LGPL and its releases include signed
drivers. Dynamic use may be compatible with an Apache-2.0 application when the
LGPL distribution obligations are met, but licensing is again downstream of
the missing primitives.

## Rejected Windows storage APIs

Microsoft's
[Projected File System](https://learn.microsoft.com/en-us/windows/win32/projfs/projected-file-system)
and [Cloud Files API](https://learn.microsoft.com/en-us/windows/win32/cfapi/cloud-files-api-portal)
are projection and sync-provider APIs. Their hydrated or dirty local files and
placeholders create a second machine-local filesystem truth. They are suitable
for source projections or sync clients, not a write-through PortableFS mount.
SMB or NFS would introduce a second data-plane protocol and identity boundary
instead of carrying the existing authority protocol, so they are not fallback
strategies.

Archil is not a Windows implementation reference. Its current
[public architecture](https://docs.archil.com/details/architecture) describes a
Linux client, and its [documentation index](https://docs.archil.com/llms.txt)
publishes mount guides for Linux and macOS but not Windows.

## Gates for a future Windows transport

Declaring Windows support requires one signed, supported native runtime that
passes all of these gates; none may be emulated by a local write-back store:

- uncached, write-through file I/O with shared file-backed mapping refused;
- exact authority-forwarded byte-range locks and owner cleanup;
- synchronous namespace and metadata repair before a peer mutation returns;
- authority-enforced Windows share/delete/open semantics across machines;
- open-after-unlink and atomic rename tests against Linux and macOS peers;
- an immutable, authority-enforced Windows-safe namespace profile. Windows
  cannot address every raw POSIX name: it reserves characters and device names,
  trims trailing dots/spaces in common APIs, and normally compares names without
  case. The profile must constrain every writer, not hide names only on Windows.
  See Microsoft's [file naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
  and [case-sensitivity guidance](https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity);
- clean driver installation, upgrade, rollback, crash, detach, and forced-fence
  batteries on a supported and fully patched Windows 11 release;
- pinned release identity, installer hash verification, signature verification,
  and complete third-party license notices.

The preferred path is an upstream WinFsp or Dokany primitive that meets these
gates. A PortableFS-specific kernel driver is a last resort: it adds Windows
Driver Kit, signing, HLK, crash-safety, servicing, and long-term kernel support
responsibilities to the product.
