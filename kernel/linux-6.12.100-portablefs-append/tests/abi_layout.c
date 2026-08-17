#include <stddef.h>
#include <stdint.h>

#include <linux/falloc.h>
#include <linux/fuse.h>

_Static_assert(FUSE_KERNEL_VERSION == 7, "FUSE major changed");
_Static_assert(FUSE_KERNEL_MINOR_VERSION == 41, "strict ABI minor changed");
_Static_assert(FUSE_PFS_STRICT_COHERENCE == (UINT64_C(1) << 63),
	       "strict capability bit changed");
_Static_assert(FUSE_PFS_CACHED_DATA == (UINT64_C(1) << 62),
	       "cached-data capability bit changed");
_Static_assert(FUSE_PFS_WRITE_ONESHOT == (UINT64_C(1) << 61),
	       "one-shot-write capability bit changed");
_Static_assert(((FUSE_PFS_STRICT_COHERENCE & FUSE_PFS_CACHED_DATA) |
	       (FUSE_PFS_STRICT_COHERENCE & FUSE_PFS_WRITE_ONESHOT) |
	       (FUSE_PFS_CACHED_DATA & FUSE_PFS_WRITE_ONESHOT)) == 0,
	       "private profile revision bits must be distinct");
_Static_assert(FUSE_PFS_UNIQUE_PUBLISH == (UINT64_C(1) << 62),
	       "publication marker changed");
_Static_assert(FUSE_UNIQUE_RESEND == (UINT64_C(1) << 63),
	       "resend marker premise changed");

_Static_assert(FOPEN_PFS_SHARED == (1U << 8), "shared-open bit changed");
_Static_assert(FOPEN_PFS_LOCAL == (1U << 9), "local-open bit changed");
_Static_assert(((FOPEN_PFS_SHARED | FOPEN_PFS_LOCAL) &
	       (FOPEN_DIRECT_IO | FOPEN_KEEP_CACHE | FOPEN_NONSEEKABLE |
		FOPEN_CACHE_DIR | FOPEN_STREAM | FOPEN_NOFLUSH |
		FOPEN_PARALLEL_DIRECT_WRITES | FOPEN_PASSTHROUGH)) == 0,
	       "private open bits collide");
_Static_assert(FUSE_ATTR_PFS_SHARED == (1U << 2),
	       "shared-attr bit changed");
_Static_assert(FUSE_ATTR_PFS_LOCAL == (1U << 3),
	       "local-attr bit changed");
_Static_assert(((FUSE_ATTR_PFS_SHARED | FUSE_ATTR_PFS_LOCAL) &
	       (FUSE_ATTR_SUBMOUNT | FUSE_ATTR_DAX)) == 0,
	       "private attr bits collide");

_Static_assert(CUSE_INIT == 4096, "CUSE collision premise changed");
_Static_assert(FUSE_PFS_WRITE == 4097, "write opcode changed");
_Static_assert(FUSE_PFS_PUBLISH == 4098, "publish opcode changed");
_Static_assert(FUSE_PFS_FALLOCATE == 4099, "fallocate opcode changed");
_Static_assert(FUSE_PFS_COPY_FILE_RANGE == 4100, "copy opcode changed");
_Static_assert(FUSE_NOTIFY_PFS_SIZE == 10, "exact-size notify changed");
_Static_assert(FUSE_TMPFILE == 51, "tmpfile opcode changed");

_Static_assert(FUSE_PFS_WRITE_BEGIN == 1, "BEGIN changed");
_Static_assert(FUSE_PFS_WRITE_DATA == 2, "DATA changed");
_Static_assert(FUSE_PFS_WRITE_COMMIT == 3, "COMMIT changed");
_Static_assert(FUSE_PFS_WRITE_ABORT == 4, "ABORT changed");
_Static_assert(FUSE_PFS_WRITE_ONE_SHOT == 5, "ONE_SHOT changed");
_Static_assert(FUSE_PFS_WRITE_OUT_REJECTED == (1U << 4),
	       "write REJECTED changed");
_Static_assert(FUSE_PFS_WRITE_OUT_POSTAPPLY_ERROR == (1U << 5),
	       "write POSTAPPLY changed");
_Static_assert(FUSE_PFS_WRITE_OUT_REJECTED_RLIMIT == (1U << 6),
	       "write RLIMIT changed");

_Static_assert(sizeof(struct fuse_pfs_write_in) == 80,
	       "write request ABI size changed");
_Static_assert(sizeof(struct fuse_pfs_write_in) > sizeof(struct fuse_write_in),
	       "read-buffer sizing premise changed");
_Static_assert(offsetof(struct fuse_pfs_write_in, position) == 32,
	       "write position offset changed");
_Static_assert(offsetof(struct fuse_pfs_write_in, rlimit_fsize) == 40,
	       "write rlimit offset changed");
_Static_assert(offsetof(struct fuse_pfs_write_in, file_max_size) == 48,
	       "write file-max offset changed");
_Static_assert(offsetof(struct fuse_pfs_write_in, lock_owner) == 56,
	       "write lock-owner offset changed");
_Static_assert(offsetof(struct fuse_pfs_write_in, size) == 64,
	       "write payload-size offset changed");
_Static_assert(offsetof(struct fuse_pfs_write_in, phase) == 76,
	       "write phase offset changed");

_Static_assert(sizeof(struct fuse_pfs_write_out) == 48,
	       "write reply ABI size changed");
_Static_assert(offsetof(struct fuse_pfs_write_out, assigned_offset) == 16,
	       "assigned-offset offset changed");
_Static_assert(offsetof(struct fuse_pfs_write_out, sequence) == 32,
	       "visibility-sequence offset changed");
_Static_assert(offsetof(struct fuse_pfs_write_out, error) == 44,
	       "write error offset changed");

_Static_assert(sizeof(struct fuse_pfs_publish_in) == 32,
	       "publish request ABI size changed");
_Static_assert(sizeof(struct fuse_pfs_publish_out) == 32,
	       "publish reply ABI size changed");
_Static_assert(offsetof(struct fuse_pfs_publish_in, opcode) == 24,
	       "publish opcode offset changed");
_Static_assert(FUSE_PFS_PUBLISH_ACK == 1, "publish ACK changed");

_Static_assert(sizeof(struct fuse_pfs_fallocate_in) == 48,
	       "fallocate input ABI size changed");
_Static_assert(offsetof(struct fuse_pfs_fallocate_in, mode) == 40,
	       "fallocate mode offset changed");
_Static_assert(sizeof(struct fuse_pfs_copy_file_range_in) == 72,
	       "copy-range input ABI size changed");
_Static_assert(offsetof(struct fuse_pfs_copy_file_range_in, write_flags) == 64,
	       "copy-range write-flags offset changed");
_Static_assert(sizeof(struct fuse_pfs_range_out) == 32,
	       "range output ABI size changed");
_Static_assert(offsetof(struct fuse_pfs_range_out, error) == 28,
	       "range error offset changed");

_Static_assert(FUSE_PFS_RANGE_OUT_APPLIED == (1U << 0),
	       "range APPLIED changed");
_Static_assert(FUSE_PFS_RANGE_OUT_REJECTED == (1U << 1),
	       "range REJECTED changed");
_Static_assert(FUSE_PFS_RANGE_OUT_POSTAPPLY_ERROR == (1U << 2),
	       "range POSTAPPLY changed");
_Static_assert(FUSE_PFS_RANGE_OUT_REJECTED_RLIMIT == (1U << 3),
	       "range RLIMIT changed");
_Static_assert(FUSE_PFS_RANGE_OUT_NOOP == (1U << 4),
	       "range NOOP changed");

_Static_assert(FALLOC_FL_KEEP_SIZE == 0x01, "KEEP_SIZE changed");
_Static_assert(FALLOC_FL_PUNCH_HOLE == 0x02, "PUNCH_HOLE changed");
_Static_assert(FALLOC_FL_COLLAPSE_RANGE == 0x08,
	       "COLLAPSE_RANGE changed");
_Static_assert(FALLOC_FL_ZERO_RANGE == 0x10, "ZERO_RANGE changed");
_Static_assert(FALLOC_FL_INSERT_RANGE == 0x20, "INSERT_RANGE changed");
_Static_assert(FALLOC_FL_UNSHARE_RANGE == 0x40, "UNSHARE_RANGE changed");

_Static_assert(sizeof(struct fuse_notify_pfs_size_out) == 24,
	       "size notification ABI size changed");

int main(void)
{
	return 0;
}
