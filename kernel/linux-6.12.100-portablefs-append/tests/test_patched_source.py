#!/usr/bin/env python3
"""Source-structure regressions for the applied Linux 6.12.100 series."""

from __future__ import annotations

import os
from pathlib import Path
import re
import unittest


TREE_VALUE = os.environ.get("PFS_PATCHED_KERNEL_TREE")


@unittest.skipUnless(TREE_VALUE, "PFS_PATCHED_KERNEL_TREE is not set")
class PatchedSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        assert TREE_VALUE is not None
        cls.tree = Path(TREE_VALUE)

    def source(self, name: str) -> str:
        return (self.tree / name).read_text()

    def test_strict_init_is_exact_741_and_indivisible(self) -> None:
        text = self.source("fs/fuse/inode.c")
        needle = "arg->minor != FUSE_KERNEL_MINOR_VERSION"
        self.assertIn(needle, text)
        for required in (
            "FUSE_ATOMIC_O_TRUNC",
            "FUSE_HANDLE_KILLPRIV_V2",
            "FUSE_POSIX_LOCKS",
            "FUSE_FLOCK_LOCKS",
        ):
            self.assertIn(f"!(flags & {required})", text)
        for forbidden in (
            "FUSE_NO_OPEN_SUPPORT",
            "FUSE_NO_OPENDIR_SUPPORT",
            "FUSE_DO_READDIRPLUS",
            "FUSE_READDIRPLUS_AUTO",
            "FUSE_PASSTHROUGH",
            "FUSE_HAS_RESEND",
        ):
            self.assertIn(forbidden, text)

    def test_private_read_header_does_not_reduce_max_write(self) -> None:
        text = self.source("fs/fuse/dev.c")
        self.assertIn(
            "fixed_in = max(fixed_in, sizeof(struct fuse_pfs_write_in))",
            text,
        )
        self.assertIn("fixed_in + fc->max_write", text)

    def test_marked_lookup_survives_an_enclosing_vfs_error(self) -> None:
        text = self.source("fs/fuse/dev.c")
        start = text.index("ssize_t __fuse_simple_request")
        end = text.index("static bool fuse_request_queue_background", start)
        request = text[start:end]
        marker = request.index(
            "else if (reply_success && args->pfs_reply_marked)"
        )
        policy = request.index(
            "token->publish_on_operation_error = "
            "args->opcode == FUSE_LOOKUP",
            marker,
        )
        retain = request.index("__fuse_get_request(req)", marker)
        self.assertLess(policy, retain)
        self.assertIn("positive or a negative", request[marker:retain])

    def test_strict_enosys_and_resend_are_terminal(self) -> None:
        text = self.source("fs/fuse/dev.c")
        self.assertIn(
            "fc->pfs_strict_coherence && req->out.h.error == -ENOSYS",
            text,
        )
        self.assertIn("case FUSE_NOTIFY_RESEND:", text)
        self.assertIn("fc->pfs_strict_coherence", text)

    def test_strict_reverse_notification_surface_is_closed(self) -> None:
        text = self.source("fs/fuse/dev.c")
        start = text.index("static int fuse_notify(struct fuse_conn")
        end = text.index("/* Look up request on processing list", start)
        notify = text[start:end]
        gate = notify.index("if (fc->pfs_strict_coherence &&")
        dispatch = notify.index("switch (code)")
        self.assertLess(gate, dispatch)
        for allowed in (
            "FUSE_NOTIFY_INVAL_INODE",
            "FUSE_NOTIFY_INVAL_ENTRY",
            "FUSE_NOTIFY_DELETE",
            "FUSE_NOTIFY_PFS_SIZE",
        ):
            self.assertIn(f"code != {allowed}", notify[:dispatch])
        self.assertIn("fuse_copy_finish(cs)", notify[gate:dispatch])
        self.assertIn("fuse_abort_conn(fc)", notify[gate:dispatch])
        for forbidden_handler in (
            "fuse_notify_store(fc",
            "fuse_notify_retrieve(fc",
            "fuse_notify_poll(fc",
            "fuse_notify_resend(fc",
        ):
            self.assertGreater(notify.index(forbidden_handler), dispatch)

    def test_strict_stock_reverse_repairs_validate_shape_and_class_first(
        self,
    ) -> None:
        text = self.source("fs/fuse/dev.c")
        target = text[
            text.index("static struct inode *fuse_pfs_notify_target"):
            text.index("static int fuse_notify_inval_inode")
        ]
        self.assertIn("FUSE_PFS_CLASS_SHARED", target)
        self.assertIn("require_dir && !S_ISDIR", target)

        name_validator = text[
            text.index("static bool fuse_pfs_notify_name_valid"):
            text.index("static int fuse_notify_inval_inode")
        ]
        self.assertIn("memchr(name, '\\0', len)", name_validator)
        self.assertIn("memchr(name, '/', len)", name_validator)
        self.assertIn("name[0] == '.'", name_validator)

        inode_repair = text[
            text.index("static int fuse_pfs_reverse_inval_inode"):
            text.index("static int fuse_pfs_reverse_inval_entry")
        ]
        self.assertLess(
            inode_repair.index("fuse_pfs_notify_target"),
            inode_repair.index("fuse_reverse_inval_inode"),
        )
        entry_repair = text[
            text.index("static int fuse_pfs_reverse_inval_entry"):
            text.index("static int fuse_notify_inval_inode")
        ]
        self.assertLess(
            entry_repair.index("fuse_pfs_notify_target"),
            entry_repair.index("fuse_reverse_inval_entry"),
        )

        inode = text[
            text.index("static int fuse_notify_inval_inode"):
            text.index("static int fuse_notify_pfs_size")
        ]
        shape = inode.index(
            "!outarg.ino || outarg.off != -1 || outarg.len != 0"
        )
        repair = inode.index("fuse_pfs_reverse_inval_inode")
        self.assertLess(shape, repair)
        self.assertIn("fuse_abort_conn(fc)", inode)

        entry = text[
            text.index("static int fuse_notify_inval_entry"):
            text.index("static int fuse_notify_delete")
        ]
        self.assertLess(
            entry.index("outarg.flags"),
            entry.index("fuse_pfs_reverse_inval_entry"),
        )
        self.assertLess(
            entry.index("!outarg.parent"),
            entry.index("fuse_pfs_reverse_inval_entry"),
        )
        self.assertLess(
            entry.index("fuse_pfs_notify_name_valid"),
            entry.index("fuse_pfs_reverse_inval_entry"),
        )
        self.assertIn("fuse_abort_conn(fc)", entry)

        delete = text[
            text.index("static int fuse_notify_delete"):
            text.index("static int fuse_notify_store")
        ]
        self.assertIn("outarg.padding", delete)
        self.assertIn("!outarg.parent || !outarg.child", delete)
        self.assertIn("fuse_pfs_notify_name_valid", delete)
        self.assertIn("fuse_pfs_reverse_inval_entry", delete)
        self.assertIn("fuse_abort_conn(fc)", delete)

        pfs_size = text[
            text.index("static int fuse_notify_pfs_size"):
            text.index("static int fuse_notify_inval_entry")
        ]
        for proof in (
            "!outarg.nodeid",
            "!outarg.sequence",
            "outarg.sequence > S64_MAX",
            "outarg.size > S64_MAX",
        ):
            self.assertIn(proof, pfs_size)
        self.assertLess(
            pfs_size.index("!outarg.nodeid"),
            pfs_size.index("fuse_ilookup"),
        )

        directory = self.source("fs/fuse/dir.c")
        start = directory.index("static int fuse_pfs_reverse_expire_entry")
        end = directory.index("int fuse_reverse_inval_entry", start)
        repair = directory[start:end]
        lookup = repair.index("entry = d_lookup")
        child_class = repair.index("FUSE_PFS_CLASS_SHARED", lookup)
        child_identity = repair.index("get_node_id(child)", lookup)
        first_mutation = repair.index("fuse_dir_changed(parent)", lookup)
        self.assertLess(child_class, first_mutation)
        self.assertLess(child_identity, first_mutation)
        self.assertIn("err = -EPROTO", repair[lookup:first_mutation])
        self.assertIn("fuse_invalidate_entry_cache(entry)", repair)
        self.assertIn("fsnotify_name", repair)
        for forbidden in (
            "inode_lock",
            "d_invalidate",
            "d_delete",
            "clear_nlink",
            "dont_mount",
        ):
            self.assertNotIn(forbidden, repair)

        stock_start = directory.index("int fuse_reverse_inval_entry", end)
        stock_end = directory.index(
            "static inline bool fuse_permissible_uidgid", stock_start
        )
        stock = directory[stock_start:stock_end]
        self.assertLess(
            stock.index("if (fc->pfs_strict_coherence)"),
            stock.index("inode_lock_nested(parent"),
        )
        self.assertIn("fuse_pfs_reverse_expire_entry", stock)

    def test_strict_init_forbids_posix_acl_cache_without_publication(self) -> None:
        text = self.source("fs/fuse/inode.c")
        start = text.index("if (flags & FUSE_PFS_STRICT_COHERENCE)")
        end = text.index("if (arg->minor >= 9", start)
        admission = text[start:end]
        self.assertIn("FUSE_POSIX_ACL", admission)
        self.assertIn("ok = false", admission)

    def test_strict_mount_cannot_be_used_as_a_stacked_filesystem_layer(
        self,
    ) -> None:
        text = self.source("fs/fuse/inode.c")
        fill_start = text.index("int fuse_fill_super_common")
        fill_end = text.index("EXPORT_SYMBOL_GPL(fuse_fill_super_common)")
        fill = text[fill_start:fill_end]
        publish = fill.index("sb->s_iflags |= SB_I_REPLY_PUBLISH")
        provisional = fill.index(
            "sb->s_stack_depth = FILESYSTEM_MAX_STACK_DEPTH"
        )
        no_export = fill.index("sb->s_export_op = NULL")
        exposed = fill.index("sb->s_root = root_dentry")
        self.assertLess(publish, exposed)
        self.assertLess(provisional, exposed)
        self.assertLess(no_export, exposed)

        start = text.index("if (flags & FUSE_PFS_STRICT_COHERENCE)")
        end = text.index("if (arg->minor >= 9", start)
        admission = text[start:end]
        self.assertIn("stack_depth = FILESYSTEM_MAX_STACK_DEPTH", admission)
        self.assertIn("export_ops = NULL", admission)

        init_start = text.index("static void process_init_reply")
        init_end = text.index("void fuse_send_init", init_start)
        init_reply = text[init_start:init_end]
        self.assertIn("if (ok) {", init_reply)
        self.assertIn(
            "if (!fc->pfs_strict_coherence)\n"
            "\t\t\t\tfm->sb->s_iflags &= ~SB_I_REPLY_PUBLISH",
            init_reply,
        )
        self.assertIn("fm->sb->s_stack_depth = stack_depth", init_reply)
        self.assertIn("fm->sb->s_export_op = export_ops", init_reply)

        # overlayfs must reject the provisional/strict maximum immediately
        # after resolving a layer.  Its later aggregate-depth check is not an
        # admission boundary: ovl_lower_dir()/ovl_get_upper() call statfs and
        # other filesystem methods before reaching it, which would block on a
        # deliberately delayed FUSE_INIT.
        overlay = self.source("fs/overlayfs/params.c")
        check_start = overlay.index("static int ovl_mount_dir_check")
        check_end = overlay.index("static int ovl_ctx_realloc_lower", check_start)
        check = overlay[check_start:check_end]
        depth_guard = check.index(
            "path->mnt->mnt_sb->s_stack_depth >= "
            "FILESYSTEM_MAX_STACK_DEPTH"
        )
        first_callback_check = check.index("sb_has_encoding")
        self.assertLess(depth_guard, first_callback_check)
        self.assertIn("maximum fs stacking depth exceeded on %s", check)

    def test_remote_authority_file_cannot_back_a_loop_device(self) -> None:
        text = self.source("drivers/block/loop.c")
        start = text.index("static int loop_check_backing_file")
        end = text.index("static int loop_change_fd", start)
        check = text[start:end]
        self.assertIn("file_can_back_independent_cache", check)
        self.assertIn("return -EOPNOTSUPP", check)

    def test_every_in_tree_independent_cache_backend_uses_one_guard(
        self,
    ) -> None:
        header = self.source("include/linux/fs.h")
        helper_start = header.index(
            "static inline bool file_can_back_independent_cache"
        )
        helper_end = header.index("struct file_handle", helper_start)
        helper = header[helper_start:helper_end]
        self.assertIn("FMODE_REMOTE_SIZE_AUTHORITY", helper)

        inventory = {
            "drivers/block/loop.c": 1,
            "drivers/mtd/nand/raw/nandsim.c": 1,
            "drivers/md/md.c": 1,
            "drivers/nvme/target/io-cmd-file.c": 1,
            "drivers/target/target_core_file.c": 2,
            "drivers/usb/gadget/function/storage_common.c": 1,
            "fs/cachefiles/namei.c": 2,
            "fs/coda/file.c": 1,
            "fs/erofs/super.c": 2,
            "mm/swapfile.c": 1,
        }
        for path, expected in inventory.items():
            with self.subTest(path=path):
                text = self.source(path)
                self.assertEqual(
                    text.count("file_can_back_independent_cache("),
                    expected,
                )

        coda = self.source("fs/coda/file.c")
        open_start = coda.index("int coda_open(")
        open_end = coda.index("int coda_release(", open_start)
        reject = coda[open_start:open_end]
        guard = reject.index("file_can_back_independent_cache")
        self.assertGreater(reject.index("venus_close", guard), guard)
        self.assertGreater(reject.index("fput(host_file)", guard), guard)

        ksmbd = self.source("fs/smb/server/smb2pdu.c")
        open_start = ksmbd.index("int smb2_open(")
        lookup = ksmbd.index("ksmbd_vfs_kern_path_locked", open_start)
        existing = ksmbd.index("if (!rc) {", lookup)
        guard = ksmbd.index("SB_I_REPLY_PUBLISH", existing)
        missing = ksmbd.index("} else {", guard)
        self.assertLess(
            lookup, guard
        )
        self.assertLess(existing, guard)
        self.assertLess(guard, missing)
        # ksmbd_vfs_kern_path_locked drops parent_path on -ENOENT.  The
        # existing-target guard must never dereference that released parent;
        # absent creates are guarded by ksmbd_vfs_kern_path_create below.
        self.assertNotIn(
            "parent_path.dentry->d_sb",
            ksmbd[lookup:ksmbd.index("smb2_creat", missing)],
        )
        self.assertLess(guard, ksmbd.index("smb2_creat", guard))
        self.assertLess(guard, ksmbd.index("smb2_set_ea", guard))
        self.assertLess(guard, ksmbd.index("dentry_open", guard))
        self.assertLess(guard, ksmbd.index("ksmbd_open_fd", guard))
        self.assertLess(guard, ksmbd.index("smb_grant_oplock", guard))

        ksmbd_vfs = self.source("fs/smb/server/vfs.c")
        lookup = ksmbd_vfs.index("static int ksmbd_vfs_lookup_in_dir")
        guard = ksmbd_vfs.index("SB_I_REPLY_PUBLISH", lookup)
        self.assertLess(guard, ksmbd_vfs.index("dentry_open", guard))
        self.assertLess(guard, ksmbd_vfs.index("iterate_dir", guard))

        create = ksmbd_vfs.index(
            "struct dentry *ksmbd_vfs_kern_path_create"
        )
        create_end = ksmbd_vfs.index("int ksmbd_vfs_remove_acl_xattrs", create)
        create_path = ksmbd_vfs[create:create_end]
        parent_lookup = create_path.index("vfs_path_parent_lookup")
        create_guard = create_path.index("SB_I_REPLY_PUBLISH")
        self.assertLess(parent_lookup, create_guard)
        self.assertLess(create_guard, create_path.index("mnt_want_write"))
        self.assertLess(create_guard, create_path.index("lookup_one_qstr_excl"))
        self.assertIn("path_put(path)", create_path[create_guard:])
        self.assertIn("putname(filename)", create_path[create_guard:])

    def test_shared_write_requires_outer_core_scope_before_begin(self) -> None:
        text = self.source("fs/fuse/file.c")
        begin = text.index("static ssize_t fuse_file_write_iter")
        end = text.index("static ssize_t fuse_splice_read", begin)
        frontend = text[begin:end]
        self.assertIn("scope->accepts_write_token", frontend)
        self.assertLess(
            frontend.index("scope->accepts_write_token"),
            frontend.index("fuse_pfs_write_transaction"),
        )
        self.assertNotIn("fs_reply_publish_scope_enter_write", frontend)

    def test_shared_splice_read_always_crosses_direct_read_iter(self) -> None:
        text = self.source("fs/fuse/file.c")
        start = text.index("static ssize_t fuse_splice_read")
        end = text.index("static ssize_t fuse_splice_write", start)
        splice_read = text[start:end]
        shared = splice_read.index("ff->open_flags & FOPEN_PFS_SHARED")
        direct = splice_read.index("return copy_splice_read", shared)
        cached = splice_read.index("return filemap_splice_read")
        passthrough = splice_read.index("fuse_file_passthrough")
        self.assertLess(shared, direct)
        self.assertLess(direct, passthrough)
        self.assertLess(direct, cached)

    def test_shared_opendir_forbids_persistent_directory_cache(self) -> None:
        text = self.source("fs/fuse/file.c")
        start = text.index("int fuse_pfs_validate_open")
        end = text.index("struct fuse_file *fuse_file_alloc", start)
        validate = text[start:end]
        self.assertIn("isdir && class_bits == FOPEN_PFS_SHARED", validate)
        self.assertIn("ff->open_flags != FOPEN_PFS_SHARED", validate)

        readdir = self.source("fs/fuse/readdir.c")
        start = readdir.index("int fuse_readdir(struct file")
        frontend = readdir[start:]
        self.assertIn("ff->open_flags & FOPEN_CACHE_DIR", frontend)
        self.assertIn("fuse_readdir_uncached", frontend)

    def test_shared_willneed_cannot_enter_address_space_readahead(self) -> None:
        text = self.source("fs/fuse/file.c")
        start = text.index("static int fuse_file_fadvise")
        end = text.index("static const struct file_operations", start)
        fadvise = text[start:end]
        shared = fadvise.index("ff->open_flags & FOPEN_PFS_SHARED")
        willneed = fadvise.index("advice == POSIX_FADV_WILLNEED", shared)
        generic = fadvise.index("return generic_fadvise", willneed)
        self.assertLess(shared, willneed)
        self.assertLess(willneed, generic)
        self.assertIn("return len < 0 ? -EINVAL : 0", fadvise)

        operations = text[text.index("static const struct file_operations"):]
        self.assertIn(".fadvise\t= fuse_file_fadvise", operations)

    def test_zero_byte_postapply_publishes_attrs_without_byte_progress(self) -> None:
        text = self.source("fs/fuse/file.c")
        write = text[text.index("static ssize_t fuse_pfs_write_transaction"):
                     text.index("static ssize_t fuse_file_read_iter")]
        self.assertIn("!out.committed_size &&", write)
        self.assertIn("out.assigned_offset", write)
        self.assertIn("if (!err && out.committed_size)", write)
        self.assertIn("if (out.committed_size) {", write)
        copy_range = text[text.index("static ssize_t fuse_pfs_copy_file_range"):
                          text.index("static ssize_t fuse_copy_file_range")]
        self.assertIn("!out.result_size &&", copy_range)
        self.assertIn("if (out.result_size)", copy_range)
        self.assertIn("return out.result_size ?: out.error", copy_range)
        io_uring = self.source("io_uring/rw.c")
        self.assertIn("if (ret > 0 || has_applied_bytes)", io_uring)

    def test_splice_forces_an_independent_per_iteration_write_scope(self) -> None:
        splice = self.source("fs/splice.c")
        start = splice.index("iter_file_splice_write(")
        end = splice.index("EXPORT_SYMBOL(iter_file_splice_write)", start)
        helper = splice[start:end]
        self.assertIn("fs_reply_publish_scope_enter_write_child", helper)
        self.assertNotIn("fs_reply_publish_scope_enter_write(&publish_scope",
                         helper)
        core = self.source("fs/reply_publish.c")
        child = core[core.index(
            "void fs_reply_publish_scope_enter_write_child"):]
        self.assertIn("fs_reply_publish_scope_enter(scope, sb)", child)
        self.assertIn("scope->accepts_write_token = scope->active", child)

    def test_boolean_scope_entry_results_are_never_discarded(self) -> None:
        ignored = re.compile(
            r"(?m)^[ \t]+fs_reply_publish_scope_enter_"
            r"(?:write|if_needed)\("
        )
        offenders: list[str] = []
        for directory in ("fs", "io_uring"):
            for path in (self.tree / directory).rglob("*.c"):
                if ignored.search(path.read_text()):
                    offenders.append(str(path.relative_to(self.tree)))
        self.assertEqual(offenders, [])

        for filename in ("fs/aio.c", "fs/read_write.c", "fs/splice.c",
                         "io_uring/rw.c"):
            self.assertIn(
                "fs_reply_publish_scope_enter_write_child",
                self.source(filename),
            )

    def test_full_xfs_fallocate_mode_set_routes_private(self) -> None:
        text = self.source("fs/fuse/file.c")
        start = text.index("static bool fuse_pfs_valid_fallocate_mode")
        end = text.index("static long fuse_pfs_fallocate", start)
        helper = text[start:end]
        for mode in (
            "FALLOC_FL_ALLOCATE_RANGE",
            "FALLOC_FL_KEEP_SIZE",
            "FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE",
            "FALLOC_FL_ZERO_RANGE",
            "FALLOC_FL_COLLAPSE_RANGE",
            "FALLOC_FL_INSERT_RANGE",
            "FALLOC_FL_UNSHARE_RANGE",
        ):
            self.assertIn(mode, helper)
        fallocate = text[text.index("static long fuse_pfs_fallocate"):]
        self.assertIn(".file_max_size = inode->i_sb->s_maxbytes", fallocate)
        self.assertIn("out.post_size", fallocate)

    def test_range_replies_cannot_bypass_eof_or_limit_proofs(self) -> None:
        text = self.source("fs/fuse/file.c")
        fallocate = text[text.index("static long fuse_pfs_fallocate"):
                         text.index("static long fuse_file_fallocate")]
        self.assertIn("mode == FALLOC_FL_COLLAPSE_RANGE", fallocate)
        self.assertIn("out.post_size <= in.offset", fallocate)
        self.assertIn(
            "out.post_size > in.file_max_size - in.length", fallocate
        )
        copy_range = text[text.index("static ssize_t fuse_pfs_copy_file_range"):
                          text.index("static ssize_t fuse_copy_file_range")]
        noop = copy_range[copy_range.index(
            "outcome == FUSE_PFS_RANGE_OUTCOME_NOOP"):
            copy_range.index("if (!applied", copy_range.index(
                "outcome == FUSE_PFS_RANGE_OUTCOME_NOOP"))]
        self.assertIn("in.off_out >= in.file_max_size", noop)
        self.assertIn("in.off_out >= in.rlimit_fsize", noop)

    def test_exact_data_update_locks_mapping_and_invalidates_all_pages(self) -> None:
        text = self.source("fs/fuse/inode.c")
        start = text.index("int fuse_pfs_update_size_locked")
        end = text.index("int fuse_pfs_update_size(", start)
        helper = text[start:end]
        self.assertLess(helper.index("filemap_invalidate_lock(mapping)"),
                        helper.index("i_size_write(inode, size)"))
        self.assertIn("invalidate_inode_pages2(mapping)", helper)
        self.assertLess(helper.index("invalidate_inode_pages2(mapping)"),
                        helper.index("fi->pfs_size_sequence = sequence"))

    def test_rcu_revalidation_never_sleeps_to_invalidate(self) -> None:
        text = self.source("fs/namei.c")
        start = text.index("static inline int d_revalidate")
        end = text.index("static int complete_walk", start)
        helper = text[start:end]
        rcu_return = helper.index("if (flags & LOOKUP_RCU)")
        invalidate = helper.index("d_invalidate(dentry)")
        self.assertLess(rcu_return, invalidate)

    def test_shared_copy_never_reaches_splice_fallback(self) -> None:
        text = self.source("fs/read_write.c")
        checks_start = text.index("static int generic_copy_file_checks")
        vfs_start = text.index("ssize_t vfs_copy_file_range")
        checks = text[checks_start:vfs_start]
        self.assertIn("remote_size_authority && (flags & COPY_FILE_SPLICE)",
                      checks)
        helper = text[vfs_start:text.index("SYSCALL_DEFINE6(copy_file_range",
                                          vfs_start)]
        self.assertIn("do_splice_direct", helper)
        fuse = self.source("fs/fuse/file.c")
        strict = fuse[fuse.index("static ssize_t fuse_copy_file_range"):]
        self.assertIn("return -EXDEV", strict)
        self.assertIn("fuse_pfs_copy_file_range", strict)

    def test_tmpfile_and_create_do_not_cache_enosys_in_strict(self) -> None:
        text = self.source("fs/fuse/dir.c")
        for marker in ("fc->no_create", "fc->no_tmpfile"):
            at = text.index(marker)
            window = text[at:at + 900]
            self.assertIn("fc->pfs_strict_coherence", window)
            self.assertIn("fuse_abort_conn", window)

    def test_publication_scope_is_cleared_at_task_creation(self) -> None:
        text = self.source("kernel/fork.c")
        self.assertIn("p->fs_reply_publish_scope = NULL", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
