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

    def test_strict_init_is_exact_742_and_indivisible(self) -> None:
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
            "FUSE_NOTIFY_PFS_SIZE",
            "FUSE_NOTIFY_PFS_ATTR",
            "FUSE_NOTIFY_PFS_ENTRY",
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

    def test_strict_stamped_reverse_repairs_validate_before_mutation(
        self,
    ) -> None:
        text = self.source("fs/fuse/dev.c")
        target = text[
            text.index("static struct inode *fuse_pfs_notify_target"):
            text.index("static int fuse_notify_pfs_size")
        ]
        self.assertIn("FUSE_PFS_CLASS_SHARED", target)
        self.assertIn("require_dir && !S_ISDIR", target)

        name_validator = text[
            text.index("static bool fuse_pfs_notify_name_valid"):
            text.index("static int fuse_notify_pfs_size")
        ]
        self.assertIn("memchr(name, '\\0', len)", name_validator)
        self.assertIn("memchr(name, '/', len)", name_validator)
        self.assertIn("name[0] == '.'", name_validator)

        pfs_size = text[
            text.index("static int fuse_notify_pfs_size"):
            text.index("static int fuse_notify_pfs_attr")
        ]
        for proof in (
            "!outarg.object.nodeid",
            "!outarg.visibility_sequence",
            "outarg.visibility_sequence > S64_MAX",
        ):
            self.assertIn(proof, pfs_size)
        self.assertLess(
            pfs_size.index("!outarg.object.nodeid"),
            pfs_size.index("fuse_ilookup"),
        )
        self.assertIn("fi->pfs_repairing = true", pfs_size)
        self.assertIn("fuse_pfs_update_size_locked(inode, &outarg.object",
                      pfs_size)

        pfs_attr = text[
            text.index("static int fuse_notify_pfs_attr"):
            text.index("static int fuse_notify_pfs_entry")
        ]
        self.assertLess(
            pfs_attr.index("!outarg.object.nodeid"),
            pfs_attr.index("fuse_pfs_notify_target"),
        )
        self.assertIn("fuse_pfs_install_repair_attr_locked(inode", pfs_attr)
        self.assertNotIn("fuse_invalidate_attr", pfs_attr)

        pfs_entry = text[
            text.index("static int fuse_notify_pfs_entry"):
            text.index("static int fuse_notify_inval_entry")
        ]
        self.assertLess(
            pfs_entry.index("!outarg.parent"),
            pfs_entry.index("fuse_pfs_reverse_entry"),
        )
        self.assertLess(
            pfs_entry.index("fuse_pfs_notify_name_valid"),
            pfs_entry.index("fuse_pfs_reverse_entry"),
        )

        directory = self.source("fs/fuse/dir.c")
        start = directory.index("int fuse_pfs_reverse_entry")
        end = directory.index("int fuse_reverse_inval_entry", start)
        repair = directory[start:end]
        lookup = repair.index("entry = d_lookup")
        child_class = repair.index("FUSE_PFS_CLASS_SHARED", lookup)
        child_identity = repair.index("get_node_id(child)", lookup)
        first_mutation = repair.index("fuse_invalidate_entry_cache(entry)", lookup)
        self.assertLess(child_class, first_mutation)
        self.assertLess(child_identity, first_mutation)
        self.assertIn("err = -EPROTO", repair[lookup:first_mutation])
        self.assertIn("fuse_invalidate_entry_cache(entry)", repair)
        self.assertIn("fsnotify_name", repair)
        self.assertIn("parent_fi->pfs_repairing = true", repair)
        self.assertIn("parent_fi->pfs_entry_repair_sequence", repair)
        self.assertIn("parent_fi->attr_version", repair)
        for forbidden in (
            "inode_lock",
            "d_invalidate",
            "d_delete",
            "clear_nlink",
            "dont_mount",
        ):
            self.assertNotIn(forbidden, repair)

    def test_strict_init_forbids_posix_acl_cache_without_publication(self) -> None:
        text = self.source("fs/fuse/inode.c")
        start = text.index("if (flags & (FUSE_PFS_STRICT_COHERENCE |")
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

        start = text.index("if (flags & (FUSE_PFS_STRICT_COHERENCE |")
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

    def test_shared_splice_read_uses_the_coherent_page_cache(self) -> None:
        text = self.source("fs/fuse/file.c")
        start = text.index("static ssize_t fuse_splice_read")
        end = text.index("static ssize_t fuse_splice_write", start)
        splice_read = text[start:end]
        shared = splice_read.index("ff->open_flags & FOPEN_PFS_SHARED")
        cached = splice_read.index("return filemap_splice_read", shared)
        passthrough = splice_read.index("fuse_file_passthrough")
        self.assertLess(shared, cached)
        self.assertLess(cached, passthrough)
        # The bounce-buffered splice is gone: a spliced folio is filled under
        # the same mapping->invalidate_lock as a read(2) folio and withdrawn by
        # the same ordered DATA publication, so it is exactly as coherent.
        self.assertNotIn("return copy_splice_read", splice_read)

    def test_shared_regular_open_is_exactly_keep_cache(self) -> None:
        text = self.source("fs/fuse/file.c")
        start = text.index("int fuse_pfs_validate_open")
        end = text.index("struct fuse_file *fuse_file_alloc", start)
        validate = text[start:end]
        self.assertIn(
            "ff->open_flags !=\n\t\t    (FOPEN_KEEP_CACHE | FOPEN_PFS_SHARED)",
            validate,
        )
        # No compatibility branch: the retired direct-I/O pair is not accepted
        # anywhere, so a daemon built against the old contract fails closed.
        self.assertNotIn("(FOPEN_DIRECT_IO | FOPEN_PFS_SHARED)", validate)

    def test_shared_reads_are_routed_to_the_cached_path(self) -> None:
        text = self.source("fs/fuse/file.c")
        start = text.index("static ssize_t fuse_file_read_iter")
        end = text.index("static ssize_t fuse_file_write_iter", start)
        read_iter = text[start:end]
        shared = read_iter.index("ff->open_flags & FOPEN_PFS_SHARED")
        cached = read_iter.index("return fuse_cache_read_iter", shared)
        direct = read_iter.index("return fuse_direct_read_iter")
        dax = read_iter.index("FUSE_IS_DAX")
        self.assertLess(shared, cached)
        self.assertLess(cached, dax)
        self.assertLess(cached, direct)

        # Writes are routed by FOPEN_PFS_SHARED, never by direct I/O, which is
        # what makes dropping FOPEN_DIRECT_IO a read-path change only.
        start = text.index("static ssize_t fuse_file_write_iter")
        end = text.index("static ssize_t fuse_splice_read", start)
        write_iter = text[start:end]
        self.assertLess(
            write_iter.index("ff->open_flags & FOPEN_PFS_SHARED"),
            write_iter.index("ff->open_flags & FOPEN_DIRECT_IO"),
        )

        # A cached SHARED read does not revalidate EOF: the ordered DATA
        # publication installs it, and bumps attr_version so a racing GETATTR
        # reply cannot roll it back.
        start = text.index("static ssize_t fuse_cache_read_iter")
        end = text.index("static void fuse_write_args_fill", start)
        cache_read = text[start:end]
        self.assertLess(
            cache_read.index("ff->open_flags & FOPEN_PFS_SHARED"),
            cache_read.index("fc->auto_inval_data"),
        )

    def test_shared_mapping_is_private_read_only_and_never_dirties(
        self,
    ) -> None:
        text = self.source("fs/fuse/file.c")
        start = text.index("static int fuse_file_mmap")
        end = text.index("static int convert_fuse_file_lock", start)
        mmap = text[start:end]
        shared = mmap.index("ff->open_flags & FOPEN_PFS_SHARED")
        refused = mmap.index("vma->vm_flags & VM_MAYSHARE", shared)
        generic = mmap.index("return generic_file_mmap(file, vma)", refused)
        direct = mmap.index("ff->open_flags & FOPEN_DIRECT_IO")
        self.assertLess(shared, refused)
        self.assertLess(refused, generic)
        self.assertLess(generic, direct)
        self.assertIn("return -ENODEV", mmap[refused:generic])

        # A dirty folio is the one thing invalidate_inode_pages2() cannot
        # withdraw, so the buffered write paths fail closed instead of
        # producing one.
        writepages = text[text.index("static int fuse_writepages("):
                          text.index("static int fuse_write_begin")]
        self.assertIn("fc->pfs_strict_coherence", writepages)
        self.assertIn("fuse_abort_conn(fc)", writepages)
        write_begin = text[text.index("static int fuse_write_begin"):
                           text.index("static int fuse_write_end")]
        self.assertIn("fc->pfs_strict_coherence", write_begin)
        self.assertIn("fuse_abort_conn(fc)", write_begin)

    def test_exact_data_publication_is_ordered_under_the_invalidate_lock(
        self,
    ) -> None:
        text = self.source("fs/fuse/inode.c")
        start = text.index("int fuse_pfs_update_size_locked")
        end = text.index("int fuse_pfs_withdraw_data", start)
        publish = text[start:end]
        # Ordering is by sequence only. A same-length overwrite carries a
        # strictly greater sequence and therefore reaches the invalidation;
        # nothing short-circuits on an unchanged i_size.
        self.assertLess(
            publish.index("sequence < fi->pfs_size_sequence"),
            publish.index("filemap_invalidate_lock(mapping)"),
        )
        self.assertLess(
            publish.index("filemap_invalidate_lock(mapping)"),
            publish.index("invalidate_inode_pages2(mapping)"),
        )
        self.assertNotIn("size == i_size_read", publish)
        self.assertLess(
            publish.index("invalidate_inode_pages2(mapping)"),
            publish.index("fi->pfs_size_sequence = sequence"),
        )

    def test_revocation_withdraws_pages_under_the_publication_locks(
        self,
    ) -> None:
        text = self.source("fs/fuse/inode.c")
        start = text.index("int fuse_pfs_withdraw_data")
        end = text.index("static void fuse_init_submount_lookup", start)
        withdraw = text[start:end]
        self.assertIn("fi->pfs_class != FUSE_PFS_CLASS_SHARED", withdraw)
        self.assertLess(
            withdraw.index("mutex_lock(&fi->pfs_publish_mutex)"),
            withdraw.index("filemap_invalidate_lock(mapping)"),
        )
        self.assertLess(
            withdraw.index("filemap_invalidate_lock(mapping)"),
            withdraw.index("invalidate_inode_pages2(mapping)"),
        )
        # A withdrawal carries no authority sequence and must not consume one.
        self.assertNotIn("pfs_size_sequence", withdraw)

        dev = self.source("fs/fuse/dev.c")
        start = dev.index("static int fuse_pfs_reverse_inval_inode")
        end = dev.index("static int fuse_pfs_reverse_inval_entry", start)
        notify = dev[start:end]
        self.assertLess(
            notify.index("off == 0 && len == 0"),
            notify.index("fuse_pfs_withdraw_data(target)"),
        )
        self.assertIn("fuse_reverse_inval_inode(fc, nodeid, off, len)", notify)

    def test_post_state_installer_snapshots_before_stores_and_invalidates_range(
        self,
    ) -> None:
        text = self.source("fs/fuse/post_state.c")
        start = text.index("int fuse_pfs_install_post_state")
        installer = text[start:]
        snapshot = installer.index("NEW-A: this loop is the complete step-3 snapshot")
        compare = installer.index("records[i].install_attr", snapshot)
        first_store = installer.index("fuse_change_attributes_common", compare)
        self.assertLess(snapshot, compare)
        self.assertLess(compare, first_store)
        self.assertNotIn("fuse_change_attributes_common", installer[snapshot:compare])
        self.assertLess(
            installer.index("state->header.snapshot_sequence <= parent_prior", compare),
            first_store,
        )
        self.assertIn("invalidate_inode_pages2_range", installer)
        self.assertIn("unmap_mapping_pages", installer)
        self.assertNotIn("truncate_pagecache", installer)
        self.assertNotIn("invalidate_inode_pages2(data_inode->i_mapping)", installer)
        self.assertLess(
            installer.index("fi->attr_version =", first_store),
            installer.index("fi->pfs_object_version =", first_store),
        )

    def test_post_state_variable_length_is_not_a_vfs_result(self) -> None:
        post_state = self.source("fs/fuse/post_state.c")
        args = post_state[
            post_state.index("void fuse_pfs_post_state_args"):
            post_state.index("static struct inode *pfs_find_inode")
        ]
        self.assertIn("args->out_argvar = true", args)
        self.assertIn("args->pfs_post_state = true", args)

        dev = self.source("fs/fuse/dev.c")
        request = dev[
            dev.index("ssize_t __fuse_simple_request"):
            dev.index("static bool fuse_request_queue_background")
        ]
        variable = request[
            request.index("if (!ret && args->out_argvar)"):
            request.index("if (fc->pfs_strict_coherence", request.index("if (!ret && args->out_argvar)"))
        ]
        self.assertIn(
            "if (!args->pfs_post_state && !args->pfs_cache_stamp)", variable
        )
        self.assertIn("ret = args->out_args[args->out_numargs - 1].size", variable)

    def test_post_state_inode_flags_are_masked_statx_attributes(self) -> None:
        text = self.source("fs/fuse/post_state.c")
        start = text.index("static void pfs_install_statx_attributes")
        end = text.index("static int pfs_install_stamped_attr", start)
        install = text[start:end]
        self.assertIn("STATX_ATTR_IMMUTABLE", install)
        self.assertIn("STATX_ATTR_APPEND", install)
        self.assertNotIn("FS_IMMUTABLE_FL", install)
        self.assertNotIn("FS_APPEND_FL", install)
        self.assertNotIn("S_ATTR_INEXACT", install)

        stamped = text[
            text.index("static int pfs_install_stamped_attr"):
            text.index("int fuse_pfs_install_repair_attr_locked")
        ]
        self.assertIn("stamp->birth_time_ns", stamped)
        self.assertIn("stamp->inode_flags", stamped)
        self.assertIn("stamp->object_version <= fi->pfs_object_version", stamped)

        repair = text[
            text.index("int fuse_pfs_install_repair_attr_locked"):
            text.index("int fuse_pfs_install_lookup")
        ]
        for source in (
            "object->object_version > visibility_sequence",
            "object->attr.flags != FUSE_ATTR_PFS_SHARED",
            "pfs_install_exact_attr_locked",
            "fuse_change_attributes_common",
            "fi->attr_version = atomic64_inc_return",
            "fi->pfs_object_version = object->object_version",
        ):
            self.assertIn(source, repair)
        self.assertNotIn("fuse_invalidate_attr", repair)

        fill_start = text.index("int fuse_pfs_fill_exact_statx")
        fill_end = text.index("static int pfs_install_stamped_attr", fill_start)
        fill = text[fill_start:fill_end]
        for source in (
            "stat->btime = fi->i_btime",
            "stat->result_mask |= STATX_BTIME",
            "stat->attributes = fi->pfs_inode_flags",
            "stat->attributes_mask |= FUSE_PFS_STATX_ATTRIBUTES",
        ):
            self.assertIn(source, fill)
        self.assertNotIn("EAGAIN", fill)

        directory = self.source("fs/fuse/dir.c")
        getattr = directory[
            directory.index("static int fuse_update_get_attr"):
            directory.index("int fuse_update_attributes")
        ]
        self.assertIn("fuse_pfs_fill_exact_statx(inode, stat)", getattr)

        all_sources = "\n".join(
            self.source(path) for path in (
                "fs/attr.c", "fs/exec.c", "fs/fcntl.c", "fs/inode.c",
                "fs/ioctl.c", "fs/locks.c", "fs/namei.c", "fs/open.c",
                "fs/read_write.c", "fs/remap_range.c", "fs/xattr.c",
                "include/linux/fs.h", "mm/mmap.c", "fs/fuse/dir.c",
                "fs/fuse/inode.c", "fs/fuse/post_state.c",
            )
        )
        for forbidden in (
            "S_ATTR_INEXACT", "attr_repair_sequence",
            "begin_attr_exact", "end_attr_exact",
            "refresh_attr_exact", "permission_attr_exact",
            "fuse_pfs_attr_is_exact",
        ):
            self.assertNotIn(forbidden, all_sources)

    def test_existing_create_and_negative_lookup_have_distinct_exact_shapes(
        self,
    ) -> None:
        post_state = self.source("fs/fuse/post_state.c")
        roles = post_state[
            post_state.index("static bool pfs_valid_roles"):
            post_state.index("void fuse_pfs_post_state_args")
        ]
        self.assertIn(
            "static const u32 existing[] = { PFS_ROLE_TARGET, PFS_ROLE_PARENT }",
            roles,
        )
        self.assertIn("fuse_pfs_existing_create", roles)

        directory = self.source("fs/fuse/dir.c")
        create = directory[
            directory.index("static int fuse_create_open"):
            directory.index("static int fuse_mknod")
        ]
        self.assertIn("fuse_pfs_existing_create(&post_state)", create)
        self.assertIn("ARRAY_SIZE(inodes)", create)
        self.assertNotIn("post_state.header.object_count == 1", create)

        lookup = directory[
            directory.index("int fuse_lookup_name"):
            directory.index("static struct dentry *fuse_lookup")
        ]
        self.assertIn("err == -ENOENT", lookup)
        self.assertIn("fuse_abort_conn(fm->fc)", lookup)
        self.assertIn("fuse_pfs_install_lookup(parent, NULL", lookup)
        self.assertIn("fuse_pfs_classify_lookup_result(fm, &args, outarg)", lookup)
        self.assertIn("args.out_argvar = true", lookup)
        self.assertIn("args.pfs_cache_stamp = true", lookup)

        local_shape = directory[
            directory.index("enum fuse_pfs_lookup_shape"):
            directory.index("static int fuse_dentry_revalidate")
        ]
        for shape in (
            "FUSE_PFS_LOOKUP_LOCAL_NEGATIVE",
            "FUSE_PFS_LOOKUP_SHARED_NEGATIVE",
            "FUSE_PFS_LOOKUP_LOCAL_POSITIVE",
            "FUSE_PFS_LOOKUP_SHARED_POSITIVE",
        ):
            self.assertIn(shape, local_shape)
        self.assertIn("expected.attr.flags = FUSE_ATTR_PFS_LOCAL", local_shape)
        self.assertIn("!memcmp(outarg, &expected, sizeof(expected))", local_shape)
        self.assertNotIn("fuse_pfs_lookup_has_stamp", local_shape)
        self.assertIn("args->out_numargs != 2", local_shape)
        self.assertIn("stamp_size = args->out_args[1].size", local_shape)
        self.assertIn("rule->stamp_size != stamp_size", local_shape)
        for exact_size in (
            ".stamp_size = 0",
            ".stamp_size = sizeof(struct fuse_pfs_cache_stamp)",
        ):
            self.assertIn(exact_size, local_shape)
        self.assertIn("rule->marked != args->pfs_reply_marked", local_shape)

        stamped = self.source("fs/fuse/post_state.c")
        negative = stamped[
            stamped.index("int fuse_pfs_install_lookup"):
            stamped.index("int fuse_pfs_install_getattr")
        ]
        self.assertIn("memcmp(&entry->attr, &empty_attr", negative)

        dev = self.source("fs/fuse/dev.c")
        request = dev[
            dev.index("ssize_t __fuse_simple_request"):
            dev.index("static bool fuse_request_queue_background")
        ]
        self.assertIn(
            "if (!args->pfs_post_state && !args->pfs_cache_stamp)", request
        )

    def test_marked_readdirplus_failure_drains_unlinked_lookup_ownership(
        self,
    ) -> None:
        readdir = self.source("fs/fuse/readdir.c")
        helper = readdir[
            readdir.index("static void fuse_pfs_forget_dirplus_tail"):
            readdir.index("static int parse_dirplusfile")
        ]
        self.assertIn("while (nbytes >= FUSE_NAME_OFFSET_PFS_DIRENTPLUS)", helper)
        self.assertIn("fuse_force_forget(file, record->entry_out.nodeid)", helper)

        stock = readdir[
            readdir.index("static int parse_dirplusfile"):
            readdir.index("static int parse_pfs_dirplusfile")
        ]
        self.assertNotIn("fuse_pfs_forget_dirplus_tail", stock)

        strict = readdir[
            readdir.index("static int parse_pfs_dirplusfile"):
            readdir.index("static int fuse_readdir_uncached")
        ]
        link_failure = strict.index("if (ret) {")
        forget_failed = strict.index("fuse_force_forget", link_failure)
        drain_tail = strict.index("fuse_pfs_forget_dirplus_tail", forget_failed)
        abort = strict.index("fuse_abort_conn", drain_tail)
        return_failure = strict.index("return -ENOTCONN", abort)
        self.assertLess(forget_failed, drain_tail)
        self.assertLess(drain_tail, abort)
        self.assertLess(abort, return_failure)

    def test_strict_init_requires_the_whole_one_shot_profile(self) -> None:
        text = self.source("fs/fuse/inode.c")
        start = text.index("if (flags & (FUSE_PFS_STRICT_COHERENCE |")
        end = text.index("if (arg->minor >= 9", start)
        admission = text[start:end]
        # Any incomplete three-bit revision is a version mismatch and fails
        # the mount before the first write can select a different shape.
        self.assertEqual(admission.count("FUSE_PFS_WRITE_ONESHOT"), 3)
        self.assertIn("The three private bits are one indivisible", admission)
        self.assertIn("(flags & FUSE_AUTO_INVAL_DATA)", admission)
        self.assertIn("!(flags & FUSE_EXPLICIT_INVAL_DATA)", admission)
        self.assertIn("ok = false", admission)

        send = text[text.index("void fuse_send_init"):]
        self.assertRegex(
            send,
            r"FUSE_PFS_STRICT_COHERENCE \| FUSE_PFS_CACHED_DATA \|\s+"
            r"FUSE_PFS_WRITE_ONESHOT",
        )

        # The negotiated read-ahead window is taken exactly rather than clamped
        # to the generic default: it is what bounds how many authority round
        # trips a sequential reader pays.
        init_reply = text[text.index("static void process_init_reply"):
                          text.index("void fuse_send_init")]
        self.assertIn("fm->sb->s_bdi->ra_pages = ra_pages;", init_reply)

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

    def test_willneed_prefetch_is_admitted_again(self) -> None:
        text = self.source("fs/fuse/file.c")
        # The override existed only to keep a direct-I/O SHARED handle's page
        # cache empty. Prefetch now reaches page_cache_ra_unbounded(), which
        # fills under mapping->invalidate_lock held shared, so it is withdrawn
        # by the ordered DATA publication like any other folio.
        self.assertNotIn("static int fuse_file_fadvise", text)
        operations = text[text.index("static const struct file_operations"):]
        self.assertNotIn(".fadvise\t=", operations)

    def test_zero_byte_postapply_publishes_attrs_without_byte_progress(self) -> None:
        text = self.source("fs/fuse/file.c")
        write = text[text.index("static ssize_t fuse_pfs_finish_write"):
                     text.index("static ssize_t fuse_pfs_write_one_shot")]
        self.assertIn("!out->committed_size &&", write)
        self.assertIn("out->assigned_offset", write)
        self.assertIn("if (out->committed_size) {", write)
        request = text[text.index("static int fuse_pfs_write_control"):
                       text.index("static void fuse_pfs_write_abort")]
        self.assertIn("if (committed) {", request)
        self.assertIn("fuse_pfs_install_post_state", request)
        copy_range = text[text.index("static ssize_t fuse_pfs_copy_file_range"):
                          text.index("static ssize_t fuse_copy_file_range")]
        self.assertIn("!out.result_size &&", copy_range)
        self.assertIn("if (out.result_size)", copy_range)
        self.assertIn("return out.result_size ?: out.error", copy_range)
        io_uring = self.source("io_uring/rw.c")
        self.assertIn("if (ret > 0 || has_applied_bytes)", io_uring)

    def test_one_fragment_write_has_one_deterministic_mutating_shape(self) -> None:
        text = self.source("fs/fuse/file.c")
        one_shot = text[text.index("static ssize_t fuse_pfs_write_one_shot"):
                        text.index("static bool fuse_pfs_write_fits_one_shot")]
        self.assertIn("FUSE_PFS_WRITE_ONE_SHOT", one_shot)
        self.assertEqual(one_shot.count("fuse_pfs_write_payload_send"), 1)
        self.assertNotIn("atomic64_inc_return", one_shot)
        self.assertNotIn("FUSE_PFS_WRITE_BEGIN", one_shot)
        self.assertNotIn("FUSE_PFS_WRITE_COMMIT", one_shot)
        self.assertIn(
            "!extract_err && nbytes != frozen->requested_size", one_shot
        )

        capacity = text[
            text.index("static bool fuse_pfs_write_fits_one_shot"):
            text.index("static ssize_t fuse_pfs_write_transaction")
        ]
        self.assertIn("requested > fc->max_write", capacity)
        self.assertIn("iov_iter_is_kvec(from)", capacity)
        self.assertIn("iov_iter_single_seg_count(from) == requested", capacity)
        self.assertIn(
            "iov_iter_npages(from, fc->max_pages + 1) <= fc->max_pages",
            capacity,
        )

        transaction = text[
            text.index("static ssize_t fuse_pfs_write_transaction"):
            text.index("static ssize_t fuse_file_read_iter")
        ]
        boundary = transaction.index(
            "if (fuse_pfs_write_fits_one_shot(fc, from, requested))"
        )
        txid = transaction.index("atomic64_inc_return(&fc->pfs_write_txid)")
        self.assertLess(boundary, txid)
        self.assertIn(
            "fuse_pfs_write_in_freeze(&frozen, iocb, 0, requested",
            transaction[:txid],
        )
        self.assertIn("FUSE_PFS_WRITE_BEGIN", transaction[txid:])
        self.assertIn("FUSE_PFS_WRITE_DATA", transaction[txid:])
        self.assertIn("FUSE_PFS_WRITE_COMMIT", transaction[txid:])
        self.assertIn("while (iov_iter_count(from))", transaction[txid:])
        self.assertIn("advanced += nbytes", transaction[txid:])

        payload_args = text[
            text.index("static void fuse_pfs_write_payload_args"):
            text.index("static int fuse_pfs_write_payload_send")
        ]
        self.assertIn("args->force = true", payload_args)
        self.assertIn(
            "args->pfs_publish_policy = FUSE_PFS_PUBLISH_OPTIONAL",
            payload_args,
        )

        dev = self.source("fs/fuse/dev.c")
        marked_start = dev.index("req->in.h.opcode == FUSE_PFS_PUBLISH")
        marked = dev[marked_start:
                     dev.index("/* Is it an interrupt reply ID? */", marked_start)]
        self.assertIn("FUSE_PFS_WRITE_ONE_SHOT", marked)

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
        end = text.index("int fuse_pfs_withdraw_data", start)
        helper = text[start:end]
        self.assertLess(helper.index("filemap_invalidate_lock(mapping)"),
                        helper.index("invalidate_inode_pages2(mapping)"))
        self.assertIn("invalidate_inode_pages2(mapping)", helper)
        self.assertLess(helper.index("invalidate_inode_pages2(mapping)"),
                        helper.index("fuse_pfs_install_repair_attr_locked"))
        self.assertLess(helper.index("fuse_pfs_install_repair_attr_locked"),
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
