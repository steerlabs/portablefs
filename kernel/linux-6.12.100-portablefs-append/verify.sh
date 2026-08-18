#!/usr/bin/env bash
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly CACHE_DIR="${PFS_KERNEL_SOURCE_CACHE:-/tmp/portablefs-kernel-source-cache}"
readonly UPSTREAM_ARCHIVE="$CACHE_DIR/linux-6.12.100.tar.xz"
readonly DEBIAN_ORIG="$CACHE_DIR/linux_6.12.100.orig.tar.xz"
readonly DEBIAN_PATCHES="$CACHE_DIR/linux_6.12.100-1.debian.tar.xz"
readonly UPSTREAM_SHA="67f973533406492e86774bacbcefae50d50d5c34cbf703c47ec526a5efdcee90"
readonly DEBIAN_ORIG_SHA="d352d8271fafd61d76b01326fbddef24848d498adb8eace1cc208d04663cc22e"
readonly DEBIAN_PATCHES_SHA="c345b6b78e43f8e80580e15869d17828ed8eff44ac62e00965c2033006230a15"
# The build image is digest-pinned and already carries the system CA bundle.
# A minimal floating Debian tag has neither property: rewriting its sources to
# HTTPS before installing ca-certificates makes a clean verifier unable to
# bootstrap, while leaving the tag floating makes yesterday's qualification
# irreproducible tomorrow. Keep this identical to the privileged userspace CI
# toolchain image so both sides compile against one named environment.
readonly BUILD_IMAGE="golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36"

BUILD=1
if [[ "${1:-}" == "--no-build" ]]; then
  BUILD=0
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--no-build]" >&2
  exit 2
fi

for command_name in cc curl git patch python3 tar; do
  command -v "$command_name" >/dev/null || {
    echo "missing required command: $command_name" >&2
    exit 1
  }
done

mkdir -p "$CACHE_DIR"

download() {
  local url="$1"
  local output="$2"

  if [[ ! -f "$output" ]]; then
    curl --fail --location --retry 5 --output "$output" "$url"
  fi
}

file_sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

verify_hash() {
  local path="$1"
  local expected="$2"
  local actual

  actual="$(file_sha256 "$path")"
  if [[ "$actual" != "$expected" ]]; then
    echo "SHA-256 mismatch for $path" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi
}

download "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.100.tar.xz" "$UPSTREAM_ARCHIVE"
download "https://deb.debian.org/debian/pool/main/l/linux/linux_6.12.100.orig.tar.xz" "$DEBIAN_ORIG"
download "https://deb.debian.org/debian/pool/main/l/linux/linux_6.12.100-1.debian.tar.xz" "$DEBIAN_PATCHES"

verify_hash "$UPSTREAM_ARCHIVE" "$UPSTREAM_SHA"
verify_hash "$DEBIAN_ORIG" "$DEBIAN_ORIG_SHA"
verify_hash "$DEBIAN_PATCHES" "$DEBIAN_PATCHES_SHA"

WORK_DIR="$(mktemp -d /tmp/portablefs-kernel-verify.XXXXXX)"
CONTAINER_ID=""
cleanup() {
  if [[ -n "$CONTAINER_ID" ]]; then
    docker rm --force "$CONTAINER_ID" >/dev/null 2>&1 || true
  fi
  case "$WORK_DIR" in
    /tmp/portablefs-kernel-verify.*) rm -rf -- "$WORK_DIR" ;;
    *) echo "refusing to clean unexpected path: $WORK_DIR" >&2 ;;
  esac
}
trap cleanup EXIT

readonly UPSTREAM_TREE="$WORK_DIR/upstream"
readonly DEBIAN_TREE="$WORK_DIR/debian"
mkdir -p "$UPSTREAM_TREE" "$DEBIAN_TREE"
tar -C "$UPSTREAM_TREE" --strip-components=1 -xf "$UPSTREAM_ARCHIVE"
tar -C "$DEBIAN_TREE" --strip-components=1 -xf "$DEBIAN_ORIG"
tar -C "$DEBIAN_TREE" -xf "$DEBIAN_PATCHES"

while IFS= read -r patch_name; do
  [[ -z "$patch_name" || "$patch_name" == \#* ]] && continue
  patch -d "$DEBIAN_TREE" -p1 -t -N -s < "$DEBIAN_TREE/debian/patches/$patch_name"
done < "$DEBIAN_TREE/debian/patches/series"

PFS_PATCHES=()
while IFS= read -r patch_name; do
  [[ -z "$patch_name" || "$patch_name" == \#* ]] && continue
  PFS_PATCHES+=("$SCRIPT_DIR/$patch_name")
done < "$SCRIPT_DIR/series"
if [[ ${#PFS_PATCHES[@]} -eq 0 ]]; then
  echo "empty PortableFS patch series" >&2
  exit 1
fi

for patch_path in "${PFS_PATCHES[@]}"; do
  # This is an ordered series: later commits may intentionally refine a line
  # introduced by an earlier patch, so validate and apply one commit at a time.
  git -C "$UPSTREAM_TREE" apply --check "$patch_path"
  git -C "$UPSTREAM_TREE" apply "$patch_path"
  git -C "$DEBIAN_TREE" apply --check "$patch_path"
  git -C "$DEBIAN_TREE" apply "$patch_path"
done

readonly -a AFFECTED_FILES=(
  "drivers/block/loop.c"
  "drivers/mtd/nand/raw/nandsim.c"
  "drivers/md/md.c"
  "drivers/nvme/target/io-cmd-file.c"
  "drivers/target/target_core_file.c"
  "drivers/usb/gadget/function/storage_common.c"
  "fs/Makefile"
  "fs/aio.c"
  "fs/cachefiles/namei.c"
  "fs/coda/file.c"
  "fs/erofs/super.c"
  "fs/attr.c"
  "fs/fuse/dev.c"
  "fs/fuse/dir.c"
  "fs/fuse/file.c"
  "fs/fuse/fuse_i.h"
  "fs/fuse/fuse_trace.h"
  "fs/fuse/inode.c"
  "fs/fuse/ioctl.c"
  "fs/fuse/post_state.c"
  "fs/fuse/readdir.c"
  "fs/fuse/xattr.c"
  "fs/namei.c"
  "fs/open.c"
  "fs/overlayfs/params.c"
  "fs/read_write.c"
  "fs/reply_publish.c"
  "fs/smb/server/smb2pdu.c"
  "fs/smb/server/vfs.c"
  "fs/splice.c"
  "fs/xattr.c"
  "include/linux/fs.h"
  "include/linux/fs_reply_publish.h"
  "include/linux/sched.h"
  "include/uapi/linux/fuse.h"
  "io_uring/rw.c"
  "kernel/fork.c"
  "mm/swapfile.c"
)
for relative_path in "${AFFECTED_FILES[@]}"; do
  test -f "$UPSTREAM_TREE/$relative_path"
  test -f "$DEBIAN_TREE/$relative_path"
done

verify_patched_tree() {
  local tree="$1"
  local label="$2"
  local abi_header="$tree/include/uapi/linux/fuse.h"
  local abi_binary="$WORK_DIR/abi_layout-$label"

  grep -Eq '^#define FUSE_PFS_STRICT_COHERENCE[[:space:]]+\(1ULL << 63\)$' "$abi_header"
  grep -Eq '^#define FUSE_PFS_CACHED_DATA[[:space:]]+\(1ULL << 62\)$' "$abi_header"
  grep -Eq '^#define FUSE_PFS_WRITE_ONESHOT[[:space:]]+\(1ULL << 61\)$' "$abi_header"
  grep -Eq '^#define FOPEN_PFS_SHARED[[:space:]]+\(1 << 8\)$' "$abi_header"
  grep -Eq '^#define FOPEN_PFS_LOCAL[[:space:]]+\(1 << 9\)$' "$abi_header"
  grep -Eq '^[[:space:]]*FUSE_PFS_WRITE[[:space:]]*=[[:space:]]*4097,$' "$abi_header"
  grep -Eq '^[[:space:]]*FUSE_PFS_PUBLISH[[:space:]]*=[[:space:]]*4098,$' "$abi_header"
  grep -Eq '^[[:space:]]*FUSE_PFS_FALLOCATE[[:space:]]*=[[:space:]]*4099,$' "$abi_header"
  grep -Eq '^[[:space:]]*FUSE_PFS_COPY_FILE_RANGE[[:space:]]*=[[:space:]]*4100,$' "$abi_header"
  grep -Eq '^[[:space:]]*FUSE_NOTIFY_PFS_SIZE[[:space:]]*=[[:space:]]*10,$' "$abi_header"
  grep -Eq '^[[:space:]]*FUSE_NOTIFY_PFS_ATTR[[:space:]]*=[[:space:]]*12,$' "$abi_header"
  grep -Eq '^[[:space:]]*FUSE_NOTIFY_PFS_ENTRY[[:space:]]*=[[:space:]]*13,$' "$abi_header"

  cc -std=c11 -Wall -Wextra -Werror \
    -I "$tree/include/uapi" \
    "$SCRIPT_DIR/tests/abi_layout.c" -o "$abi_binary"
  "$abi_binary"
  PFS_PATCHED_KERNEL_TREE="$tree" \
    python3 "$SCRIPT_DIR/tests/test_patched_source.py"
}

"$UPSTREAM_TREE/scripts/checkpatch.pl" --no-tree \
  --ignore ENOSYS,COMMIT_MESSAGE,MISSING_SIGN_OFF,BAD_SIGN_OFF,FILE_PATH_CHANGES \
  "${PFS_PATCHES[@]}"
verify_patched_tree "$UPSTREAM_TREE" upstream
verify_patched_tree "$DEBIAN_TREE" debian
python3 "$SCRIPT_DIR/tests/test_state_machine.py"
python3 "$SCRIPT_DIR/tests/test_xfs_fallocate.py"
python3 "$SCRIPT_DIR/tests/test_strict_stacking.py"

if [[ "$BUILD" -eq 0 ]]; then
  echo "PortableFS strict-coherence patch verification passed (build skipped)."
  exit 0
fi

command -v docker >/dev/null || {
  echo "Docker is required for the hermetic build; use --no-build to skip." >&2
  exit 1
}

CONTAINER_ID="$(docker create --workdir /src "$BUILD_IMAGE" sleep infinity)"
docker start "$CONTAINER_ID" >/dev/null
docker cp "$UPSTREAM_TREE/." "$CONTAINER_ID:/src/"

docker exec "$CONTAINER_ID" sh -eu -c '
  sed -i "s|http://deb.debian.org|https://deb.debian.org|g" /etc/apt/sources.list.d/debian.sources
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bc bison build-essential flex gcc-aarch64-linux-gnu gcc-x86-64-linux-gnu libelf-dev libssl-dev

  build_affected() {
    arch="$1"
    cross="$2"
    output="/build-$arch"

    make O="$output" ARCH="$arch" CROSS_COMPILE="$cross" defconfig
    scripts/config --file "$output/.config" --module CONFIG_FUSE_FS
    scripts/config --file "$output/.config" --enable CONFIG_AIO
    scripts/config --file "$output/.config" --enable CONFIG_IO_URING
    make O="$output" ARCH="$arch" CROSS_COMPILE="$cross" olddefconfig
    make O="$output" ARCH="$arch" CROSS_COMPILE="$cross" W=1 -j2 \
      drivers/block/loop.o drivers/mtd/nand/raw/nandsim.o \
      drivers/md/md.o \
      drivers/nvme/target/io-cmd-file.o \
      drivers/target/target_core_file.o \
      drivers/usb/gadget/function/storage_common.o \
      fs/cachefiles/namei.o \
      fs/coda/file.o \
      fs/erofs/super.o mm/swapfile.o \
      fs/overlayfs/params.o \
      fs/smb/server/smb2pdu.o fs/smb/server/vfs.o \
      fs/fuse/dev.o fs/fuse/dir.o fs/fuse/file.o fs/fuse/inode.o \
      fs/fuse/ioctl.o fs/fuse/post_state.o fs/fuse/readdir.o fs/fuse/xattr.o \
      fs/reply_publish.o fs/namei.o fs/open.o fs/read_write.o \
      fs/splice.o fs/xattr.o fs/aio.o io_uring/rw.o kernel/fork.o
  }

  case "$(uname -m)" in
    aarch64)
      build_affected arm64 ""
      build_affected x86_64 x86_64-linux-gnu-
      ;;
    x86_64)
      build_affected x86_64 ""
      build_affected arm64 aarch64-linux-gnu-
      ;;
    *)
      build_affected arm64 aarch64-linux-gnu-
      build_affected x86_64 x86_64-linux-gnu-
      ;;
  esac
'

echo "PortableFS strict-coherence patch verification passed for arm64 and x86_64."
