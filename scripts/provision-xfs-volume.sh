#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <xfs-mount> <volume-name> <project-id> <service-uid> <service-gid> <block-hard-limit> <inode-hard-limit>" >&2
  echo "example: $0 /srv/portablefs vol_01JXYZ 42001 200001 200001 100g 10000000" >&2
  exit 64
}

fail() {
  echo "$1" >&2
  exit "${2:-65}"
}

decimal_at_most() {
  local value=$1 maximum=$2
  [[ $value =~ ^[1-9][0-9]*$ ]] || return 1
  (( ${#value} < ${#maximum} )) ||
    { (( ${#value} == ${#maximum} )) && [[ $value == "$maximum" || $value < "$maximum" ]]; }
}

[[ $# -eq 7 ]] || usage

mount_root=$1
volume_name=$2
project_id=$3
service_uid=$4
service_gid=$5
block_limit=$6
inode_limit=$7

[[ $EUID -eq 0 ]] || fail "provisioning requires root" 77
[[ $mount_root == /* && $mount_root =~ ^/[A-Za-z0-9._/-]+$ ]] || fail "xfs-mount must be a safe absolute path" 64
[[ $volume_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || fail "invalid volume-name" 64
decimal_at_most "$project_id" 4294967295 || fail "project-id must be a nonzero uint32" 64
# uid_t/gid_t all-ones is the chown(2) sentinel, not a usable service identity.
decimal_at_most "$service_uid" 4294967294 || fail "service-uid must be a nonzero usable uint32" 64
decimal_at_most "$service_gid" 4294967294 || fail "service-gid must be a nonzero usable uint32" 64
[[ $block_limit =~ ^[1-9][0-9]*[kKmMgGtTpP]?$ ]] || fail "invalid XFS block hard limit" 64
[[ $inode_limit =~ ^[1-9][0-9]*$ ]] || fail "invalid inode hard limit" 64

for command_name in find findmnt flock mktemp readlink stat sync xfs_io xfs_quota; do
  command -v "$command_name" >/dev/null || fail "required command is missing: $command_name" 69
done

mount_root=$(readlink -f -- "$mount_root") || fail "cannot resolve xfs-mount" 66
[[ $mount_root =~ ^/[A-Za-z0-9._/-]+$ && -d $mount_root && ! -L $mount_root ]] || fail "resolved xfs-mount is not a safe directory" 66
[[ $(findmnt -n -r -o FSTYPE -T "$mount_root") == xfs ]] || fail "target is not XFS"
mount_target=$(findmnt -n -r -o TARGET -T "$mount_root")
mount_target=$(readlink -f -- "$mount_target") || fail "cannot resolve XFS mount target"
[[ $mount_root == "$mount_target" ]] || fail "xfs-mount must be the dedicated XFS mount point, not a nested directory"
mount_options=$(findmnt -n -r -o OPTIONS -T "$mount_root")
for required in nodev nosuid noexec; do
  [[ ,$mount_options, == *,$required,* ]] || fail "XFS mount is missing $required"
done
[[ ,$mount_options, == *,prjquota,* || ,$mount_options, == *,pquota,* ]] || fail "XFS project quotas are not enabled"

mount_owner=$(stat -c '%u:%g' -- "$mount_root")
mount_mode=$(stat -c '%a' -- "$mount_root")
[[ $mount_owner == 0:0 ]] || fail "XFS mount point must be owned by root:root"
(( (8#$mount_mode & 0022) == 0 )) || fail "XFS mount point must not be writable by group or other users"

# The registry is the fail-closed allocator for project IDs on this dedicated
# XFS filesystem. It is initialized only on an empty cell, so an existing tree
# can never be silently adopted without registering its already-used ID.
registry=$mount_root/.portablefs-projects
if [[ ! -e $registry && ! -L $registry ]]; then
  existing=$(find "$mount_root" -mindepth 1 -maxdepth 1 -print -quit)
  [[ -z $existing ]] || fail "cannot initialize project registry on a nonempty XFS cell"
  mkdir -m 0700 -- "$registry"
  sync -- "$registry"
  sync -- "$mount_root"
fi
[[ -d $registry && ! -L $registry ]] || fail "project registry is not a real directory"
[[ $(stat -c '%u:%g:%a' -- "$registry") == 0:0:700 ]] || fail "project registry must be root:root mode 0700"

exec {registry_lock_fd}>"$registry/.lock"
chmod 0600 "$registry/.lock"
flock -x "$registry_lock_fd"
sync -- "$registry/.lock"
sync -- "$registry"

destination=$mount_root/$volume_name
[[ ! -e $destination && ! -L $destination ]] || fail "volume already exists: $destination" 73

reservation=$registry/$project_id
if ! mkdir -m 0700 -- "$reservation"; then
  fail "project ID is already reserved: $project_id" 73
fi

write_registry_record() {
  local state=$1 record_tmp=$reservation/record.tmp.$BASHPID
  (umask 077; printf 'state=%s\nvolume=%s\npath=%s\nblock_hard=%s\ninode_hard=%s\n' \
    "$state" "$volume_name" "$destination" "$block_limit" "$inode_limit" >"$record_tmp")
  sync -- "$record_tmp"
  mv -f -- "$record_tmp" "$reservation/record"
  sync -- "$reservation"
  sync -- "$registry"
}

# A failed run intentionally leaves this durable reservation behind. Reusing
# an ID whose quota setup may have partially completed would merge accounting
# and limits with another volume.
write_registry_record reserved

stage=$(mktemp -d "$mount_root/.provision-$volume_name.XXXXXX")
cleanup() {
  if [[ -n ${stage:-} && -d $stage ]]; then
    rmdir -- "$stage" 2>/dev/null || true
  fi
}
trap cleanup EXIT

chmod 0700 "$stage"
xfs_quota -x -c "project -s -p $stage $project_id" "$mount_target"
xfs_quota -x -c "limit -p bhard=$block_limit ihard=$inode_limit $project_id" "$mount_target"
# Read the result back through FS_IOC_FSGETXATTR, the same ioctl the data plane
# uses at startup, instead of parsing xfs_quota's progress text. `project -c`
# always prints two informational lines, so treating any output as a failure
# rejected every correctly provisioned volume.
stage_attributes=$(LC_ALL=C xfs_io -r -c stat -- "$stage")
stage_project=$(printf '%s\n' "$stage_attributes" | sed -n 's/^fsxattr\.projid = \([0-9]\{1,\}\)$/\1/p')
stage_xflags=$(printf '%s\n' "$stage_attributes" | sed -n 's/^fsxattr\.xflags = 0x\([0-9a-fA-F]\{1,\}\).*$/\1/p')
[[ $stage_project == "$project_id" ]] ||
  fail "XFS project validation failed: project ID is ${stage_project:-unreadable}, want $project_id"
[[ $stage_xflags =~ ^[0-9a-fA-F]+$ ]] || fail "XFS project validation failed: xflags are unreadable"
# FS_XFLAG_PROJINHERIT. Without it, children of this directory escape the
# project and its quota, which is the whole isolation guarantee.
(( (16#$stage_xflags & 0x200) != 0 )) || fail "XFS project validation failed: project inheritance flag is not set"
# Project limits are separate XFS metadata from the directory inode. Force the
# quota transaction as well as fsyncing the directory and its publish parent.
sync -f -- "$mount_root"
chown "$service_uid:$service_gid" "$stage"
sync -- "$stage"
mv -- "$stage" "$destination"
stage=
sync -- "$mount_root"
write_registry_record published

echo "provisioned $destination (project $project_id, owner $service_uid:$service_gid, hard limits $block_limit / $inode_limit inodes)"
