#!/usr/bin/env bash
# Private native-gate authority/peer fixture. Run only in its owned container.
set -euo pipefail
[[ $EUID == 0 && ${PFS_NATIVE_FIXTURE_CONTAINER:-} == 1 ]] || exit 77
root=/var/tmp/pfs-native
volume=native-managed
mkdir -p "$root/bin" "$root/home" "$root/xfs"
apt-get update -qq
apt-get install -y -qq --no-install-recommends xfsprogs fuse3 util-linux python3 >/dev/null
mountpoint -q /sys/fs/fuse/connections || mount -t fusectl none /sys/fs/fuse/connections
for program in portablefs-authority portablefs-mount-v3; do
  go -C /work/vcs build -o "$root/bin/$program" "./cmd/$program"
done
go -C /work/vcs build -o "$root/bin/pfs-workspace-fixture" ./test/workspace/cmd/pfs-workspace-fixture
truncate -s 1G "$root/xfs.img"
mkfs.xfs -q -f "$root/xfs.img"
# util-linux sets LO_FLAGS_AUTOCLEAR. Namespace teardown cannot leave an owned
# persistent loop attachment, including if the container is killed mid-test.
mount -o loop,prjquota,nodev,nosuid,noexec,noatime "$root/xfs.img" "$root/xfs"
bash /work/scripts/provision-xfs-volume.sh "$root/xfs" "$volume" 42016 200001 200001 512m 100000
chown 200001:200001 "$root/home"
chmod 0700 "$root/home"
service() { setpriv --reuid 200001 --regid 200001 --clear-groups "$@"; }
service "$root/bin/pfs-workspace-fixture" setup "$root/home/test-pki" "$volume"
service mkdir "$root/home/peer"
authority_pid= peer_pid=
cleanup() {
  trap - EXIT TERM INT
  if [[ -n "$peer_pid" ]]; then kill -TERM "$peer_pid" 2>/dev/null || true; wait "$peer_pid" || true; fi
  if [[ -n "$authority_pid" ]]; then kill -TERM "$authority_pid" 2>/dev/null || true; wait "$authority_pid" || true; fi
  umount "$root/xfs"
  [[ -z $(losetup -j "$root/xfs.img") ]]
}
trap cleanup EXIT TERM INT
service "$root/bin/portablefs-authority" --listen 0.0.0.0:17443 --volume-id "$volume" \
  --root "$root/xfs/$volume" --project-id 42016 \
  --tls-cert "$root/home/test-pki/server.pem" --tls-key "$root/home/test-pki/server.key" \
  --client-ca "$root/home/test-pki/client-ca.pem" --capability-public-key "$root/home/test-pki/capability-public.pem" \
  --capability-max-lifetime 1h --mount-membership-file "$root/xfs/.portablefs-control/$volume/mount.membership" \
  >"$root/authority.log" 2>&1 &
authority_pid=$!
for attempt in $(seq 1 150); do
  if (exec 3<>/dev/tcp/127.0.0.1/17443) 2>/dev/null; then break; fi
  kill -0 "$authority_pid"
  sleep 0.1
done
service "$root/bin/portablefs-mount-v3" --authority 127.0.0.1:17443 --volume-id "$volume" --mountpoint "$root/home/peer" \
  --access-token-file "$root/home/test-pki/peer.token" --tls-cert "$root/home/test-pki/peer.pem" \
  --tls-key "$root/home/test-pki/peer.key" --tls-server-ca "$root/home/test-pki/server-ca.pem" \
  --tls-server-name authority.portablefs.test >"$root/peer.log" 2>&1 &
peer_pid=$!
for attempt in $(seq 1 150); do
  if [[ $(findmnt -rn -o FSTYPE --target "$root/home/peer") == fuse.portablefs ]]; then
    service stat "$root/home/peer" >/dev/null
    printf 'ready\n' >"$root/ready"
    break
  fi
  kill -0 "$peer_pid"
  sleep 0.1
done
[[ -f "$root/ready" ]]
wait "$authority_pid"
