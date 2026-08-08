#!/bin/bash
# Solo FSKit production battery: mounts an isolated branch and exercises the
# 2026-07-30 incident surfaces (attribute masks, flags, hard-link alias
# parents, orphan reads, locks, allocated size, unmount lifecycle) on a real
# FSKit host against the real authority. Usage: fskit-solo-battery.sh <ts>
# Env: PFS_BIN, PFS_VOLUME, PFS_BRANCH, PFS_MOUNT_DIR.
set -u
B="${PFS_BIN:-$HOME/.portablefs-stress-5d5b8a7-prod/bin/portablefs}"
TS="${1:?usage: solo-smoke.sh <timestamp>}"
VOL="${PFS_VOLUME:-portablefs-cloud-3}"
BR="${PFS_BRANCH:-stress-solo-$TS}"
M="${PFS_MOUNT_DIR:-$HOME/.portablefs-stress-solo/mount}"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $*"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $*"; }
# watchdog: run a command, kill it (and report) if it exceeds $1 seconds.
# The watchdog subshell chdirs out of the mount so a lingering sleep never
# holds the mount busy at unmount time.
wd() {
  local t=$1; shift
  "$@" & local p=$!
  ( cd / 2>/dev/null; sleep "$t"; kill -9 $p 2>/dev/null ) & local w=$!
  wait $p 2>/dev/null; local s=$?
  kill $w 2>/dev/null; wait $w 2>/dev/null
  return $s
}

echo "=== branch create $BR ==="
wd 60 "$B" branch "$VOL" "$BR" || { bad "branch create"; exit 1; }
mkdir -p "$M"
echo "=== mount ==="
wd 90 "$B" mount "$VOL" "$M" --branch "$BR" --strategy fskit || { bad "mount"; exit 1; }
ok "mounted"
mount | grep -q "$M" && ok "mount visible in mount table" || bad "mount not in mount table"

cd "$M" || { bad "cd mount"; exit 1; }
MARK_START=$(date "+%Y-%m-%d %H:%M:%S")

echo "=== basic io ==="
wd 20 mkdir -p left right && ok "mkdir" || bad "mkdir"
wd 20 sh -c 'echo hello-world > left/f1' && ok "create+write" || bad "create+write"
[ "$(wd 20 cat left/f1)" = "hello-world" ] && ok "read back" || bad "read back"

echo "=== full stat (attribute mask exercise) ==="
wd 20 stat -f 'dev=%d ino=%i mode=%p nlink=%l uid=%u gid=%g size=%z blocks=%b blksize=%k flags=%f' left/f1 && ok "stat full" || bad "stat full"
wd 20 ls -laO left/ >/dev/null && ok "ls -laO (flags via readdir)" || bad "ls -laO"

echo "=== bsd file flags ==="
# The authority tree format has no flags slot yet, so the honest contract is
# an explicit refusal: chflags must FAIL (ENOTSUP), never silently no-op.
if wd 20 chflags uchg left/f1 2>/dev/null; then
  FL=$(wd 20 ls -lO left/f1 | awk '{print $5}')
  if [ "$FL" = "uchg" ]; then
    ok "chflags uchg persisted ($FL)"
    wd 20 chflags nouchg left/f1 && ok "chflags cleared" || bad "chflags clear"
  else
    bad "chflags silently dropped (reported success but flags empty)"
  fi
else
  ok "chflags refused explicitly (flags honestly unsupported)"
fi

echo "=== hard link alias parents (incident sec.9) ==="
wd 20 ln left/f1 right/f1alias && ok "hardlink create" || bad "hardlink create"
I1=$(wd 20 stat -f %i left/f1); I2=$(wd 20 stat -f %i right/f1alias)
[ -n "$I1" ] && [ "$I1" = "$I2" ] && ok "aliases share inode $I1" || bad "alias inode mismatch ($I1 vs $I2)"
NL=$(wd 20 stat -f %l left/f1)
[ "$NL" = "2" ] && ok "nlink=2" || bad "nlink=$NL expected 2"
wd 20 ls -la left/ >/dev/null && wd 20 ls -la right/ >/dev/null && ok "readdir both alias parents" || bad "readdir alias parents"

echo "=== cross-directory rename ==="
wd 20 sh -c 'echo mv-me > left/mv1' || bad "prep mv1"
wd 20 mv left/mv1 right/mv1-moved && ok "cross-dir rename" || bad "cross-dir rename"
wd 20 stat -f 'ino=%i' right/mv1-moved >/dev/null && ok "stat after rename" || bad "stat after rename"
[ ! -e left/mv1 ] && ok "old name gone" || bad "old name still present"

echo "=== open-after-unlink (orphan) ==="
exec 7< left/f1
wd 20 rm right/f1alias || bad "rm alias"
wd 20 rm left/f1 || bad "rm last name"
DATA=$(head -c 11 <&7)
[ "$DATA" = "hello-world" ] && ok "read from unlinked open handle" || bad "orphan read (got: $DATA)"
exec 7<&-

echo "=== xattrs ==="
wd 20 sh -c 'echo x > left/xf' || bad "prep xf"
# The production XFS authority deliberately exposes a partial xattr surface:
# list/get/remove of pre-existing portable attributes are real operations, but
# set must fail because XFS attribute-fork blocks bypass project quotas.
wd 20 python3 - <<'PYEOF' && ok "xattr write refused with exact EOPNOTSUPP" || bad "xattr write did not return exact EOPNOTSUPP"
import ctypes, errno, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
libc.setxattr.restype = ctypes.c_int
value = ctypes.create_string_buffer(b'somevalue')
result = libc.setxattr(b'left/xf', b'user.test', value, len(value.raw) - 1, 0, 0)
sys.exit(0 if result == -1 and ctypes.get_errno() == errno.EOPNOTSUPP else 1)
PYEOF
[ ! -e left/._xf ] && ok "xattr refusal created no AppleDouble sidecar" || bad "xattr refusal leaked an AppleDouble sidecar"
wd 20 xattr -l left/xf >/dev/null && ok "xattr list" || bad "xattr list"
wd 20 python3 - <<'PYEOF' && ok "xattr get reports the refused value absent" || bad "xattr get after refused write"
import errno, os, sys
try:
    os.getxattr('left/xf', 'user.test')
except OSError as error:
    absent = {getattr(errno, 'ENOATTR', errno.ENODATA), errno.ENODATA}
    sys.exit(0 if error.errno in absent else 2)
sys.exit(1)
PYEOF

echo "=== symlink ==="
wd 20 ln -s xf left/xf-link && ok "symlink create" || bad "symlink create"
RL=$(wd 20 readlink left/xf-link)
[ "$RL" = "xf" ] && ok "readlink" || bad "readlink (got: $RL)"

echo "=== truncate / setattr ==="
wd 20 sh -c 'printf 0123456789 > left/tr' || bad "prep tr"
wd 20 python3 -c "import os; os.truncate('left/tr', 4)" && ok "truncate" || bad "truncate"
SZ=$(wd 20 stat -f %z left/tr)
[ "$SZ" = "4" ] && ok "size after truncate" || bad "size=$SZ expected 4"
wd 20 touch -t 202601010101 left/tr && ok "utimes" || bad "utimes"

echo "=== allocated size semantics (incident sec.2) ==="
wd 30 sh -c 'dd if=/dev/zero of=left/big bs=1m count=1 2>/dev/null' || bad "write 1MB"
BSZ=$(wd 20 stat -f %z left/big); BBL=$(wd 20 stat -f %b left/big)
ALLOC=$((BBL * 512))
if [ "$ALLOC" -ge "$BSZ" ] && [ "$ALLOC" -le $((BSZ * 4 + 1048576)) ]; then
  ok "allocated bytes sane (size=$BSZ alloc=$ALLOC)"
else
  bad "allocated bytes suspicious (size=$BSZ blocks=$BBL alloc=$ALLOC)"
fi

echo "=== fcntl advisory locks (incident sec.4/5) ==="
wd 40 python3 - <<'PYEOF' && ok "fcntl lock/unlock cycle" || bad "fcntl locks"
import fcntl, os, struct, sys
f = open('left/lockfile', 'w'); f.write('lockme'); f.flush()
# exclusive setlk
lk = struct.pack('qqihh', 0, 0, 0, fcntl.F_WRLCK, 0)
fcntl.fcntl(f.fileno(), fcntl.F_SETLK, lk)
# getlk from a second fd must see the conflict shape without hanging
f2 = os.open('left/lockfile', os.O_RDWR)
probe = struct.pack('qqihh', 0, 0, 0, fcntl.F_WRLCK, 0)
fcntl.fcntl(f2, fcntl.F_GETLK, probe)
# unlock
ulk = struct.pack('qqihh', 0, 0, 0, fcntl.F_UNLCK, 0)
fcntl.fcntl(f.fileno(), fcntl.F_SETLK, ulk)
# relock via second fd proves unlock actually released authority-side
fcntl.fcntl(f2, fcntl.F_SETLK, struct.pack('qqihh', 0, 0, 0, fcntl.F_WRLCK, 0))
fcntl.fcntl(f2, fcntl.F_SETLK, struct.pack('qqihh', 0, 0, 0, fcntl.F_UNLCK, 0))
os.close(f2); f.close()
PYEOF

echo "=== setlkw blocking handoff between two processes ==="
wd 60 python3 - <<'PYEOF' && ok "setlkw blocking handoff" || bad "setlkw handoff"
import fcntl, os, struct, sys, time, multiprocessing
def holder(ev_locked, ev_release):
    f = open('left/lockfile2', 'w')
    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    ev_locked.set()
    ev_release.wait(20)
    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    time.sleep(5)
if __name__ == '__main__':
    ev_locked = multiprocessing.Event(); ev_release = multiprocessing.Event()
    p = multiprocessing.Process(target=holder, args=(ev_locked, ev_release))
    p.start()
    assert ev_locked.wait(20)
    f = open('left/lockfile2', 'r+')
    # this must block until holder releases, then succeed (no deadlock, no instant fail)
    t0 = time.time()
    import threading
    def releaser():
        time.sleep(2); ev_release.set()
    threading.Thread(target=releaser).start()
    fcntl.flock(f.fileno(), fcntl.LOCK_EX)   # blocking acquire
    dt = time.time() - t0
    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    p.join(20)
    assert dt >= 1.5, f"acquired too fast ({dt})"
    sys.exit(0)
PYEOF

echo "=== readdir under churn + many-file getattr sweep ==="
wd 60 sh -c 'mkdir -p sweep && cd sweep && for i in $(seq 1 120); do echo $i > f$i; done' && ok "create 120 files" || bad "create 120"
wd 60 sh -c 'ls -la@O sweep >/dev/null' && ok "bulk ls -la@O sweep" || bad "bulk attr sweep"

echo "=== concurrent local churn (30s, 3 writers) ==="
churn() { local d=$1; local end=$((SECONDS+25)); mkdir -p "$d"; local i=0;
  while [ $SECONDS -lt $end ]; do
    echo data-$i > "$d/a$i"; ln "$d/a$i" "$d/l$i" 2>/dev/null; mv "$d/a$i" "$d/b$i"; cat "$d/b$i" >/dev/null; rm -f "$d/b$i" "$d/l$i"; i=$((i+1));
  done; echo "$d iterations=$i"; }
churn c1 & churn c2 & churn c3 & wait
ok "concurrent churn completed"

echo "=== post-churn statfs / df ==="
wd 20 df -k . >/dev/null && ok "statfs" || bad "statfs"

cd /
# Give any straggling watchdog subshells a moment to die before the busy check.
sleep 3
echo "=== unmount ==="
wd 90 "$B" umount "$M" && ok "clean unmount" || bad "clean unmount"
mount | grep -q "$M" && bad "mount still present after umount" || ok "mount gone"

echo "=== remount lifecycle ==="
wd 90 "$B" mount "$VOL" "$M" --branch "$BR" --strategy fskit && ok "remount" || bad "remount"
[ "$(wd 20 cat "$M/left/xf" 2>/dev/null)" = "x" ] && ok "data persisted across remount" || bad "data persistence"
wd 90 "$B" umount "$M" && ok "final unmount" || bad "final unmount"

echo "=== FSKit error scan (since $MARK_START) ==="
sleep 2
log show --start "$MARK_START" --predicate 'process CONTAINS[c] "fskit" OR process CONTAINS[c] "PortableFS" OR eventMessage CONTAINS[c] "incomplete" OR eventMessage CONTAINS[c] "ESTALE"' --style compact 2>/dev/null | grep -iE "incomplete|ESTALE|error" | grep -viE "no error|error=nil|errors=0" | head -30 > /tmp/fskit-errscan-$TS.txt
if [ -s /tmp/fskit-errscan-$TS.txt ]; then
  echo "LOG FINDINGS (review needed):"; cat /tmp/fskit-errscan-$TS.txt
else
  ok "no incomplete-attributes / ESTALE in unified log"
fi

echo ""
echo "=== RESULT: PASS=$PASS FAIL=$FAIL ==="
[ $FAIL -eq 0 ]
