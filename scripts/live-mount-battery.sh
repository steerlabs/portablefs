#!/bin/bash
# PortableFS live-mount verification battery. Run with the volume mounted at $1 (default /tmp/pfs-live/mnt).
set -u
MNT="${1:-/tmp/pfs-live/mnt}"
FSTYPE="${PFS_BATTERY_FSTYPE:-pfs}"
PASS=0; FAIL=0

# THE MOUNT IDENTITY IS ASSERTED BEFORE EVERY VERDICT. A PortableFS mount that
# dies mid-run leaves an ordinary directory underneath the mountpoint, and
# every remaining case then "passes" against local disk — a full battery once
# reported 14 green cases against bare APFS because its liveness check was a
# plain `ls`, which a bare directory satisfies. The kernel mount table is the
# only witness that does not traverse the filesystem, so it is consulted from
# the verdict functions themselves: a vanished mount voids the run loudly
# instead of counting local-disk passes.
mount_alive() { /sbin/mount | /usr/bin/grep -q " on $MNT ($FSTYPE" ; }
void_run() {
  echo "BATTERY VOID: the $FSTYPE mount at $MNT is gone; every further case would run against the bare directory"
  echo; echo "RESULT: VOID ($PASS passed, $FAIL failed before the mount vanished)"
  exit 2
}
ok()   { mount_alive || void_run; PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { mount_alive || void_run; FAIL=$((FAIL+1)); echo "FAIL: $1"; }

mount_alive || { echo "refusing to run: no $FSTYPE mount at $MNT (found only the underlying directory)"; exit 2; }
T="$MNT/battery-$$"
mkdir -p "$T" || { echo "cannot create test dir"; exit 1; }

# 1. basic write/read
echo "hello" > "$T/a.txt" && [ "$(cat "$T/a.txt")" = "hello" ] && ok "write/read" || bad "write/read"

# 2. rename
mv "$T/a.txt" "$T/b.txt" && [ "$(cat "$T/b.txt")" = "hello" ] && ok "rename" || bad "rename"

# 3. symlink create + readlink + follow
ln -s b.txt "$T/l.txt"
[ "$(readlink "$T/l.txt")" = "b.txt" ] && ok "readlink target" || bad "readlink target ($(readlink "$T/l.txt"))"
[ "$(cat "$T/l.txt" 2>/dev/null)" = "hello" ] && ok "symlink follow" || bad "symlink follow"

# 4. enumerate dir containing symlink (fts walk)
ls -la "$T" >/dev/null 2>&1 && ok "ls -la with symlink" || bad "ls -la with symlink"

# 5. rename-over-existing: stat + read after clobber
echo v1 > "$T/config"; echo v2 > "$T/config.lock"; mv "$T/config.lock" "$T/config"
stat -f %z "$T/config" >/dev/null 2>&1 && ok "stat after rename-over" || bad "stat after rename-over"
[ "$(cat "$T/config")" = "v2" ] && ok "read after rename-over" || bad "read after rename-over"

# 6. rename-over while target open (open-after-unlink)
python3 - "$T" <<'EOF' && ok "rename-over with open fd" || bad "rename-over with open fd"
import sys, os
t = sys.argv[1]
with open(f"{t}/keep","w") as f: f.write("old")
fd = os.open(f"{t}/keep", os.O_RDONLY)
with open(f"{t}/keep.new","w") as f: f.write("new")
os.rename(f"{t}/keep.new", f"{t}/keep")
old = os.pread(fd, 10, 0)          # old fd must still see old content
os.close(fd)
new = open(f"{t}/keep").read()     # path must see new content
sys.exit(0 if (old == b"old" and new == "new") else 1)
EOF

# 7. git end-to-end
# AppleDouble ._* files are expected on macOS (the mount has no native xattrs) — exclude them from the clean-tree check.
(cd "$T" && mkdir repo && cd repo && git init -q . && echo x > f && git add f && git commit -qm init && git log --oneline | grep -q init && [ "$(git status --porcelain | grep -cv '^?? \._')" = "0" ]) && ok "git init/add/commit/status" || bad "git init/add/commit/status"

# 7b. git stash/branch churn (regression: .git dir deletion during stash)
(cd "$T/repo" && echo tweak >> f && git stash -q && git stash pop -q && git checkout -q -b side && echo s > s.txt && git add s.txt && git commit -qm side && git checkout -q - && [ -d .git ] && git log --oneline | grep -q init) && ok "git stash/branch churn" || bad "git stash/branch churn"

# 8. 8MiB hash round-trip
dd if=/dev/urandom of="$T/big" bs=1m count=8 2>/dev/null
H1=$(shasum "$T/big" | cut -d' ' -f1); cp "$T/big" "$T/big2"; H2=$(shasum "$T/big2" | cut -d' ' -f1)
[ "$H1" = "$H2" ] && ok "8MiB hash round-trip" || bad "8MiB hash round-trip"

# 9. sqlite
sqlite3 "$T/t.db" "create table t(x); insert into t values(1),(2); select count(*) from t;" 2>/dev/null | grep -q 2 && ok "sqlite" || bad "sqlite"

# 10. unlink-while-open
python3 - "$T" <<'EOF' && ok "open-after-unlink" || bad "open-after-unlink"
import sys, os
t = sys.argv[1]
with open(f"{t}/gone","w") as f: f.write("data")
fd = os.open(f"{t}/gone", os.O_RDONLY)
os.unlink(f"{t}/gone")
d = os.pread(fd, 10, 0); os.close(fd)
sys.exit(0 if d == b"data" else 1)
EOF

# The v2-era "cross-client visibility" case is gone: it drove a retired
# daemon control-API write route against a hard-coded socket and attach ref,
# so it could only ever fail. Cross-client visibility is a two-mount property
# and is proven by the coherence matrix (scripts/coherence-matrix-*.sh), not
# by a single-mount battery.

# 12. deep tree + enumerate
mkdir -p "$T/deep/a/b/c" && for i in $(seq 1 60); do echo $i > "$T/deep/a/f$i"; done
[ "$(ls "$T/deep/a" | wc -l | tr -d ' ')" = "61" ] && ok "60-entry enumerate" || bad "60-entry enumerate"

# cleanup — and one final identity assertion, so a mount that died after the
# last case cannot present a green RESULT line.
mount_alive || void_run
rm -rf "$T"
echo; echo "RESULT: $PASS passed, $FAIL failed"
exit $FAIL
