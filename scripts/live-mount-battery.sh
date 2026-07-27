#!/bin/bash
# PortableFS live-mount verification battery. Run with the volume mounted at $1 (default /tmp/pfs-live/mnt).
set -u
MNT="${1:-/tmp/pfs-live/mnt}"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
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

# 11. cross-client visibility (control API write -> kernel)
python3 - "$T" <<'EOF' && ok "cross-client visibility" || bad "cross-client visibility"
import base64, json, subprocess, sys, time, os
t = sys.argv[1]
rel = os.path.relpath(f"{t}/ext.txt", os.path.expanduser("/tmp/pfs-live/mnt"))
body = json.dumps({"path": rel, "dataBase64": base64.b64encode(b"ext").decode()})
subprocess.run(["curl","-s","--unix-socket","/tmp/pfs-live/run/control.sock","-X","POST","-H","content-type: application/json","-d",body,
  "http://portablefsd/v1/attaches/att_O8vC7SepSumfOlqnM0VArp/fs/write"],check=True,capture_output=True)
deadline = time.time()+5
while time.time() < deadline:
    try:
        if open(f"{t}/ext.txt","rb").read() == b"ext": sys.exit(0)
    except FileNotFoundError: pass
    time.sleep(0.05)
sys.exit(1)
EOF

# 12. deep tree + enumerate
mkdir -p "$T/deep/a/b/c" && for i in $(seq 1 60); do echo $i > "$T/deep/a/f$i"; done
[ "$(ls "$T/deep/a" | wc -l | tr -d ' ')" = "61" ] && ok "60-entry enumerate" || bad "60-entry enumerate"

# cleanup
rm -rf "$T"
echo; echo "RESULT: $PASS passed, $FAIL failed"
exit $FAIL
