"""Run identity and continuity checks, independent of planned guest fences."""
import json
import os
import pathlib
import subprocess
import sys
import time


def host_pair():
    before = time.monotonic_ns()
    # Darwin RAW includes sleep; Python monotonic (UPTIME_RAW) excludes it.
    # Linux BOOTTIME likewise includes suspend. A bracket avoids scheduling
    # latency being mistaken for sleep between the two host reads.
    clock = time.CLOCK_MONOTONIC_RAW if sys.platform == 'darwin' else time.CLOCK_BOOTTIME
    continuous = time.clock_gettime_ns(clock)
    after = time.monotonic_ns()
    return continuous-after, continuous-before


def verify_awake(initial, current):
    lower,upper=current
    # This detects suspend, not an independently supported UTC rate envelope.
    if lower>initial[1]+1_000_000 or upper<initial[0]-1_000_000:
        raise RuntimeError('host sleep/monotonic discontinuity')
    return current


class Continuity:
    def __init__(self, authority, guest, peer_log):
        self.authority,self.guest,self.peer_log=authority,guest,peer_log
        self.host=host_pair()
        self.initial=self.snapshot()
        self.last_peer=None
        self.last_peer_host=time.monotonic_ns()
        self.guest_identity=guest.ssh("python3 -c \"import json,pathlib,subprocess;print(json.dumps([pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),subprocess.check_output(['systemctl','show','--property=MainPID','--value','portablefs-workspaced'],text=True).strip()]))\"")

    def snapshot(self):
        raw=subprocess.check_output(['docker','inspect','--format','{{json .State}}',self.authority.name],text=True,timeout=5)
        state=json.loads(raw)
        if not state['Running'] or state['Paused'] or state['Restarting']:
            raise RuntimeError('unplanned authority pause/exit/restart')
        # Read only process identity fields for the owned container's service
        # and ordinary peer. Never inspect argv, environment, or credential data.
        code="""import json,pathlib
rows={}
for name in ('portablefs-authority','portablefs-mount-v3'):
 found=[]
 for p in pathlib.Path('/proc').iterdir():
  if not p.name.isdigit(): continue
  try:
   if (p/'comm').read_text().strip()==name[:15]:
    raw=(p/'stat').read_text();fields=raw[raw.rfind(')')+2:].split();found.append([p.name,fields[0],fields[19]])
  except FileNotFoundError: pass
 assert len(found)==1,(name,found)
 assert found[0][1] not in ('T','t','Z','X'),found
 rows[name]=[[pid,started] for pid,_,started in found]
print(json.dumps(rows,sort_keys=True))
"""
        processes=subprocess.check_output(['docker','exec',self.authority.name,'python3','-c',code],text=True,timeout=5)
        return dict(pid=state['Pid'],started=state['StartedAt'],processes=json.loads(processes))

    def check(self, campaign_active=False):
        tunnel = getattr(self.authority, 'tunnel', None)
        if tunnel is not None:
            tunnel.check()
        lower,upper=verify_awake(self.host,host_pair())
        if self.snapshot()!=self.initial:
            raise RuntimeError('authority/ordinary peer process identity changed')
        if self.guest.p.poll() is not None:
            raise RuntimeError('guest owner exited')
        # The host log is append-only; no guest SSH is needed during a pause.
        with self.peer_log.open('rb') as stream:
            stream.seek(0,2);end=stream.tell();stream.seek(max(0,end-2048));lines=stream.read().splitlines()
        if lines:
            value=json.loads(lines[-1])['peer_completed_ns']
            if self.last_peer is not None and value < self.last_peer:
                raise RuntimeError('independent peer restarted')
            if value != self.last_peer:
                self.last_peer=value;self.last_peer_host=time.monotonic_ns()
        if time.monotonic_ns()-self.last_peer_host>90_000_000_000:
            raise RuntimeError('lost independent authority/peer progress')
        if not campaign_active:
            current=self.guest.ssh("python3 -c \"import json,pathlib,subprocess;print(json.dumps([pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),subprocess.check_output(['systemctl','show','--property=MainPID','--value','portablefs-workspaced'],text=True).strip()]))\"")
            if current!=self.guest_identity:
                raise RuntimeError('guest reboot/service owner restart')
        return dict(host_clock_offset_bracket_ns=[lower,upper],authority=self.initial,
                    peer_completed_ns=self.last_peer,observed_ns=time.monotonic_ns())


def verify_owner(status_path, owner_pid, run_id, now_ns, parent_pid):
    status=json.loads(pathlib.Path(status_path).read_text())
    parent_pid=parent_pid() if callable(parent_pid) else parent_pid
    if parent_pid!=owner_pid:
        raise RuntimeError('clock sampler lost its exact owner process')
    if status.get('pid')!=owner_pid or status.get('run_id')!=run_id:
        raise RuntimeError('clock sampler owner identity changed')
    heartbeat=status.get('continuity',{}).get('observed_ns')
    now_ns=now_ns() if callable(now_ns) else now_ns
    if type(heartbeat) is not int or not 0<=now_ns-heartbeat<=45_000_000_000:
        raise RuntimeError('clock sampler lost fresh authority/peer continuity evidence')
    return heartbeat


def record_invalid(path, value):
    """Atomically retain the first disruption across the owner and sampler."""
    path=pathlib.Path(path)
    temporary=path.with_name(path.name+f'.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(value,indent=2)+'\n')
    try:
        try:os.link(temporary,path)
        except FileExistsError:pass
    finally:
        temporary.unlink()
