"""Host-side causal collector for a prestarted product-VM RTC reader."""
import json
import pathlib
import queue
import subprocess
import threading
import time


class ProductProbe:
    def __init__(self, guest, reference):
        self.reference = reference
        source = pathlib.Path(__file__).with_name('g3_product_rtc_reader.py').read_text()
        # Stream source on stdin; never enumerate or copy a guest credential.
        subprocess.run(['ssh','-F',guest.ready['ssh_config'],'portablefs-workspace',
                        'cat > /tmp/g3-product-rtc-reader.py'],input=source,text=True,check=True,timeout=10)
        find="import os,pathlib; found=[]\nfor p in pathlib.Path('/proc').iterdir():\n if p.name.isdigit():\n  try:\n   if (p/'comm').read_text().strip()=='portablefs' and os.readlink(p/'fd/8')=='/dev/rtc0': found.append(int(p.name))\n  except (FileNotFoundError,PermissionError): pass\nassert len(found)==1,found\nprint(found[0])"
        import shlex
        pid=int(guest.ssh('python3 -c '+shlex.quote(find)))
        self.process = subprocess.Popen(['ssh','-F',guest.ready['ssh_config'],
                        '-o','ServerAliveInterval=0','-o','TCPKeepAlive=no','portablefs-workspace',
                        f'python3 -u /tmp/g3-product-rtc-reader.py {pid}'],
                        text=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.lines = queue.Queue()
        self.reference_results=[]
        self.reference_errors=[]
        self.reference_lock=threading.Lock()
        self.after_reference_thread=None
        def receive():
            for line in self.process.stdout:
                value=json.loads(line)
                self.lines.put((time.monotonic_ns(),value))
                if value.get('event')=='first-read':
                    self.after_reference_thread=threading.Thread(target=self.collect_reference,daemon=True)
                    self.after_reference_thread.start()
            self.lines.put((time.monotonic_ns(),dict(event='eof')))
        threading.Thread(target=receive,daemon=True).start()
        try:
            _, self.armed = self.lines.get(timeout=10)
            assert self.armed['event']=='armed', (self.armed,self.process.stderr.read() if self.process.poll() is not None else '')
            self.armed['reader_ssh_pid']=self.process.pid
        except BaseException:
            self.close()
            raise
        self.reference_thread = None
        self.resume_ns = None

    def collect_reference(self):
        began = time.monotonic_ns()
        try:
            result = json.loads(subprocess.check_output([str(self.reference)],text=True,timeout=9.8))
            value=dict(references=result['references'],clock=result['clock'],
                       reference_began_ns=began,reference_ended_ns=time.monotonic_ns(),adapter=result)
            with self.reference_lock: self.reference_results.append(value)
        except Exception as error:
            with self.reference_lock: self.reference_errors.append(repr(error))

    def prepare(self, duration):
        # Short pauses must not grow by reference-command latency. Long pauses
        # collect near their end, and never delay the requested VZ resume.
        if duration < 10:
            self.collect_reference()

    def paused(self, duration):
        self.process.stdin.write('probe\n');self.process.stdin.flush()
        if duration >= 10:
            def collect():
                time.sleep(max(0,duration-9))
                self.collect_reference()
            self.reference_thread=threading.Thread(target=collect,daemon=True)
            self.reference_thread.start()

    def resuming(self, stamp):
        self.resume_ns=stamp

    def finish(self):
        ended, first=self.lines.get(timeout=15)
        assert first['event']=='first-read', first
        _, duplicate=self.lines.get(timeout=15)
        assert duplicate['event']=='contention', duplicate
        assert self.process.wait(timeout=5)==0, self.process.stderr.read()
        if self.reference_thread: self.reference_thread.join(timeout=11)
        if self.after_reference_thread: self.after_reference_thread.join(timeout=11)
        assert self.reference_results, self.reference_errors
        domains={v['clock'] for v in self.reference_results}
        assert len(domains)==1, 'mismatched reference clock domains'
        first.update(references=[r for v in self.reference_results for r in v['references']],clock=domains.pop(),
                     reference_began_ns=min(v['reference_began_ns'] for v in self.reference_results),
                     reference_ended_ns=max(v['reference_ended_ns'] for v in self.reference_results),
                     adapter_collections=self.reference_results,reference_errors=self.reference_errors,
                     sample_began_ns=self.resume_ns,sample_ended_ns=ended)
        assert first['boot_id']==self.armed['boot_id'] and first['service_pid']==self.armed['service_pid']
        return first, duplicate

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write('stop\n');self.process.stdin.flush();self.process.stdin.close()
                self.process.wait(timeout=15)
            except (BrokenPipeError,subprocess.TimeoutExpired):
                # A paused guest cannot consume stdin. Its owned VM shutdown
                # closes the bridge; never kill a host SSH process by name.
                pass
