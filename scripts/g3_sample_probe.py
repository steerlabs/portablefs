"""A prestarted probe channel with complete per-request host timing brackets."""
import json
import queue
import subprocess
import threading
import time


WORKER = '''import json,sys
print(json.dumps(dict(ready=True)),flush=True)
for line in sys.stdin:
 request=json.loads(line)
 value=collect()
 print(json.dumps(dict(request_id=request['request_id'],sample=value)),flush=True)
'''


class ProbeSession:
    def __init__(self, command, evidence):
        self.command=command
        self.stderr=(evidence/'probe-session.stderr').open('w')
        self.raw=(evidence/'probe-responses.jsonl').open('w')
        self.late=(evidence/'probe-late-responses.jsonl').open('w')
        self.responses=queue.Queue()
        self.request_id=0
        self.process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                      stderr=self.stderr,text=True,bufsize=1)
        def receive():
            try:
                for line in self.process.stdout:
                    if self.raw.tell()+len(line)>32*1024*1024:
                        raise RuntimeError('probe response log bound exceeded')
                    self.raw.write(line);self.raw.flush()
                    self.responses.put(json.loads(line))
            except BaseException as error:
                self.responses.put(dict(error=repr(error)))
            finally:
                self.responses.put(dict(eof=True))
        self.reader=threading.Thread(target=receive,daemon=True);self.reader.start()
        try:
            assert self.responses.get(timeout=10)==dict(ready=True), 'probe session failed readiness'
        except BaseException:
            self.close()
            raise

    def probe(self, timeout=10):
        self.request_id+=1
        identity=self.request_id
        deadline=time.monotonic()+timeout
        self.process.stdin.write(json.dumps(dict(request_id=identity))+'\n');self.process.stdin.flush()
        while True:
            try:value=self.responses.get(timeout=max(0,deadline-time.monotonic()))
            except queue.Empty:
                raise subprocess.TimeoutExpired(self.command,timeout) from None
            if 'error' in value or value.get('eof'):
                raise RuntimeError('owned probe session lost: '+repr(value))
            if value.get('request_id',identity+1)<identity:
                # A request timed out during a scheduled guest pause. Retain its
                # late response, never associate it with a later sample slot.
                self.late.write(json.dumps(value)+'\n');self.late.flush()
                continue
            if value.get('request_id')!=identity:
                raise RuntimeError('probe response request identity mismatch')
            return value['sample']

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        self.reader.join(timeout=1)
        if not self.process.stdin.closed:self.process.stdin.close()
        self.process.stdout.close()
        self.stderr.close();self.raw.close();self.late.close()
