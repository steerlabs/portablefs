"""An owned vsock SSH forward keeps qualification TLS off external interfaces."""
import subprocess


class AuthorityTunnel:
    endpoint = '127.0.0.1:17443'

    def __init__(self, guest, published_port, evidence):
        self.log = (evidence/'authority-tunnel.log').open('w')
        self.process = subprocess.Popen([
            'ssh', '-F', guest.ready['ssh_config'], '-T', '-N',
            '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=0',
            '-o', 'TCPKeepAlive=no', '-o', 'ControlMaster=no',
            '-o', 'ControlPath=none', '-o', 'ControlPersist=no',
            '-R', self.endpoint+':127.0.0.1:'+str(published_port),
            'portablefs-workspace'], stdin=subprocess.DEVNULL,
            stdout=self.log, stderr=subprocess.STDOUT)
        try:
            # Probe the actual forwarded endpoint before provisioning the mount.
            guest.ssh("python3 -c \"import socket,time;deadline=time.monotonic()+10\n"
                      "while True:\n try:\n  socket.create_connection(('127.0.0.1',17443),1).close();break\n"
                      " except OSError:\n  assert time.monotonic()<deadline;time.sleep(.1)\"")
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        if self.process.poll() is not None:
            raise RuntimeError('owned authority vsock tunnel exited; continuity lost')

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
